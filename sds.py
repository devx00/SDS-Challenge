from enum import Enum
from sds_types import ECU, Service, SecurityAccessFunction, DataTransferFunction, ECU_Mode, FailureReason, ResponseType, DID
from pwn import log

"""
|             0             |        1        |  2  |  3  |  4  |  5  |  6  |  7  |
|---------------------------|-----------------|-----|-----|-----|-----|-----|-----|
| Size              0x1-0x6 | <---------------- Command Packet -----------------> | <-- Command Packet or Small (<=6bytes) Data Packet
| Flow Control Resp.   0x10 |  Response Size  | <------------- Data ------------> | <-- Data Packet 6 bytes (1 byte for response length)
| Frame ID        0x21-0x2f | <--------------------- Data ----------------------> | <-- Data Packet 7 bytes
| Flow Control Request 0x30 |       0x0       | 0x0 | 0x0 | 0x0 | 0x0 | 0x0 | 0x0 | <-- Flow Control Request 1 byte total 0 data bytes.
"""


class MsgDirection(Enum):
    Request = 0
    Response = 1

    def __str__(self):
        if self is MsgDirection.Request:
            return "⟶"
        return "⟵"


class Failure:
    def __init__(self, service, code):
        self.service = Service(service)
        self.reason = FailureReason(code)

    def __str__(self):
        return f"{self.service} - {self.reason}"


class PacketType(Enum):
    Command = 1
    ControlFlow = 2


class MsgPacket:
    def __init__(self):
        pass

    @staticmethod
    def parse(data:bytearray):
        len_or_type = data[0]
        if len_or_type <= 0xf:
            return CommandPacket.parse(data)
        return ControlFlowPacket.parse(data)


class ControlFlowPacket(MsgPacket):
    @staticmethod
    def class_for_ptype(ptype):
        if ptype == 0x10:
            return ControlFlowRequestPacket
        elif ptype & 0xF0 == 0x20:
            return ControlFlowFramePacket
        elif ptype == 0x30:
            return ControlFlowResponsePacket

    @staticmethod
    def parse(data:bytes):
        packet_class = ControlFlowPacket.class_for_ptype(data[0])
        return packet_class(data)

    def __str__(self):
        return f"{self.ptype} - {self.data.hex()}"


class ControlFlowRequestPacket(ControlFlowPacket):
    @property
    def ptype(self):
        return "Flow Control Request"

    def __init__(self, data:bytes):
        _ = data.pop(0)
        self.data_length = data.pop(0)
        self.data = data

    def __str__(self):
        return f"{self.ptype} - [{self.data_length}]:\n|\t{self.data.hex()}"


class ControlFlowFramePacket(ControlFlowPacket):
    @property
    def ptype(self):
        return "Flow Control Frame"

    def __init__(self, data:bytes):
        _ = data.pop(0)
        self.data_length = 7
        self.data = data

    def __str__(self):
        return f"{self.ptype} - [7]:\n|\t{self.data.hex()}"


class ControlFlowResponsePacket(ControlFlowPacket):
    @property
    def ptype(self):
        return "Flow Control Continue"

    def __init__(self, data:bytes):
        _ = data.pop(0)
        self.data = b""

    def __str__(self):
        return f"{self.ptype}"


class CommandPacket(MsgPacket):
    def __init__(self, data:bytes):
        self.packet_length = data.pop(0)
        data_length = self.packet_length
        while len(data) > data_length:
            data.pop()

    @staticmethod
    def parse(data:bytes):
        ptype = data[1]
        if ptype == 0x7F:
            return CommandFailurePacket(data)
        if ptype < 0x30:
            return CommandRequestPacket(data)
        return CommandResponsePacket(data)


class CommandResponsePacket(CommandPacket):
    def __init__(self, data:bytes):
        super().__init__(data)
        self.response_code = ResponseType(data.pop(0))
        self.response_data = data

    @property
    def data(self):
        return self.response_data

    def __str__(self):
        return f"{self.response_code} Response - {self.data.hex()}"


class CommandRequestPacket(CommandPacket):
    def __init__(self, data:bytes):
        super().__init__(data)
        self.service = Service(data.pop(0))
        self.request_data = data

    def __str__(self):
        return f"{self.service} Request - {self.request_description()}"

    def request_description(self) -> str:
        # TODO: Implement Request Specific Descriptions
        return self.request_data.hex()


class CommandFailurePacket(CommandPacket):
    def __init__(self, data:bytes):
        super().__init__(data)
        _ = data.pop(0)
        self.failure = Failure(data.pop(0), data.pop(0))

    def __str__(self):
        return f"[-] {self.failure}"


class Msg:
    @staticmethod
    def parse_size(data_size):
        if type(data_size) is bytes:
            data_size = data_size.decode()
        if type(data_size) is str:
            data_size = data_size.strip("[]")
        return int(data_size)

    @staticmethod
    def parse_ecu_id(ecu_id_unparsed):
        if type(ecu_id_unparsed) is bytes:
            ecu_id_unparsed = ecu_id_unparsed.decode()
        if type(ecu_id_unparsed) is str:
            ecu_id_unparsed = int(ecu_id_unparsed, 16)
        if type(ecu_id_unparsed) is int:
            ecu = ECU(ecu_id_unparsed & 0xFF0)
            last_nibble = ecu_id_unparsed & 0xF
        else:
            ecu = ecu_id_unparsed
            last_nibble = 0

        if last_nibble == 0:
            msg_dir = MsgDirection.Request
        else:
            msg_dir = MsgDirection.Response

        return ecu, msg_dir

    @staticmethod
    def from_candump(candump_line):
        log.debug(f"Processing: {candump_line}")
        parts = candump_line.split(" ")
        if len(parts) < 4:
            return None
        can_interface, ecu_id, data_size, *msg_bytes = parts
        msg_bytes = bytearray([int(b, 16) for b in msg_bytes])
        return Msg(can_interface, ecu_id, data_size, *msg_bytes)

    def __init__(self, can_interface, ecu_id, data_size, *msg_bytes):
        if type(can_interface) is bytes:
            can_interface = can_interface.decode()
        self.can_interface = can_interface
        self.ecu, self.direction = self.parse_ecu_id(ecu_id)
        self.data_size = self.parse_size(data_size)
        self.packet = MsgPacket.parse(bytearray(msg_bytes))

    def __str__(self):
        parts = [self.direction,
                 self.can_interface,
                 self.ecu,
                 self.packet]
        return "\t".join(map(str, parts))

    def __bytes__(self):
        return self.packet.data

    def hex_data(self):
        return bytes(self).hex()


class Request:
    @staticmethod
    def set_mode(mode, ecu=ECU.ECM, interface="can0"):
        return Request(ecu,
                       Service.Initiate_Diagnostic_Session,
                       data=[mode.value],
                       interface=interface)

    @staticmethod
    def return_to_normal(ecu=ECU.ECM, interface="can0"):
        return Request(ecu,
                       Service.Return_To_Normal,
                       interface=interface)

    @staticmethod
    def security_access_seed(ecu=ECU.ECM, interface="can0"):
        return Request(ecu,
                       Service.Security_Access,
                       data=[SecurityAccessFunction.Seed.value],
                       interface=interface)

    @staticmethod
    def security_access_send_key(key, ecu=ECU.ECM, interface="can0"):
        return Request(ecu,
                       Service.Security_Access,
                       packet_len=0x6,
                       data=[SecurityAccessFunction.Key.value, *key],
                       interface=interface)

    @staticmethod
    def read_address(address,
                     length,
                     ecu=ECU.ECM,
                     interface="can0"):
        return Request(ecu,
                       Service.Read_Memory_By_Address,
                       packet_len=0x8,  # Must be above 7 to bypass flaw
                       data=[*address.to_bytes(4, "big"),
                             *length.to_bytes(2, "big")],
                       interface=interface)

    @staticmethod
    def read_did(did, ecu=ECU.ECM, interface="can0"):
        return Request(ecu,
                       Service.Read_DID_By_ID,
                       data=[did],
                       interface=interface)

    @staticmethod
    def programming_mode(ecu=ECU.ECM, interface="can0"):
        return Request(ecu,
                       Service.Programming_Mode,
                       interface=interface)

    @staticmethod
    def request_download(size, ecu=ECU.ECM, interface="can0"):
        return Request(ecu,
                       Service.Request_Download,
                       data=size.to_bytes(2, "big"),
                       interface=interface)

    @staticmethod
    def transfer_data(address=0,
                      data=bytearray(),
                      packet_len=0x8,
                      function=DataTransferFunction.Download,
                      ecu=ECU.ECM,
                      interface="can0"):

        return Request(ecu,
                       Service.Transfer_Data,
                       packet_len=packet_len,
                       data=[
                           function.value, * address.to_bytes(4, "big"),
                           *data
                       ],
                       interface=interface)

    @staticmethod
    def execute_data(ecu=ECU.ECM,
                     interface="can0"):

        return Request(ecu,
                       Service.Transfer_Data,
                       packet_len=3,
                       data=[
                           DataTransferFunction.DownloadAndExecute.value
                       ],
                       interface=interface)

    @staticmethod
    def flow_control_continue(ecu=ECU.ECM, interface="can0"):
        return Request(ecu,
                       None,
                       packet_len=0x30,
                       interface=interface)

    @staticmethod
    def flow_control_request(length, data, ecu=ECU.ECM, interface="can0"):
        return Request(ecu,
                       None,
                       data=[length, *data],
                       packet_len=0x10,
                       interface=interface)

    @staticmethod
    def enter_diagnostic_session(ecu=ECU.ECM, interface="can0"):
        return Request.set_mode(ECU_Mode.Diagnostic, ecu, interface)

    @staticmethod
    def enter_device_control_session(ecu=ECU.ECM, interface="can0"):
        return Request.set_mode(ECU_Mode.Device_Control, ecu, interface)

    def __init__(self, ecu, service, packet_len=None, data=b"", interface="can0"):
        if type(ecu) is str:
            ecu = int(ecu, 16)
        if type(ecu) is int:
            ecu = ECU(ecu)
        self.ecu = ecu
        self.interface = interface
        if service is not None:
            service_val = service.value
        else:
            service_val = None
        if packet_len is None:
            packet_len = len([service_val, *data])

        if service_val is None:
            self.data = bytes([packet_len, *data])
        else:
            self.data = bytes([packet_len, service_val, *data])

    def __str__(self):
        return f"{self.ecu.value:x}#{self.data.hex()}"

    def __bytes__(self):
        return str(self).encode()

    def serialize(self):
        return self.__bytes__()
