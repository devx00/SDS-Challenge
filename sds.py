from enum import Enum


class ECU(Enum):
    BCM = 0x7C0
    ECM = 0x7E0

    def __str__(self):
        return self.name


class SecurityAccessFunction(Enum):
    Seed = 0x01
    Key = 0x02


class DID(Enum):
    Author = 0
    Manufacturer = 1
    Year = 2
    Vin = 3

    def __str__(self):
        return self.name


class DataTransferFunction(Enum):
    Download = 0x0
    DownloadAndExecute = 0x1


class Service(Enum):
    Initiate_Diagnostic_Session = 0x20
    Return_To_Normal = 0x21
    Security_Access = 0x22
    Read_Memory_By_Address = 0x23
    Read_DID_By_ID = 0x24
    Programming_Mode = 0x25
    Request_Download = 0x26
    Transfer_Data = 0x27

    def __str__(self):
        return self.name.replace("_", " ")


class ResponseType(Enum):
    IniitiateDiagnosticSession_Success = 0x60
    ReturnToNormal_Success = 0x61
    SecurityAccess_Success = 0x62
    ReadMemoryByAddress_Success = 0x63
    ReadDIDByID_Success = 0x64
    ProgrammingMode_Success = 0x65
    RequestDownload_Success = 0x66
    TransferData_Success = 0x67
    Failure = 0x7F
    FlowControl = 0x30

    def __str__(self):
        return self.name.replace("_", " ")


class MsgDirection(Enum):
    Request = 0
    Response = 1

    def __str__(self):
        if self is MsgDirection.Request:
            return "⟶"
        return "⟵"


class FailureReason(Enum):
    ServiceNotSupported = 0x11
    SubFunctionNotSupported = 0x12
    ConditionsNotCorrect = 0x13
    RequestOutOfRange = 0x14
    InvalidKey = 0x15
    ExceedNumberOfAttempts = 0x16

    def __str__(self):
        return self.name.replace("_", " ")


class Failure:
    def __init__(self, service, code):
        self.service = Service(service)
        self.reason = FailureReason(code)

    def __str__(self):
        return f"{self.service} - {self.reason}"


class ECU_Mode(Enum):
    Default = 0x01
    Diagnostic = 0x02
    Device_Control = 0x03
    Flow_Control = 0x10
    Flow_Control_Continue = 0x30

    def __str__(self):
        return self.name.replace("_", " ")


class MsgType(Enum):
    ModeDefault = 1
    ModeDiagnostic = 2
    ModeDeviceControl = 3
    FlowControlIndicatorResponse = 0x10
    FlowControlFrame = 0x20
    FlowControlIndicatorRequest = 0x30

    def __str__(self):
        return self.name

    @staticmethod
    def from_int(val):
        if val & 0xf0 == 0x20 or 0x4 <= val <= 0xf:
            return MsgType.FlowControlFrame
        return MsgType(val)


class MsgFrame:
    @property
    def msg_type(self):
        return MsgType.from_int(self.data_bytes[0])

    def __init__(self, data_bytes, data_size=None):
        if type(data_bytes) is tuple:
            if type(data_bytes[0]) is bytes:
                data_bytes = b"".join(data_bytes)
            else:
                data_bytes = bytes(data_bytes)
        self.data_bytes = data_bytes
        self.data_size = data_size if data_size else len(data_bytes)

    def __str__(self):
        return self.data_bytes.hex()

    def __bytes__(self):
        return self.data_bytes

    @staticmethod
    def for_direction(direction, *args, **kwargs):
        if direction is MsgDirection.Request:
            return RequestFrame(*args, **kwargs)
        return ResponseFrame(*args, **kwargs)


class RequestFrame(MsgFrame):
    @property
    def service(self):
        if self.msg_type is MsgType.FlowControlIndicatorRequest:
            return None
        return Service(self.data_bytes[1])

    def __init__(self, *data_bytes):
        super().__init__(*data_bytes)

    def __str__(self):
        return f"{self.msg_type}\n⏐\t{self.service} {self.data_bytes[2:].hex()}"


class ResponseFrame(MsgFrame):
    @property
    def response_type(self):
        if self.msg_type in [
            MsgType.FlowControlFrame,
            MsgType.FlowControlIndicatorResponse,
            MsgType.FlowControlIndicatorRequest
        ]:
            return ResponseType.FlowControl
        return ResponseType(self.data_bytes[1])

    @property
    def failure(self):
        if self.response_type is ResponseType.Failure:
            return Failure(self.data_bytes[2], self.data_bytes[3])

    def __init__(self, *data_bytes):
        super().__init__(*data_bytes)

    def __str__(self):
        failure_msg = f" {self.failure} " if self.failure else ""
        return f"{self.msg_type}\n⏐\t{self.response_type}{failure_msg}"


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
        parts = candump_line.split(" ")
        if len(parts) < 4:
            return None
        can_interface, ecu_id, data_size, *msg_bytes = parts
        msg_bytes = bytes([int(b, 16) for b in msg_bytes])
        return Msg(can_interface, ecu_id, data_size, *msg_bytes)

    def __init__(self, can_interface, ecu_id, data_size, *msg_bytes):
        if type(can_interface) is bytes:
            can_interface = can_interface.decode()
        self.can_interface = can_interface
        self.ecu, self.direction = self.parse_ecu_id(ecu_id)
        self.data_size = self.parse_size(data_size)
        self.frames = [MsgFrame.for_direction(
            self.direction, msg_bytes, self.data_size)]

    def __str__(self):
        parts = [self.direction,
                 self.can_interface,
                 self.ecu,
                 self.frames[0]]
        return "\t".join(map(str, parts))

    def __bytes__(self):
        print(self.frames[0].data_bytes)
        return self.frames[0].data_bytes

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
                       data=[SecurityAccessFunction.Key.value, *key],
                       interface=interface)

    @staticmethod
    def read_address(address,
                     length,
                     ecu=ECU.ECM,
                     interface="can0"):
        return Request(ecu,
                       Service.Read_Memory_By_Address,
                       mode=ECU_Mode.Flow_Control.value,
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
                       data=size.to_bytes(2, "little"),
                       interface=interface)

    @staticmethod
    def transfer_data(address=0,
                      byte=0,
                      function=DataTransferFunction.Download,
                      ecu=ECU.ECM,
                      interface="can0"):

        return Request(ecu,
                       Service.Transfer_Data,
                       data=[function.value, *
                             address.to_bytes(4, "little"), byte],
                       interface=interface)

    @staticmethod
    def flow_control_continue(ecu=ECU.ECM, interface="can0"):
        return Request(ecu,
                       None,
                       mode=ECU_Mode.Flow_Control_Continue.value,
                       interface=interface)

    @staticmethod
    def enter_diagnostic_session(ecu=ECU.ECM, interface="can0"):
        return Request.set_mode(ECU_Mode.Diagnostic, ecu, interface)

    def __init__(self, ecu, service, mode=0x2, data=b"", interface="can0"):
        if type(ecu) is str:
            ecu = int(ecu, 16)
        if type(ecu) is int:
            ecu = ECU(ecu)
        self.ecu = ecu
        self.interface = interface
        if service is not None:
            service_val = service.value
        else:
            service_val = 0
        self.data = bytes([mode, service_val, *data])

    def __str__(self):
        return f"{self.ecu.value:x}#{self.data.hex()}"

    def __bytes__(self):
        return str(self).encode()

    def serialize(self):
        return self.__bytes__()
