from enum import Enum


class SDSEnum(Enum):
    def __str__(self):
        return self.name.replace("_", " ")


class ECU(SDSEnum):
    BCM = 0x7C0
    ECM = 0x7E0


class ECU_Mode(SDSEnum):
    Default = 0x01
    Diagnostic = 0x02
    Device_Control = 0x03


class SecurityAccessFunction(SDSEnum):
    Seed = 0x01
    Key = 0x02


class DID(SDSEnum):
    Author = 0
    Manufacturer = 1
    Year = 2
    Vin = 3


class DataTransferFunction(SDSEnum):
    Download = 0x0
    DownloadAndExecute = 0x80


class FailureReason(SDSEnum):
    ServiceNotSupported = 0x11
    SubFunctionNotSupported = 0x12
    ConditionsNotCorrect = 0x13
    RequestOutOfRange = 0x14
    InvalidKey = 0x15
    ExceedNumberOfAttempts = 0x16


class Service(SDSEnum):
    Initiate_Diagnostic_Session = 0x20
    Return_To_Normal = 0x21
    Security_Access = 0x22
    Read_Memory_By_Address = 0x23
    Read_DID_By_ID = 0x24
    Programming_Mode = 0x25
    Request_Download = 0x26
    Transfer_Data = 0x27


class ResponseType(SDSEnum):
    IniitiateDiagnosticSession_Success = 0x60
    ReturnToNormal_Success = 0x61
    SecurityAccess_Success = 0x62
    ReadMemoryByAddress_Success = 0x63
    ReadDIDByID_Success = 0x64
    ProgrammingMode_Success = 0x65
    RequestDownload_Success = 0x66
    TransferData_Success = 0x67
    Failure = 0x7F


def get_value_from(value, enums):
    for e in enums:
        if e.value == value:
            return e
    return None
