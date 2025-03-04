from enum import Enum, auto
from typing import Optional


class CliHandlerAction(Enum):
    INIT_NEW_IFACE = auto()  # unused
    ADD = auto()
    LIST = auto()
    RENAME = auto()
    NEWKEY_CLIENT = auto()
    NEWPSK = auto()
    NEWKEY_SERVER = auto()  # unused
    DELETE = auto()
    DELETE_IFACE = auto()
    FLIP_SYSTEMD = auto()
    GO_UP = auto()

    @staticmethod
    def get_enum_from_str(value: str) -> "CliHandlerAction":
        for enum_value in list(CliHandlerAction):
            mapped_enum = CliHandlerAction.get_str_mapping(enum_value)
            if value.strip().lower() == mapped_enum:
                return enum_value

        return None

    @staticmethod
    def get_str_mapping(enum_value: "CliHandlerAction") -> Optional[str]:
        if enum_value == CliHandlerAction.INIT_NEW_IFACE:
            return "i"
        if enum_value == CliHandlerAction.ADD:
            return "a"
        if enum_value == CliHandlerAction.LIST:
            return "l"
        if enum_value == CliHandlerAction.RENAME:
            return "r"
        if enum_value == CliHandlerAction.NEWKEY_CLIENT:
            return "k"
        if enum_value == CliHandlerAction.NEWPSK:
            return "p"
        if enum_value == CliHandlerAction.NEWKEY_SERVER:
            return "ks"
        if enum_value == CliHandlerAction.DELETE:
            return "d"
        if enum_value == CliHandlerAction.DELETE_IFACE:
            return "ds"
        if enum_value == CliHandlerAction.FLIP_SYSTEMD:
            return "s"
        if enum_value == CliHandlerAction.GO_UP:
            return ".."

        return None

    @staticmethod
    def list():
        return list(map(lambda c: c.value, CliHandlerAction))
