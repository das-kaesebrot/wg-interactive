from enum import StrEnum

class CliHandlerAction(StrEnum):
    INIT_NEW_IFACE = 'i' # unused
    ADD = 'a'
    LIST = 'l'
    RENAME = 'r'
    NEWKEY_CLIENT = 'k'
    NEWKEY_SERVER = 'ks' # unused
    DELETE = 'd'
    FLIP_SYSTEMD = 's'