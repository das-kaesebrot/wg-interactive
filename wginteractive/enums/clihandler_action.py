from enum import StrEnum

class CliHandlerAction(StrEnum):
    INIT_NEW_IFACE = 'i' # unused
    ADD = 'a'
    LIST = 'l'
    RENAME = 'r'
    NEWKEY_CLIENT = 'k'
    NEWPSK = 'p'
    NEWKEY_SERVER = 'ks' # unused
    DELETE = 'd'
    DELETE_IFACE = 'ds'
    FLIP_SYSTEMD = 's'
    GO_UP = '..'