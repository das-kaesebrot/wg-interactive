import os
import subprocess

from ..utility.subprocesshandler import SubprocessHandler


class Systemd:

    MULTI_USER_TARGET_WANTS_FOLDER = "/etc/systemd/system/multi-user.target.wants"

    CMD_ENABLE = "enable"
    CMD_DISABLE = "disable"

    CMD_START = "start"
    CMD_STOP = "stop"

    WG_QUICK_SERVICE = "wg-quick"

    def __init__(self) -> None:
        pass

    @staticmethod
    def wg_interface_is_enabled(interface) -> bool | None:
        return Systemd.unit_is_enabled(f"{Systemd.WG_QUICK_SERVICE}@{interface}.service")

    @staticmethod
    def flip_wg_interface_enabled_status(interface):
        Systemd.flip_enabled_status(f"{Systemd.WG_QUICK_SERVICE}@{interface}", now=True)
        
    @staticmethod
    def disable_wg_interface(interface: str, now: bool):
        unit = f"{Systemd.WG_QUICK_SERVICE}@{interface}"
        if os.path.isfile(os.path.join(Systemd.MULTI_USER_TARGET_WANTS_FOLDER, unit)):
            Systemd.invoke_systemd_command_on_unit(Systemd.CMD_DISABLE, unit)
            if now:
                Systemd.stop_unit(unit)

    @staticmethod
    def start_unit(unit: str):
        if not unit.endswith(".service"):
            unit = f"{unit}.service"

        Systemd.invoke_systemd_command_on_unit(Systemd.CMD_START, unit)

    @staticmethod
    def stop_unit(unit: str):
        if not unit.endswith(".service"):
            unit = f"{unit}.service"

        Systemd.invoke_systemd_command_on_unit(Systemd.CMD_STOP, unit)

    @staticmethod
    def flip_enabled_status(unit: str, now: bool = False) -> None:
        if not unit.endswith(".service"):
            unit = f"{unit}.service"

        if os.path.isfile(os.path.join(Systemd.MULTI_USER_TARGET_WANTS_FOLDER, unit)):
            Systemd.invoke_systemd_command_on_unit(f"{Systemd.CMD_DISABLE}{' --now' if now else ''}", unit)
        else:
            Systemd.invoke_systemd_command_on_unit(f"{Systemd.CMD_ENABLE}{' --now' if now else ''}", unit)

    @staticmethod
    def unit_is_enabled(unit) -> bool:
        if not Systemd.host_is_using_systemd():
            return None
        return os.path.isfile(
            os.path.join(Systemd.MULTI_USER_TARGET_WANTS_FOLDER, unit)
        )

    @staticmethod
    def host_is_using_systemd() -> bool:
        return os.path.exists("/run/systemd/system")

    @staticmethod
    def invoke_systemd_command_on_unit(
        command: str, unit: str
    ) -> subprocess.CompletedProcess:
        return SubprocessHandler.invoke_command(f"systemctl {command} {unit}")
