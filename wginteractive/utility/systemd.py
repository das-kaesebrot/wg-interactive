import os
import subprocess
from typing import Optional

from ..utility.subprocesshandler import SubprocessHandler


class Systemd:

    MULTI_USER_TARGET_WANTS_FOLDER = "/etc/systemd/system/multi-user.target.wants"

    CMD_ENABLE = "enable"
    CMD_DISABLE = "disable"

    CMD_START = "start"
    CMD_STOP = "stop"

    CMD_IS_ENABLED = "is-enabled"

    WG_QUICK_SERVICE = "wg-quick"

    def __init__(self) -> None:
        pass

    @staticmethod
    def wg_interface_is_enabled(interface) -> Optional[bool]:
        return Systemd.unit_is_enabled(f"{Systemd.WG_QUICK_SERVICE}@{interface}")

    @staticmethod
    def flip_wg_interface_enabled_status(interface):
        Systemd.flip_enabled_status(f"{Systemd.WG_QUICK_SERVICE}@{interface}", now=True)

    @staticmethod
    def disable_wg_interface(interface: str, now: bool):
        unit = f"{Systemd.WG_QUICK_SERVICE}@{interface}"
        unit = Systemd.append_unit_file_extension_if_missing(unit)
        if os.path.isfile(os.path.join(Systemd.MULTI_USER_TARGET_WANTS_FOLDER, unit)):
            Systemd.invoke_systemd_command_on_unit(Systemd.CMD_DISABLE, unit)
            if now:
                Systemd.stop_unit(unit)

    @staticmethod
    def start_unit(unit: str):
        unit = Systemd.append_unit_file_extension_if_missing(unit)
        Systemd.invoke_systemd_command_on_unit(Systemd.CMD_START, unit)

    @staticmethod
    def stop_unit(unit: str):
        unit = Systemd.append_unit_file_extension_if_missing(unit)
        Systemd.invoke_systemd_command_on_unit(Systemd.CMD_STOP, unit)

    @staticmethod
    def flip_enabled_status(unit: str, now: bool = False) -> None:
        unit = Systemd.append_unit_file_extension_if_missing(unit)

        if os.path.isfile(os.path.join(Systemd.MULTI_USER_TARGET_WANTS_FOLDER, unit)):
            Systemd.invoke_systemd_command_on_unit(
                f"{Systemd.CMD_DISABLE}{' --now' if now else ''}", unit
            )
        else:
            Systemd.invoke_systemd_command_on_unit(
                f"{Systemd.CMD_ENABLE}{' --now' if now else ''}", unit
            )

    @staticmethod
    def unit_is_enabled(unit) -> bool:
        if not Systemd.host_is_using_systemd():
            return None

        unit = Systemd.append_unit_file_extension_if_missing(unit)

        return (
            Systemd.invoke_systemd_command_on_unit(
                Systemd.CMD_IS_ENABLED, unit=unit, capture_output=True
            ).returncode
            == 0
        )

    @staticmethod
    def host_is_using_systemd() -> bool:
        return os.path.exists("/run/systemd/system")

    @staticmethod
    def invoke_systemd_command_on_unit(
        command: str, unit: str, silent: bool = False, capture_output: bool = False
    ) -> subprocess.CompletedProcess:
        return SubprocessHandler.invoke_command(
            f"systemctl {command} {unit}", silent=silent, capture_output=capture_output
        )

    @staticmethod
    def append_unit_file_extension_if_missing(unit: str) -> str:
        if not unit.endswith(".service"):
            return f"{unit}.service"

        return unit
