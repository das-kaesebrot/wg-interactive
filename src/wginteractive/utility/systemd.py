import os
import subprocess

class Systemd:
    
    MULTI_USER_TARGET_WANTS_FOLDER = "/etc/systemd/system/multi-user.target.wants"
    
    def __init__(self) -> None:
        pass

    @staticmethod
    def flip_enabled_status(ifaceName):
        service_name = f"wg-quick@{ifaceName}.service"
        if os.path.isfile(os.path.join(Systemd.MULTI_USER_TARGET_WANTS_FOLDER, service_name)):
            subprocess.run(f"systemctl disable {service_name}".split())
        else:
            subprocess.run(f"systemctl enable {service_name}".split())
    