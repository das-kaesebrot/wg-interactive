import subprocess

class SubprocessHandler:
    
    def __init__(self) -> None:
        pass
    
    @staticmethod
    def invoke_command(command: str, silent: bool = False) -> tuple[int, subprocess.CompletedProcess[str]]:
        if silent:
            result = subprocess.run(command.split(), stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        else:
            result = subprocess.run(command.split())
            
        return result.returncode, result