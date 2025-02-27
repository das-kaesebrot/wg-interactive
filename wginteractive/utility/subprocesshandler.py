import subprocess


class SubprocessHandler:

    def __init__(self) -> None:
        pass

    @staticmethod
    def invoke_command(
        command: str, silent: bool = False, capture_output: bool = False
    ) -> subprocess.CompletedProcess[str]:
        if silent:
            result = subprocess.run(
                command.split(),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT,
                capture_output=capture_output,
            )
        else:
            result = subprocess.run(command.split(), capture_output=capture_output)

        return result
