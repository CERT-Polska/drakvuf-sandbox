import subprocess


def tool_exists(tool):
    return subprocess.run(["which", tool]).returncode == 0
