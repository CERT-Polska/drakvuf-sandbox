import json
import subprocess


def start_service(service_name: str):
    return subprocess.Popen(
        ["systemctl", "start", service_name],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def stop_service(service_name: str):
    return subprocess.Popen(
        ["systemctl", "stop", service_name],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def enable_service(service_name: str):
    return subprocess.Popen(
        ["systemctl", "enable", service_name],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def disable_service(service_name: str):
    return subprocess.Popen(
        ["systemctl", "disable", service_name],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def systemctl_daemon_reload():
    return subprocess.run(["systemctl", "daemon-reload"], check=True, shell=True)


def list_enabled_services(service_name_pattern: str, state: str = ""):
    # Requires systemd version that supports --output=json (Debian Bullseye)
    units_data = subprocess.check_output(
        [
            "systemctl",
            "list-units",
            "--type=service" "--full",
            "--all",
            "--no-pager",
            "--output=json",
            *([f"--state={state}"] if state else []),
            service_name_pattern,
        ],
        shell=True,
        text=True,
    )
    units = json.loads(units_data)
    return [item["unit"] for item in units]
