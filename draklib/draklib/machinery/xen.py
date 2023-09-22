import subprocess


def get_domid_from_name(vm_name: str) -> int:
    output = subprocess.check_output(["xl", "domid", vm_name], text=True)
    return int(output.strip())


def get_xl_info():
    xl_info_out = subprocess.check_output(["xl", "info"], text=True)
    xl_info_lines = xl_info_out.strip().split("\n")

    cfg = {}

    for line in xl_info_lines:
        k, v = line.split(":", 1)
        k, v = k.strip(), v.strip()
        cfg[k] = v

    return cfg
