import subprocess

from .subprocess import check_output, run


def get_domid_from_name(vm_name: str) -> int:
    output = check_output(["xl", "domid", vm_name], text=True)
    return int(output.strip())


def get_xl_info():
    xl_info_out = check_output(["xl", "info"], text=True)
    xl_info_lines = xl_info_out.strip().split("\n")

    cfg = {}

    for line in xl_info_lines:
        k, v = line.split(":", 1)
        k, v = k.strip(), v.strip()
        cfg[k] = v

    return cfg


def eject_cd(domain, drive):
    run(["xl", "cd-eject", domain, drive], check=True)


def insert_cd(domain, drive, iso):
    run(["xl", "cd-insert", domain, drive, iso], check=True)