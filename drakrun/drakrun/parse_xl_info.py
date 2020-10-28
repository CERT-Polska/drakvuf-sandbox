import subprocess


def get_xl_info():
    xl_info_out = subprocess.check_output('xl info', shell=True).decode('utf-8', 'replace')
    xl_info_lines = xl_info_out.strip().split('\n')

    cfg = {}

    for line in xl_info_lines:
        k, v = line.split(':', 1)
        k, v = k.strip(), v.strip()
        cfg[k] = v

    return cfg


def get_xen_commandline(parsed_xl_info):
    opts = parsed_xl_info['xen_commandline'].split(' ')

    cfg = {}

    for opt in opts:
        if '=' not in opt:
            cfg[opt] = '1'
        else:
            k, v = opt.split('=', 1)
            cfg[k] = v

    return cfg
