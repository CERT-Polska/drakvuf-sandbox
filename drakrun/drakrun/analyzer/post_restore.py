import base64
import datetime

from drakrun.lib.paths import ETC_DIR, PACKAGE_DATA_PATH


def prepare_ps_command(script: str):
    encoded_cmd = base64.b64encode(script.encode("utf-16le")).decode()
    return ["powershell.exe", "-EncodedCommand", encoded_cmd]


def get_post_restore_command(net_enable: bool):
    post_restore_script_path = ETC_DIR / "vm-post-restore.ps1"
    if not post_restore_script_path.exists():
        post_restore_script_path = PACKAGE_DATA_PATH / "vm-post-restore.ps1"
    post_restore_script = post_restore_script_path.read_text()
    current_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    script_substs = {
        "$DRAKVUF_NET_ENABLE": "$true" if net_enable else "$false",
        "$DRAKVUF_DATE": f'"{current_date}"',
    }
    for subst_key, subst_value in script_substs.items():
        post_restore_script = post_restore_script.replace(subst_key, subst_value)
    return prepare_ps_command(post_restore_script)
