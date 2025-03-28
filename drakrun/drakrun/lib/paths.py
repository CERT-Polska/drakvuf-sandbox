import os
import pathlib

ETC_DIR = "/etc/drakrun"
VM_CONFIG_DIR = os.path.join(ETC_DIR, "configs")
SCRIPTS_DIR = os.path.join(ETC_DIR, "scripts")

LIB_DIR = "/var/lib/drakrun"
PROFILE_DIR = os.path.join(LIB_DIR, "profiles")
RUNTIME_FILE = os.path.join(PROFILE_DIR, "runtime.json")
APISCOUT_PROFILE_DIR = os.path.join(LIB_DIR, "apiscout_profile")
VOLUME_DIR = os.path.join(LIB_DIR, "volumes")
CONFIG_PATH = os.path.join(ETC_DIR, "config.ini")

PACKAGE_DIR = pathlib.Path(__file__).parent.parent.absolute()

SNAPSHOT_DIR = pathlib.Path(VOLUME_DIR)
XL_CFG_TEMPLATE_PATH = pathlib.Path(SCRIPTS_DIR) / "cfg.template"
