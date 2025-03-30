import os
import pathlib
import shutil

ETC_DIR = "/etc/drakrun"
VM_CONFIG_DIR = os.path.join(ETC_DIR, "configs")
SCRIPTS_DIR = os.path.join(ETC_DIR, "scripts")
INSTALL_INFO_PATH = pathlib.Path(ETC_DIR) / "install.json"
NETWORK_CONF_PATH = pathlib.Path(ETC_DIR) / "network.json"

LIB_DIR = "/var/lib/drakrun"
CONFIGS_DIR = pathlib.Path(LIB_DIR) / "configs"
PROFILE_DIR = os.path.join(LIB_DIR, "profiles")
RUNTIME_FILE = os.path.join(PROFILE_DIR, "runtime.json")
APISCOUT_PROFILE_DIR = os.path.join(LIB_DIR, "apiscout_profile")
VOLUME_DIR = os.path.join(LIB_DIR, "volumes")
CONFIG_PATH = os.path.join(ETC_DIR, "config.ini")

PACKAGE_DIR = pathlib.Path(__file__).parent.parent.absolute()
PACKAGE_DATA_PATH = PACKAGE_DIR / "data"
PACKAGE_TOOLS_PATH = PACKAGE_DIR / "tools"

RUN_DIR = pathlib.Path("/var/run/drakrun")

SNAPSHOT_DIR = pathlib.Path(VOLUME_DIR)
XL_CFG_TEMPLATE_PATH = pathlib.Path(ETC_DIR) / "cfg.template"


def make_dirs():
    pathlib.Path(ETC_DIR).mkdir(exist_ok=True)
    pathlib.Path(LIB_DIR).mkdir(exist_ok=True)
    SNAPSHOT_DIR.mkdir(exist_ok=True)
    CONFIGS_DIR.mkdir(exist_ok=True)


def initialize_config_files():
    if not XL_CFG_TEMPLATE_PATH.exists():
        source_file = PACKAGE_DATA_PATH / "cfg.template"
        shutil.copy(source_file, XL_CFG_TEMPLATE_PATH)
