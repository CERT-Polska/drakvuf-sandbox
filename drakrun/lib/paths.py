import pathlib
import shutil

ETC_DIR = pathlib.Path("/etc/drakrun")
INSTALL_INFO_PATH = ETC_DIR / "install.json"
XL_CFG_TEMPLATE_PATH = ETC_DIR / "cfg.template"
CONFIG_PATH = ETC_DIR / "config.toml"

LIB_DIR = pathlib.Path("/var/lib/drakrun")
SNAPSHOT_DIR = LIB_DIR / "volumes"
CONFIGS_DIR = LIB_DIR / "configs"
VMI_PROFILES_DIR = LIB_DIR / "profiles"
PDB_CACHE_DIR = LIB_DIR / "pdb_cache"
ANALYSES_DIR = LIB_DIR / "analyses"

VMI_INFO_PATH = VMI_PROFILES_DIR / "runtime.json"
VMI_KERNEL_PROFILE_PATH = VMI_PROFILES_DIR / "kernel.json"

PACKAGE_DIR = pathlib.Path(__file__).parent.parent.absolute()
PACKAGE_DATA_PATH = PACKAGE_DIR / "data"
PACKAGE_TOOLS_PATH = PACKAGE_DIR / "tools"

RUN_DIR = pathlib.Path("/var/run/drakrun")

DUMPS_DIR = "dumps"
DUMPS_ZIP = "dumps.zip"
IPT_DIR = "ipt"
IPT_ZIP = "ipt.zip"


def make_dirs():
    pathlib.Path(ETC_DIR).mkdir(exist_ok=True)
    pathlib.Path(LIB_DIR).mkdir(exist_ok=True)
    SNAPSHOT_DIR.mkdir(exist_ok=True)
    CONFIGS_DIR.mkdir(exist_ok=True)
    ANALYSES_DIR.mkdir(exist_ok=True)
    VMI_PROFILES_DIR.mkdir(exist_ok=True)
    PDB_CACHE_DIR.mkdir(exist_ok=True)


def initialize_config_files():
    if not XL_CFG_TEMPLATE_PATH.exists():
        source_file = PACKAGE_DATA_PATH / "cfg.template"
        shutil.copy(source_file, XL_CFG_TEMPLATE_PATH)
    if not CONFIG_PATH.exists():
        source_file = PACKAGE_DATA_PATH / "config.toml"
        shutil.copy(source_file, CONFIG_PATH)
