import os

# Root directories
ETC_DIR = os.getenv("DRAKRUN_ETC_DIR") or "/etc/drakrun"
LIB_DIR = os.getenv("DRAKRUN_LIB_DIR") or "/var/lib/drakrun"
PACKAGE_DIR = os.path.dirname(__file__)

# Configuration directories
VM_CONFIG_DIR = os.path.join(ETC_DIR, "configs")
DRAKRUN_CONFIG_PATH = os.path.join(ETC_DIR, "config.ini")

# Storage directories
PROFILE_DIR = os.path.join(LIB_DIR, "profiles")
APISCOUT_PROFILE_DIR = os.path.join(LIB_DIR, "apiscout_profile")
VOLUME_DIR = os.path.join(LIB_DIR, "volumes")
