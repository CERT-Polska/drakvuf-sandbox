import configparser

from drakrun.paths import DRAKRUN_CONFIG_PATH

config = configparser.ConfigParser()
config.read(DRAKRUN_CONFIG_PATH)
