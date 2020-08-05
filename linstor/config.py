import os

from linstor.linstorapi import MultiLinstor

try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import SafeConfigParser as ConfigParser


class Config(object):
    @staticmethod
    def read_config(config_file):
        cp = ConfigParser()
        cp.read(config_file)
        config = {}
        for section in cp.sections():
            config[section] = cp.items(section)
        return config

    @staticmethod
    def get_section(section, config_file_name=None):
        home_dir = os.path.expanduser("~")
        config_file = "linstor-client.conf"
        user_conf = os.path.join(home_dir, ".config", "linstor", config_file)
        sys_conf = os.path.join('/etc', 'linstor', config_file)

        config = None
        if config_file_name and os.path.exists(config_file_name):
            config = Config.read_config(config_file_name)
        elif os.path.exists(user_conf):
            config = Config.read_config(user_conf)
        elif os.path.exists(sys_conf):
            config = Config.read_config(sys_conf)

        entries = config.get(section, []) if config else []
        return {k: v for k, v in entries}

    @staticmethod
    def get_controllers(section='global', config_file_name=None, fallback='linstor://localhost'):
        """
        :param str section: Section to parse, defaults to 'global'
        :param str config_file_name: Config file to parse, if not set, the default files in /etc and $HOME are
         parsed
        :param str fallback: Fallback controller if none was found in the environment or the config. Defaults
         to 'linstor://localhost'.
        :return: List of linstor uris. This list is intended to be used via the MultiLinstor class.
        :rtype: list[str]
        """
        controllers = os.environ.get('LS_CONTROLLERS', None)
        if not controllers:
            cfg = Config.get_section(section, config_file_name)
            controllers = cfg.get('controllers', fallback)

        return MultiLinstor.controller_uri_list(controllers)
