import os
from configparser import RawConfigParser, NoSectionError, NoOptionError

#: Locations where to look for configuration file by *increasing* priority
CONFIG_PATH = [
    "/etc/ovh.conf",
    os.path.expanduser("~/.ovh.conf"),
    os.path.realpath("./ovh.conf"),
]


class ConfigurationManager(object):
    """
    Application wide configuration manager
    """

    def __init__(self):
        """
        Create a config parser and load config from environment.
        """
        # create config parser
        self.config = RawConfigParser()
        self.config.read(CONFIG_PATH)

    def get(self, section, name):
        """
        Load parameter ``name`` from configuration, respecting priority order.
        Most of the time, ``section`` will correspond to the current api
        ``endpoint``. ``default`` section only contains ``endpoint`` and general
        configuration.

        :param str section: configuration section or region name. Ignored when
            looking in environment
        :param str name: configuration parameter to lookup
        """
        # 1/ try env
        try:
            return os.environ["OVH_" + name.upper()]
        except KeyError:
            pass

        # 2/ try from specified section/endpoint
        try:
            return self.config.get(section, name)
        except (NoSectionError, NoOptionError):
            pass

        # not found, sorry
        return None

    def read(self, config_file):
        # Read an other config file
        self.config.read(config_file)


#: System wide instance :py:class:`ConfigurationManager` instance
config = ConfigurationManager()
