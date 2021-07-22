"""Atakama plugin base lib."""

import abc

from typing import TypeVar, List, Type, Any, Dict


def is_abstract(cls):
    """Return true if the class has __abstractmethods__"""
    return bool(getattr(cls, "__abstractmethods__", False))


T = TypeVar("T")


class Plugin(abc.ABC):
    """Derive from this class to make a new plugin type."""

    _all_plugins_by_name: Dict[str, Type["Plugin"]] = {}

    SDK_VERSION = 1

    def __init__(self, args: Any):
        """Init instance, passing args defined in the config file.

        Only called if config.plugins['name'].enabled is set to True.
        """
        self.args = args

    def __init_subclass__(cls):
        if not is_abstract(cls):
            cls._all_plugins_by_name[cls.name()] = cls

    @staticmethod
    @abc.abstractmethod
    def name() -> str:
        """Name this plugin.

        This is used in the configuration file to enable/disable this plugin.
        """

    @classmethod
    def get_by_name(cls, name: str) -> Type[T]:
        """Return a plugin based on the name."""
        return cls._all_plugins_by_name[name]


class DetectorPlugin(Plugin):
    @abc.abstractmethod
    def needs_encryption(self, full_path) -> bool:
        """Return true if the file needs to be encrypted.

        This is called any time a file in a secure folder is changed.
        """

    def watch_callback(self, full_path) -> List[str]:
        """Return a list of dependent files to check if they need encryption.

        This is called any time a file in a secure folder is changed.
        """


class FileChangedPlugin(Plugin):
    @abc.abstractmethod
    def file_changed(self, full_path) -> None:
        """Called when a file is created or changed within a vault.

        Typically used for document (re)classification.
        """


__all__ = ["Plugin", "DetectorPlugin", "FileChangedPlugin"]
