"""Atakama plugin base lib."""

import abc
import os
import sys
import importlib
from typing import TypeVar, List, Type, Any, Dict

SDK_VERSION_NAME = "ATAKAMA_SDK_VERSION"


def is_abstract(cls):
    """Return true if the class has __abstractmethods__"""
    return bool(getattr(cls, "__abstractmethods__", False))


def strip_ext(text):
    return os.path.splitext(text)[0]


def look_for_sdk_version(module):
    """Look for the sdk version at the package level for plugins."""

    mod = sys.modules.get(module)
    if mod and hasattr(mod, SDK_VERSION_NAME):
        return getattr(mod, SDK_VERSION_NAME)

    try:
        # we look for a module named sdk_version
        mod = importlib.import_module(module + ".sdk_version")
        return getattr(mod, SDK_VERSION_NAME)
    except ImportError:
        pass

    parent_module = strip_ext(module)
    if "." in parent_module:
        return look_for_sdk_version(parent_module)

    return None


class PluginVersionMissingError(RuntimeError):
    pass


T = TypeVar("T")


class Plugin(abc.ABC):
    """Derive from this class to make a new plugin type."""

    CURRENT_SDK_VERSION = 1
    _all_plugins_by_name: Dict[str, Type["Plugin"]] = {}

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
    def type(cls) -> str:
        """Return the type of plugin that this is.

        Used for display purposes only, default is the super class name.
        """
        return cls.__bases__[0].__name__

    @classmethod
    def get_by_name(cls, name: str) -> Type[T]:
        """Return a plugin based on the name."""
        return cls._all_plugins_by_name[name]

    @classmethod
    def get_sdk_version(cls) -> float:
        """Get the compatible sdk version.

        By default, looks in the current module's .sdk_version for the ATAKAMA_SDK_VERSION variable.


        Plugin makers can override this.

        For example, it's possible to make a plugin that's compatible with many versions.

        Or you can choose to package your signed plugins differently.
        """

        version = look_for_sdk_version(cls.__module__)
        if not version:
            raise PluginVersionMissingError("no version for %s" % cls.__name__)
        return version

    @classmethod
    def all_names(cls):
        """Get a list of all plugin names."""
        return list(cls._all_plugins_by_name)


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


__all__ = [
    "Plugin",
    "DetectorPlugin",
    "FileChangedPlugin",
    "SDK_VERSION_NAME",
    "PluginVersionMissingError",
]
