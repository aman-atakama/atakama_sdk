# [atakama](atakama.md).plugin_base
Atakama plugin base lib.


#### .needs_encryption(self, full_path) -> bool
Return true if the file needs to be encrypted.

This is called any time a file in a secure folder is changed.


#### .watch_callback(self, full_path) -> List[str]
Return a list of dependent files to check if they need encryption.

This is called any time a file in a secure folder is changed.


#### .file_changed(self, full_path) -> None
Called when a file is created or changed within a vault.

Typically used for document (re)classification.


## Plugin(ABC)
Derive from this class to make a new plugin type.


#### .name() -> str
Name this plugin.

This is used in the configuration file to enable/disable this plugin.


## StartupPlugin(Plugin)
Plugin for launching things at start and at shutdown.


#### .run_after_start(self) -> bool
Runs once at product start, after gui & filesystem are running.

Exceptions prevent startup and may induce a dialog/alert.


#### .run_before_start(self) -> bool
Runs once before product start, can be uses to modify the system before startup.

Exceptions cause the system to shut down, and may cause a dialog/alert.


#### .shutdown(self)
Runs at system shutdown, exceptions are logged but ignored.

