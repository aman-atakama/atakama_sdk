# Atakama Python SDK


## Overview

This is a library for programmatically interacting and enhancing the Atakama encrypted file system.

However, the best way to interact with Atakama is to use the filesystem itself.

*It is not necessary to use this SDK for most development efforts, it is provided solely for efficiency and convenience.*

### For example:

In order to integrate with ssh, so that you have to approve a login on your phone, 
the easiest thing to do is create an identity file, secure it with Atakama, and then put a soft link to it.

That way when you go to ssh in somewhere, the identity file is unlocked, and you are prompted on your mobile device.

Using the atakama command-line or SDK would not be recommended in this case.   

## Plugin System:

Atakama supports plugins. This is largely done so that we can have multiple release cycles for 3rd party vendor integrations.

### Detector Plugins:

Atakama runs a file monitoring system. This system will automatically-encrypt files as files are modified. For efficiency,
especially on large systems, it may be desirable to alter the rules used to detect and encrypt files.

#### Example of a detector plugin:

This plugin will cause any file with the word "secret" in the name to be encrypted.

```
from atakama import DetectorPlugin

class ExampleDetector(DetectorPlugin):
    @staticmethod
    def name():
        return "example-detector"

    def needs_encryption(self, full_path):
        return "secret" in full_path:
```

### Dependencies:

Detector plugins run inside a protected namespace within Atakama.   Not all imports are available.

 - Python code is version 3
 - All `__builtins__` are guaranteed to be available
 - In particular, `subprocess`, `sys`, `requests`, `os`, `zipfile` and `atakama` are explicitly available.
 - If you're concerned about specific package versions and other dependencies, please package your plugin as a subprocess call (or DLL) with its own deps included
 - Atakama will endeavor to update the `ATAKAMA_SDK_VERSION` if we ship libraries that have major version changes, or backward breaking python-version changes
