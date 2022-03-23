# SPDX-FileCopyrightText: © 2020 Atakama, Inc <support@atakama.com>
# SPDX-License-Identifier: LGPL-3.0-or-later

import fnmatch
import re

from atakama import DetectorPlugin


class NameMatchDetector(DetectorPlugin):
    """A Detector that classifies files based on name.

    Config accepts three (3) fields: type, pattern, and invert.

    Type: One of "glob", "regex", and "*". Determines how the pattern in
          interpreted.
    Pattern: The pattern to match against.
    Invert: If set to "true" will invert the match selection, i.e., files that
            don't match the pattern will be encrypted.

    If glob, a file is classified if the pattern can be glob expanded to the
    filename. Supports wildcards (* and ?) and character ranges (e.g., [aeiou]
    and [a-z]).

    If regex, the pattern is a regular expression to be matched against. See the
    documention for the python re module for more information.

    If *, all files are selected. No pattern field in the config is required.
    The invert field is ignored."""

    def __init__(self, args):
        super().__init__(args)
        match_type = args["type"].strip().lower()
        invert = args.pop("invert", "false").strip().lower()
        if match_type == "*":
            self.match_fn = self.true_match
        elif match_type == "glob":
            if invert == "true":
                self.match_fn = lambda path: not self.regex_match(path)
            else:
                self.match_fn = self.regex_match
            self.pattern = args["pattern"]
            self.pattern = re.compile(fnmatch.translate(self.pattern))
        elif match_type == "regex":
            if invert == "true":
                self.match_fn = lambda path: not self.regex_match(path)
            else:
                self.match_fn = self.regex_match
            self.pattern = args["pattern"]
            self.pattern = re.compile(self.pattern)
        else:
            raise NotImplementedError

    @staticmethod
    def name():
        return "name-match-detector"

    def needs_encryption(self, path):
        print(path)
        print(self.match_fn)
        print(self.match_fn(path))
        return self.match_fn(path)

    def regex_match(self, path):
        return self.pattern.search(path)

    def true_match(self, path):
        return True
