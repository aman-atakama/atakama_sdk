import re

from atakama import DetectorPlugin

class NameMatchDetector(DetectorPlugin):
    def __init__(self, args):
        super().__init__(args)
        self.match = args["match"]

    @staticmethod
    def name():
        return "name-match-detector"

    def needs_encryption(self, path):
        return re.match(self.match, path)
