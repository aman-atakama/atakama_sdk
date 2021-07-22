# note: do not move these packages around!

from atakama import DetectorPlugin, FileChangedPlugin, Plugin

def test_simple_detector():
    # we just test that we can write a class to spec
    class ExamplePlugin(DetectorPlugin):
        @staticmethod
        def name():
            return "yo"

        def needs_encryption(self, full_path):
            return True

    assert Plugin.get_by_name("yo") is ExamplePlugin

    ExamplePlugin({"arg": 1})



def test_simple_fchange():
    # we just test that we can write a class to spec
    class ExamplePlugin(FileChangedPlugin):
        @staticmethod
        def name():
            return "yo"

        def file_changed(self, full_path):
            return

    assert Plugin.get_by_name("yo") is ExamplePlugin

    ExamplePlugin({"arg": 1})

