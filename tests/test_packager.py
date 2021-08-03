import shutil
import subprocess
import sys
from contextlib import suppress
from pathlib import Path

import pytest

from atakama.packager import Packager, main

EXAMPLE_PATH = Path(__file__).parent.parent / "example"
EXAMPLE_RUNCMD_PATH = EXAMPLE_PATH / "runcmd"

@pytest.fixture(scope="module")
def self_signed_cert(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("cert")
    priv = str(tmp_path / "key")
    crt = str(tmp_path / "crt")
    p = Packager()
    p.openssl(["req", "-x509", "-sha256", "-nodes", "-days", "365", "-newkey", "rsa:2048", "-keyout", priv, "-out", crt,
               "-subj", "/C=X /ST=X /L= /O= /OU= /CN=X"
               ], check=True)
    yield priv, crt
    Path(priv).unlink()
    Path(crt).unlink()

def test_package_main(self_signed_cert, tmp_path):
    priv, crt = self_signed_cert
    assert EXAMPLE_RUNCMD_PATH.exists()

    # remove the dist dir, in case it's leftover from an aborted test
    with suppress(FileNotFoundError):
        shutil.rmtree(Path("dist"))

    # have to pass self-signed to generate an apkg file
    sys.argv = ["whatever", "--src", str(EXAMPLE_RUNCMD_PATH), "--key", priv, "--crt", crt, "--self-signed"]
    pkg_dir = EXAMPLE_RUNCMD_PATH.parent
    dist_dir = pkg_dir / "dist"
    main()
    assert dist_dir.is_dir()
    (final, ) = [file for file in dist_dir.iterdir() if file.suffix == ".apkg"]

    Packager.unpack_plugin(final, tmp_path, self_signed=True)

    files = set(Path(f).name for f in Path(tmp_path).glob("runcmd/*.py"))
    assert "subproc_detector.py" in files
    assert "sdk_version.py" in files

def test_not_valid_cert(self_signed_cert):
    # self signed are not valid
    _, crt = self_signed_cert
    p = Packager()
    with pytest.raises(Exception):
        p.verify_certificate(crt)