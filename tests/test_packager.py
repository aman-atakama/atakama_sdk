import shutil
import sys
from contextlib import suppress
from glob import glob
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

def test_package_main(request, self_signed_cert, tmp_path):
    pkg_dir = tmp_path / "ex"
    shutil.copytree(str(EXAMPLE_RUNCMD_PATH.parent), str(pkg_dir))
    src_dir = pkg_dir / "runcmd"

    priv, crt = self_signed_cert

    dist_dir = pkg_dir / "dist"

    request.addfinalizer(lambda: shutil.rmtree(pkg_dir / "build"))
    request.addfinalizer(lambda: shutil.rmtree(dist_dir))

    # remove the dist dir, in case it's leftover from an aborted test
    sys.argv = ["whatever", "--src", str(src_dir), "--key", priv, "--crt", crt]
    with pytest.raises(Exception):
        main()

    # have to pass self-signed to generate an apkg file
    sys.argv += ["--self-signed"]
    main()
    assert dist_dir.is_dir()
    final, = [file for file in dist_dir.iterdir() if file.suffix == ".apkg" and "runcmd" in str(file)]

    Packager.unpack_plugin(final, tmp_path, self_signed=True)

    files = set(Path(f).name for f in Path(tmp_path).glob("runcmd/*.py"))
    assert "subproc_detector.py" in files
    assert "sdk_version.py" in files

    with pytest.raises(Exception):
        Packager.unpack_plugin(final, tmp_path)

def test_not_valid_key(self_signed_cert, tmp_path):
    pkg_dir = tmp_path / "ex"
    shutil.copytree(str(EXAMPLE_RUNCMD_PATH.parent), str(pkg_dir))
    priv, crt = self_signed_cert
    sys.argv = ["whatever", "--src", str(pkg_dir / "runcmd"), "--key", crt, "--crt", crt, "--self-signed"]
    with pytest.raises(SystemExit):
        main()

def test_invalid_args():
    sys.argv = ["whatever", "--key", "whatver", "--crt", "whatever"]
    with pytest.raises(ValueError):
        main()

def test_not_valid_cert(self_signed_cert):
    # self signed are not valid
    _, crt = self_signed_cert
    p = Packager()
    with pytest.raises(Exception):
        p.verify_certificate(crt)