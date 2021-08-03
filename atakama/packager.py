import argparse
import os
import subprocess
import sys
import textwrap
from shutil import which
from zipfile import ZipFile


class Packager:
    def __init__(self, src=None, pkg=None, key=None, crt=None, self_signed=False, openssl=None):
        self.pkg = pkg
        self.src = src
        self.key = key
        self.crt = crt
        self.self_signed = self_signed

        self.setup_path = src and os.path.join(self.src, "setup.py")
        self.openssl_path = openssl or which("openssl")
        self.made_setup = False

    @classmethod
    def from_args(cls, argv):
        args = cls.parse_args(argv)
        return Packager(src=args.src, pkg=args.pkg,
                        key=args.key, crt=args.crt,
                        self_signed=args.self_signed, openssl=args.openssl)

    @staticmethod
    def parse_args(argv):
        parser = argparse.ArgumentParser(description="Atakama plugin packaging helper", epilog="""

        An atakama plugin package consists of a python installable package, and an openssl signature file.

        These two files are located in the same zip.


        It is installed by installing the package into the plugins folder.

        The python package can be:

            - a simple zip of sources
            - a binary wheel
            - a certificate file (CRT), proving authority

        This tool simply shells out to openssl as needed to produce the signature.
        """)

        parser.add_argument("--src", help="Package source root folder.")
        parser.add_argument("--pkg", help="Package file path (wheel, for example)")
        parser.add_argument("--key", help="Openssl private key file", required=True)
        parser.add_argument("--crt", help="Openssl certificate file", required=True)
        parser.add_argument("--openssl", help="Location of openssl binary", default=which("openssl"))
        parser.add_argument("--self-signed", help="Allow a self-signed cert", action="store_true")
        args = parser.parse_args(argv)
        if not args.src and not args.pkg:
            raise ValueError("Nothing to do: must specify --src or --pkg")
        return args

    def run_setup(self):
        from distutils.core import run_setup
        dist = run_setup(self.setup_path, script_args=["bdist_wheel"], stop_after='run')
        for typ, ver, path in getattr(dist, "dist_files"):
            if typ == "bdist_wheel":
                self.pkg = path
                return
        raise ValueError("Expected package not created")

    def has_setup(self):
        return os.path.exists(self.setup_path)

    def make_setup(self):
        self.made_setup = True
        with open(self.setup_path, "w") as f:
            f.write(textwrap.dedent("""
        from setuptools import setup
        setup(
            name="atakama_generic_plugin",
            version="1.0",
            description="atakama generic plugin",
            packages=["."],
            setup_requires=["wheel"],
        )
            """))

    def remove_setup(self):
        os.remove(self.setup_path)

    def openssl(self, cmd, **kws) -> subprocess.CompletedProcess:
        print("+ openssl", " ".join(cmd), file=sys.stderr)
        cmd = [self.openssl_path] + cmd
        return subprocess.run(cmd, **kws)

    def sign_package(self):
        key = self.key
        crt = self.crt
        pkg = self.pkg

        sig = pkg + ".sig"
        self.openssl(["dgst", "-sha256", "-sign", key, "-out", sig, pkg], check=True)
        self.verify_package(pkg, sig, crt)

    def verify_package(self, pkg, sig, crt):
        ret = self.openssl(["x509", "-in", crt, "-pubkey", "-noout"], check=True, stdout=subprocess.PIPE)
        pub = crt + ".pub"
        with open(pub, "wb") as f:
            f.write(ret.stdout)
        self.openssl(["dgst", "-sha256", "-verify", pub, "-signature", sig, pkg], check=True)

    def verify_certificate(self, crt):
        self.openssl(["verify", crt], check=True)

    def zip_package(self):
        crt = self.crt
        pkg = self.pkg
        sig = pkg + ".sig"
        final = pkg + ".apkg"
        with ZipFile(final, 'w') as myzip:
            myzip.write(pkg)
            myzip.write(sig)
            myzip.write(crt, arcname="cert")
        print("wrote package", final, file=sys.stderr)
        return final

def main():
    try:
        p = Packager.from_args(sys.argv[1:])

        if not p.self_signed:
            p.verify_certificate(p.crt)

        if p.src:
            if not p.has_setup():
                p.make_setup()
            try:
                p.run_setup()
            finally:
                if p.made_setup:
                    p.remove_setup()

        if p.pkg:
            p.sign_package()
            p.zip_package()

    except subprocess.CalledProcessError as ex:
        print(ex)
        sys.exit(1)


if __name__ == "__main__":
    main()
