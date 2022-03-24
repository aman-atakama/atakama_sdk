# SPDX-FileCopyrightText: © Atakama, Inc <support@atakama.com>
# SPDX-License-Identifier: LGPL-3.0-or-later

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
from shutil import which
from typing import List
from zipfile import ZipFile, ZipInfo
from distutils.core import run_setup

import certvalidator
from certvalidator import CertificateValidator, ValidationContext
from oscrypto.asymmetric import load_certificate, rsa_pkcs1v15_verify

errors = certvalidator.errors


class Packager:
    """Class to manage the packing and unpacking of atakama plugins.

    Mostly, plugins are just wheels that get loaded at runtime.

    A package consists of wheels, signatures and a cert.

    Wheels are just unpacked into the plugins/ folder.
    """

    def __init__(
        self, src=None, pkg=None, key=None, crt=None, self_signed=False, openssl=None
    ):
        self.pkg = pkg
        self.src = src
        self.key = key
        self.crt = crt
        self.self_signed = self_signed

        self.setup_path = src and os.path.abspath(os.path.join(self.src, "setup.py"))
        self.openssl_path = openssl or which("openssl")
        self.openssl_path = self.openssl_path and os.path.abspath(self.openssl_path)
        self.made_setup = False

    @classmethod
    def from_args(cls, argv):
        """Given sys args, return a packager."""
        args = cls.parse_args(argv)
        return Packager(
            src=args.src,
            pkg=args.pkg,
            key=args.key,
            crt=args.crt,
            self_signed=args.self_signed,
            openssl=args.openssl,
        )

    @staticmethod
    def parse_args(argv):
        """Command line argument parser."""
        parser = argparse.ArgumentParser(
            description="Atakama plugin packaging helper",
            epilog="""

        An atakama plugin package consists of a python installable package, an openssl signature file,
        and a certificate.

        These three files are located in the same zip.

        It is installed by installing the package into the "plugins" folder.

        The python package can be:
            - a simple zip of sources
            - a binary wheel (which is treated, for now, as a zip anyway)

        This tool simply shells out to openssl as needed to produce the signature.
        """,
        )

        parser.add_argument("--src", help="Package source root folder.")
        parser.add_argument("--pkg", help="Package file path (wheel, for example)")
        parser.add_argument("--key", help="Openssl private key file", required=True)
        parser.add_argument("--crt", help="Openssl certificate file", required=True)
        parser.add_argument(
            "--openssl", help="Location of openssl binary", default=which("openssl")
        )
        parser.add_argument(
            "--self-signed", help="Allow a self-signed cert", action="store_true"
        )
        args = parser.parse_args(argv)
        if not args.src and not args.pkg:
            raise ValueError("Nothing to do: must specify --src or --pkg")
        return args

    def run_setup(self) -> None:
        """Given a src directory, run the setup.py command within it."""
        wd = os.getcwd()
        try:
            os.chdir(os.path.dirname(self.src))
            print("running: ", os.getcwd(), self.setup_path, file=sys.stderr)
            dist = run_setup(self.setup_path, script_args=["bdist_wheel"])
            for typ, _, path in getattr(dist, "dist_files"):
                if typ == "bdist_wheel":
                    self.pkg = os.path.abspath(path)
                    return
            assert False, "Expected package not created"  # pragma: no cover
        finally:
            os.chdir(wd)

    def has_setup(self):
        """True if the setup.py file exists."""
        return os.path.exists(self.setup_path)

    def make_setup(self):
        """Make a fake setup.py.  This is probably a bad idea."""
        print("make setup:", self.setup_path, file=sys.stderr)
        self.made_setup = True
        with open(self.setup_path, "w", encoding="utf8") as f:
            f.write(
                textwrap.dedent(
                    """
        from setuptools import setup
        setup(
            name="{plug_name}",
            version="1.0",
            description="{plug_name}",
            packages=["{plug_name}"],
            setup_requires=["wheel"],
        )
            """.format(
                        plug_name=os.path.basename(self.src)
                    )
                )
            )

    def remove_setup(self):
        os.remove(self.setup_path)

    def openssl(self, cmd, check=True, **kws) -> subprocess.CompletedProcess:
        """Shell openssl, and log that you did so."""
        print("+ openssl", " ".join(cmd), file=sys.stderr)
        cmd = [self.openssl_path] + cmd
        kws["check"] = check
        return subprocess.run(cmd, **kws)  # pylint: disable=subprocess-run-check

    def sign_package(self):
        """Shell openssl, to sign a package given a crt and a privkey."""
        key = self.key
        crt = self.crt
        pkg = self.pkg

        sig = pkg + ".sig"
        self.openssl(["dgst", "-sha256", "-sign", key, "-out", sig, pkg])
        self.verify_signature(crt, pkg, sig)

    @staticmethod
    def verify_certificate(crt):
        """Validate a cert against system root certs."""

        # handles revocation
        # we do not want *users* of this lib to need openssl in the path
        # as opposed to *packages* which we actually *do* want to ensure compat with
        with open(crt, "rb") as f:
            end_entity_cert = f.read()
        context = ValidationContext(weak_hash_algos={"md2", "md5"})
        validator = CertificateValidator(end_entity_cert, validation_context=context)
        validator.validate_usage({"digital_signature"})

    def zip_package(self):
        """Stuff the sig, wheel and cert into an ".apkg" file."""
        crt = self.crt
        pkg = self.pkg
        sig = pkg + ".sig"
        final = pkg + ".apkg"
        with ZipFile(final, "w") as myzip:
            myzip.write(pkg, arcname=os.path.basename(pkg))
            myzip.write(sig, arcname=os.path.basename(sig))
            myzip.write(crt, arcname="cert")
        print(final, file=sys.stdout)
        return final

    @classmethod
    def unpack_plugin(cls, path, dest_dir, self_signed=False):
        """Given an .apkg path, validate it and unpack to dest_dir."""
        with ZipFile(path) as zzz:
            ent: ZipInfo
            wheels: List[ZipInfo] = []
            for ent in zzz.infolist():
                if ent.filename.endswith(".whl"):
                    wheels.append(ent)

            tmpdir = tempfile.mkdtemp("-apkg")
            try:
                crt = zzz.getinfo("cert")
                crt = zzz.extract(crt, tmpdir)

                if not self_signed:
                    cls.verify_certificate(crt)

                unpacked_wheels = []
                for whl in wheels:
                    sig = whl.filename + ".sig"
                    whl = zzz.extract(whl, tmpdir)
                    sig = zzz.extract(sig, tmpdir)
                    cls.verify_signature(crt, whl, sig)
                    unpacked_wheels.append(whl)

                # all checks out?  unpack
                for whl in unpacked_wheels:
                    with ZipFile(whl) as wzip:
                        wzip.extractall(dest_dir)
            finally:
                shutil.rmtree(tmpdir)

    @staticmethod
    def verify_signature(crt, whl, sig):
        """Given 3 files, verify the cert has signed the wheel to produce sig."""
        cert_obj = load_certificate(crt)

        # Load the payload contents and the signature.
        with open(whl, "rb") as f:
            payload_contents = f.read()

        with open(sig, "rb") as f:
            signature = f.read()

        rsa_pkcs1v15_verify(cert_obj, signature, payload_contents, "sha256")


def main():
    """Main entry point."""
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
        print(ex, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":  # pragma: no cover
    main()
