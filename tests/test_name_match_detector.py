# SPDX-FileCopyrightText: © Atakama, Inc <support@atakama.com>
# SPDX-License-Identifier: LGPL-3.0-or-later

from example.name_match import NameMatchDetector


def test_regex():
    detector = NameMatchDetector(
        {"type": " Regex", "pattern": "(?i).*\\.(pdf|doc|docx)$"}
    )
    assert detector.needs_encryption(r"C:\Users\Documents\Documentation\document.doc")
    assert detector.needs_encryption(r"C:\Users\Documents\Documentation\document.DoC")
    assert detector.needs_encryption(r"D:\Downloads\secrets.pdf")
    assert not detector.needs_encryption(r"D:\Downloads\secrets.xls")
    assert not detector.needs_encryption(r"C:\Users\Downloads\confidential.docm")

    detector = NameMatchDetector(
        {"type": " Regex", "pattern": "(?i).*\\.(pdf|doc|docx)$", "invert": "true"}
    )
    assert not detector.needs_encryption(
        r"C:\Users\Documents\Documentation\document.doc"
    )
    assert not detector.needs_encryption(
        r"C:\Users\Documents\Documentation\document.DoC"
    )
    assert not detector.needs_encryption(r"D:\Downloads\secrets.pdf")
    assert detector.needs_encryption(r"D:\Downloads\secrets.xls")
    assert detector.needs_encryption(r"C:\Users\Downloads\confidential.docm")


def test_glob():
    detector = NameMatchDetector({"type": "gloB", "pattern": "*.pdf"})
    assert detector.needs_encryption(r"C:\Downloads\secRetS.pdf")
    assert detector.needs_encryption(r"D:\Downloads\secrets.pdf")
    assert not detector.needs_encryption(r"F:\Top Secret.docx")

    detector = NameMatchDetector({"type": "gloB", "pattern": "*.pdf", "invert": "true"})
    assert not detector.needs_encryption(r"C:\Downloads\secRetS.pdf")
    assert not detector.needs_encryption(r"D:\Downloads\secrets.pdf")
    assert detector.needs_encryption(r"F:\Top Secret.docx")


def test_true():
    detector = NameMatchDetector({"type": " * "})
    assert detector.needs_encryption("/test")
    assert detector.needs_encryption("tEsT.exe")
    assert detector.needs_encryption("D://Not\x00a>valid\\path:")
