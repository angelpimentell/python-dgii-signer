from signers import DgiiSigner
import pathlib
import os
import re

def clean_content(xml_content):
    xml_content = xml_content.replace("\n", "")
    xml_content = re.sub(r">\s+<", "><", xml_content)
    return xml_content.strip()


def test_sign_invoice():
    # Arrange
    signer = DgiiSigner(f"{pathlib.Path().resolve()}{os.sep}files{os.sep}certificate.p12", "admin")
    xml_content = open(f"{pathlib.Path().resolve()}{os.sep}files{os.sep}invoice.xml").read()
    expected_xml_content = open(f"{pathlib.Path().resolve()}{os.sep}files{os.sep}invoice_signed.xml", encoding="utf-8").read()

    # Act
    signed_xml_content = signer.sign(xml_content)

    # Assert
    assert clean_content(expected_xml_content) == clean_content(signed_xml_content)
