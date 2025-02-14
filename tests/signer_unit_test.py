from signers import DgiiSigner
import pathlib
import os
from helpers import clean_xml


def test_sign_invoice():
    # Arrange
    signer = DgiiSigner(f"{pathlib.Path().resolve()}{os.sep}files{os.sep}certificate.p12", "admin")
    xml_content = open(f"{pathlib.Path().resolve()}{os.sep}files{os.sep}invoice.xml").read()
    expected_xml_content = open(f"{pathlib.Path().resolve()}{os.sep}files{os.sep}invoice_signed.xml", encoding="utf-8").read()

    # Act
    signed_xml_content = signer.sign(xml_content)

    # Assert
    assert clean_xml(expected_xml_content) == clean_xml(signed_xml_content)
