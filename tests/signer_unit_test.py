from dgii_signer import DgiiSigner
import os
from helpers import clean_xml


def test_sign_invoice():
    # Arrange
    current_dir = os.path.dirname(os.path.abspath(__file__))
    signer = DgiiSigner(f"{current_dir}{os.sep}files{os.sep}certificate.p12", "admin")
    xml_content = open(f"{current_dir}{os.sep}files{os.sep}invoice.xml").read()
    expected_xml_content = open(f"{current_dir}{os.sep}files{os.sep}invoice_signed.xml", encoding="utf-8").read()

    # Act
    signed_xml_content = signer.sign(xml_content)

    # Assert
    assert clean_xml(expected_xml_content) == clean_xml(signed_xml_content)
