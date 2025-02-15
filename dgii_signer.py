import xml.etree.ElementTree as elementTree

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from lxml import etree
from signxml import XMLSignatureProcessor, XMLSigner
from signxml.algorithms import CanonicalizationMethod

from helpers import clean_xml


class DgiiSigner:
    def __init__(self, certificate_path, password):
        self.certificate_path = certificate_path
        self.password = password

    def get_certificate_data(self) -> (bytes, bytes, any):
        """
        Loads a PKCS12 certificate file and extracts the private key, certificate, and additional data.

        :return: A tuple containing the private key in PEM format, the certificate in PEM format,
                 and additional information from the PKCS12 file.
        :rtype: tuple (bytes, bytes, Any)
        """
        with open(self.certificate_path, "rb") as p12_file:
            p12_data = p12_file.read()
            private_key, certificate, adds = pkcs12.load_key_and_certificates(
                p12_data,
                self.password.encode(),
            )
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
            certificate_pem = certificate.public_bytes(
                encoding=serialization.Encoding.PEM
            )
            return private_key_pem, certificate_pem, adds

    def sign(self, xml_content: str) -> str:
        """
        Signs an XML string, ensuring its integrity and compliance with required standards.

        :param xml_content: The XML string to be signed.
        :type xml_content: str
        :return: The signed and cleaned XML string.
        :rtype: str
        """
        private_key_pem, certificate_pem, adds = self.get_certificate_data()
        xml_content = clean_xml(xml_content)
        xml_element = elementTree.fromstring(xml_content)

        for element in xml_element.iter():
            if element.text is not None:
                element.text = element.text.strip().replace("\n", "").replace("\r", "")
            if element.tail is not None:
                element.tail = element.tail.strip().replace("\n", "").replace("\r", "")

        signer = XMLSigner(
            c14n_algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
        )

        signed_xml = signer.sign(xml_element, key=private_key_pem, cert=certificate_pem)

        for element in signed_xml.iter():
            if element.text is not None:
                element.text = element.text.strip().replace("\n", "").replace("\r", "")
            if element.tail is not None:
                element.tail = element.tail.strip().replace("\n", "").replace("\r", "")

        # Remove prefixes
        for child in signed_xml.iter():
            tag = child.tag
            if "}" in tag:
                child.tag = tag.split("}", 1)[1]

        signed_xml.find("Signature").set("xmlns", "http://www.w3.org/2000/09/xmldsig#")

        transforms = signed_xml.find(".//Transforms")

        if len(transforms) > 1:
            second_transform = signed_xml.findall(".//Transform")[1]
            transforms.remove(second_transform)

        cleaned_xml = elementTree.tostring(signed_xml, encoding="unicode", method="xml")

        cleaned_xml = '<?xml version="1.0" encoding="utf-8"?>' + cleaned_xml

        return cleaned_xml


# Don't modify this function
def _c14n(self, nodes, algorithm: CanonicalizationMethod, inclusive_ns_prefixes=None):
    exclusive, with_comments = False, False

    if algorithm.value.startswith("http://www.w3.org/2001/10/xml-exc-c14n#"):
        exclusive = True
    if algorithm.value.endswith("#WithComments"):
        with_comments = True

    if not isinstance(nodes, list):
        nodes = [nodes]

    c14n = b""
    for node in nodes:
        c14n += etree.tostring(
            node,
            method="c14n",
            exclusive=exclusive,
            with_comments=with_comments,
            inclusive_ns_prefixes=inclusive_ns_prefixes,
        )
    if exclusive is False and self.excise_empty_xmlns_declarations is True:
        # Incorrect legacy behavior. See also:
        # - https://github.com/XML-Security/signxml/issues/193
        # - http://www.w3.org/TR/xml-c14n, "namespace axis"
        # - http://www.w3.org/TR/xml-c14n2/#sec-Namespace-Processing
        c14n = c14n.replace(b' xmlns=""', b"")

    c14n = (
        c14n.replace(b"ds:", b"")
        .replace(b":ds", b"")
        .replace(
            b'<Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"></Transform>',
            b"",
        )
    )
    # logger.debug("Canonicalized string (exclusive=%s, with_comments=%s): %s", exclusive, with_comments, c14n)
    return c14n


XMLSignatureProcessor._c14n = _c14n
