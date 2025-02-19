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

    def clean_xml_inputs(self, element_tree):
        for element in element_tree.iter():
            if element.text is not None:
                element.text = element.text.strip().replace("\n", "").replace("\r", "")
            if element.tail is not None:
                element.tail = element.tail.strip().replace("\n", "").replace("\r", "")

    def get_certificate_data(self) -> (bytes, bytes, any):
        cert_file = open(self.certificate_path, "rb")
        cert_data = cert_file.read()

        private_key, certificate, adds = pkcs12.load_key_and_certificates(
            cert_data,
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

        cert_file.close()
        return private_key_pem, certificate_pem, adds

    def sign(self, xml_content: str) -> str:
        private_key_pem, certificate_pem, _ = self.get_certificate_data()
        xml_element = elementTree.fromstring(clean_xml(xml_content))
        self.clean_xml_inputs(xml_element)

        signer = XMLSigner(
            c14n_algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
        )

        signed_xml = signer.sign(xml_element, key=private_key_pem, cert=certificate_pem)

        # Remove prefixes
        for child in signed_xml.iter():
            if "}" in child.tag:
                child.tag = child.tag.split("}", 1)[1]

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
