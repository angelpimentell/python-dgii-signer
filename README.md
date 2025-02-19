# Python Dgii Signer

![Pip Version](https://img.shields.io/badge/pip-23.2.1-orange)

![Python Versions](https://img.shields.io/badge/python-3.8%20%7C%203.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)

Firmador de XML para DGII con Python.

<br />

How to prepare
```Bash
pip install -r .\requirements.txt
```

Run tests
```Bash
pytest .\tests\signer_unit_test.py
```

How to use

```Python
from dgii_signer import DgiiSigner

signer = DgiiSigner("/path/cert.p12", "admin")
xml_content = open("/path/invoice.xml").read()

signed_xml_content = signer.sign(xml_content)
```