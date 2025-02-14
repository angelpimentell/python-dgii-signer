# Python Dgii Signer

Firmador de XML para DGII con Python.

<br />

Python Version
```
Python >= 3.9.13 | Python <= 3.13.1
```

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