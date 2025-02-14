from setuptools import setup, find_packages

setup(
    name="dgii_signer",
    version="1.0.0",
    author="Angel Pimentel",
    author_email="angelpimentelcontact@gmail.com",
    description="XML signer for DGII with Python",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/angelpimentell/python-dgii-signer",
    packages=find_packages(),
    install_requires=[
        "certifi==2025.1.31",
        "cffi==1.17.1",
        "cryptography==44.0.1",
        "lxml==5.3.1",
        "pycparser==2.22",
        "signxml==4.0.3",
    ],
    python_requires=">=3.8.0",
)
