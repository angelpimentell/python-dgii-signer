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
    install_requires=open("requirements.txt").read().splitlines(),
    python_requires=">=3.13.1",
)
