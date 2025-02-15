import re


def clean_xml(xml_content):
    xml_content = xml_content.replace("\n", "")
    xml_content = re.sub(r">\s+<", "><", xml_content)
    return xml_content.strip()
