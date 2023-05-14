import re
from collections import OrderedDict

from sigma.backends.QRadarAQL import QRadarAQLBackend
from sigma.pipelines.QRadarAQL.QRadarAQL import qradar_log_source_mapping, \
    qradar_field_mapping
import pandas as pd


def field_mapping():
    header = "\n### Field Mapping"
    mapping = OrderedDict(qradar_field_mapping)
    mapping_table = pd.DataFrame({
        '<u>Sigma field</u>': mapping.keys(),
        '<u>QRadar AQL field</u>': [
            re.sub(r"[\[\]']", "", str(val)) for val in mapping.values()
        ]})
    return (
        f"{header}\n\n"
        f"{mapping_table.to_markdown(index=False)}\n"
    )


def device_mapping(log_source, log_source_mapping):
    header = f"\n#### Sigma {log_source} name mapping to QRadar device name"
    mapping = OrderedDict(log_source_mapping)
    log_source_device_type = [
        [list(qradar_log_source_mapping.keys())[list(
            qradar_log_source_mapping.values()).index(device_type)] for device_type
         in device_types]
        for device_types in mapping.values()
    ]
    mapping_table = pd.DataFrame({
        f'<u>Sigma {log_source}</u>': mapping.keys(),
        '<u>QRadar device name</u>': [
            re.sub(r"[\[\]']", "", str(val)) for val in log_source_device_type
        ],
        '<u>QRadar device type</u>': [
            re.sub(r"[\[\]']", "", str(val)) for val in mapping.values()
        ]}
    )
    return (
        f"{header}\n\n"
        f"{mapping_table.to_markdown(index=False)}"
    )


def log_sources_mapping():
    header = "### Log-Source Mapping"
    service_mapping = device_mapping("service", QRadarAQLBackend.service_devicetype)
    product_mapping = device_mapping("product", QRadarAQLBackend.product_devicetype)
    return (
        f"\n{header}\n"
        f"{service_mapping}\n"
        f"{product_mapping}"
    )


mappings = (
    f"{field_mapping()}"
    f"{log_sources_mapping()}"
)


def generate_README():
    with open("./readme_template.md", 'r') as f:
        template = f.read()
        template = template.replace('{{mappings}}', mappings)
    with open("./README.md", 'w+') as f:
        f.write(template)


if __name__ == '__main__':
    generate_README()
