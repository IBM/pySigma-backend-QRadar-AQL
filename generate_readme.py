import re
from collections import OrderedDict

from sigma.backends.QRadarAQL import QRadarAQLBackend
from sigma.pipelines.QRadarAQL.QRadarAQL import qradar_log_source_mapping, \
    qradar_field_mapping
import pandas as pd


def field_mapping():
    header = "### Field Mapping"
    mapping = OrderedDict(qradar_field_mapping)
    mapping_table = pd.DataFrame({
        '<u>Sigma field</u>': mapping.keys(),
        '<u>QRadar AQL field</u>': [
            re.sub(r"[\[\]']", "", str(val)) for val in mapping.values()
        ]})
    return (
        f"{header}\n\n"
        f"{mapping_table.to_markdown(index=False)}"
    )


def device_mapping(log_source, log_source_mapping):
    header = f"#### Sigma {log_source} name mapping to QRadar device name"
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
        f"{mapping_table.to_markdown(index=False)}\n\n"
    )


def log_sources_mapping():
    header = "### Log-Source Mapping"
    service_mapping = device_mapping("service", QRadarAQLBackend.service_devicetype)
    product_mapping = device_mapping("product", QRadarAQLBackend.product_devicetype)
    return (
        f"{header}\n\n"
        f"{service_mapping}\n\n"
        f"{product_mapping}\n"
    )


badges = (
    "[![Tests](https://github.com/IBM/pySigma-backend-QRadar-AQL/actions/workflows"
    "/test.yml/badge.svg)](https://github.com/IBM/pySigma-backend-QRadar-AQL/actions"
    "/workflows/test.yml)\n"
    "![Coverage Badge](https://img.shields.io/endpoint?url=https://gist"
    ".githubusercontent.com/IBM/https://gist.github.ibm.com/Noaa-Kless"
    "/2a6a370ae37067d0c28be98eeeee4f61/raw/IBM-pySigma-backend-QRadar-AQL.json)\n"
    "![Status](https://img.shields.io/badge/Status-release-green)\n"
)

pySigma_QRadarAQL = (
    "# `PySigma QRadar AQL`\n"
    "This is the QRadar AQL backend for [pySigma](https://github.com/SigmaHQ/pySigma) "
    "which parses and converts [Sigma](https://github.com/SigmaHQ/sigma) Rules into "
    "QRadar queries in AQL. It consists of a backend and two pipelines as describes "
    "below.\n"
)

Backend = (
    "## Backend\n"
    "- QRadarAQL: It provides the package `sigma.backends.QRadarAQL` with the "
    "`QRadarAQLBackend` class.\n"
    "It converts Sigma log-sources to Qradar device-type using the "
    "[Log-source Mapping](./README.md#log-source-mapping).\n"
)

pipelines = (
    "## Pipelines\n"
    "Further, it contains the following processing pipelines in "
    "`sigma.pipelines.QRadarAQL`:\n"
    "- QRadarAQL_fields_pipeline: Supports only the `Sigma fields` in the "
    "[Field Mapping](./README.md#field-mapping).\n"
    "- QRadarAQL_payload_pipeline: Uses `UTF8(payload)` instead of fields unsupported "
    "by the [Field Mapping](./README.md#field-mapping). For unsupported fields, the "
    "following value types are not supported–\n"
    "   * Boolean\n"
    "   * Null\n"
    "   * CIDR\n"
    "   * Regular Expression\n"
    "   * Numeric Comparison\n"
)

installation = (
    "## Installation\n"
    "Installation can be done using Sigma's plugins after installing [sigma-cli]("
    "https://github.com/SigmaHQ/sigma-cli#Installation)\n"
    "<pre>sigma plugin install QRadarAQL</pre>"
)

usage = (
    "## Usage\n"

    "### Usage via [Sigma-CLI](https://github.com/SigmaHQ/sigma-cli#usage)\n"
    "Use `QRadarAQL` as backend, and one of `QRadarAQL_fields` and "
    "`QRadarAQL_payload` as pipeline.\n"

    "##### Input example:\n"
    "<pre>"
    "sigma convert -t QRadarAQL -p QRadarAQL_payload "
    "rules/windows/builtin/application/win_audit_cve.yml -o output_file.txt"
    "</pre>\n"

    "##### Output example:\n"
    "<pre>"
    "[\"SELECT * FROM events WHERE devicetype=12 AND (LOWER(UTF8(payload)) LIKE "
    "'%microsoft-windows-audit-cve%' OR LOWER(UTF8(payload)) LIKE '%audit-cve%') AND "
    "'Event ID'=1\"]"
    "</pre>\n"

    "### Usage for developers\n"
    "##### Input example:\n"
    "<pre>"
    "from sigma.collection import SigmaCollection\n"
    "from sigma.backends.QRadarAQL import QRadarAQLBackend\n"
    "from sigma.pipelines.QRadarAQL import QRadarAQL_payload_pipeline, "
    "QRadarAQL_fields_pipeline\n"

    "pipeline = QRadarAQL_fields_pipeline  # or QRadarAQL_payload_pipeline\n"
    'rule = SigmaCollection.from_yaml("""\n'
    "   logsource:\n"
    "       category: process_access\n"
    "       product: windows\n"
    "   detection:\n"
    "       selection:\n"
    "          CallTrace|startswith: 'C:\Windows\System32\\ntdll.dll+'\n"
    "           GrantedAccess:\n"
    "               - '0x1028'\n"
    "               - '0x1fffff'\n"
    "       condition: selection\n"
    '""")\n'
    "print(QRadarAQLBackend(pipeline()).convert(rule))"
    "</pre>\n"

    "##### Output example:\n"
    "<pre>"
    "[\"SELECT * FROM events WHERE devicetype=12 AND LOWER('Call Trace') LIKE "
    "'c:\\windows\\system32 tdll.dll+%' AND ('Granted Access' IN('0x1028', "
    "'0x1fffff'))\"]"
    "</pre>\n"
)

QRadar_content_packs = (
    "## QRadar Content Packs\n"
    "- [Properties Dictionary](https://exchange.xforce.ibmcloud.com/hub/extension"
    "/73f46b27280d30a4b8ec4685da391b1c) (required)\n"
    "- [Windows Custom Properties]("
    "https://exchange.xforce.ibmcloud.com/hub/extension/IBMQRadar"
    ":MicrosoftWindowsCustomProperties) (recommended)\n"
    "- [Linux Custom Properties](https://exchange.xforce.ibmcloud.com/hub/extension"
    "/427f5d543cb917916619e6abafc26404) (recommended)\n\n"
    "other properties you may find in the [App Exchange]("
    "https://exchange.xforce.ibmcloud.com/hub)\n"
)

mappings = (
    "## Mapping\n\n"
    f"{field_mapping()}\n\n"
    f"{log_sources_mapping()}"
)

mapping_contribution = (
    "## Mapping Contribution\n"
    "Pull requests are welcome. After updating the Mapping, run "
    "[generate_readme.py](./sigma/generate_readme.py) for updating the README tables.\n"

    "###### [Field Mapping](./sigma/pipelines/QRadarAQL/QRadarAQL.py): field mapping "
    "from Sigma to AQL\n"
    "- `field_mapping`: mapping for fields with exact mach from Sigma to AQL\n"
    "- `host_field_mapping`: mapping for host fields- values with wildcards converts "
    "to CIDR\n"
    "- `unstructured_field_mapping`: mapping for fields that their value is a "
    "substring of another field's value- equal sign ('=') will be replaced with "
    "'LIKE' operator\n"
    "- `unstructured_part_field_mapping`: mapping for fields that are part of another "
    "field- equal sign ('=') will be replaced with 'LIKE' operator, and the value "
    "transforms to the form '{field}%{value}' \n"

    "###### [Log-Source Mapping](./sigma/backends/QRadarAQL/QRadarAQL.py): mapping from"
    " Sigma log source to AQL device type id using the `qradar_log_source_mapping` "
    "taken from QRadar DataBase\n"

    "- [qradar_log_source_mapping](./sigma/pipelines/QRadarAQL/QRadarAQL.py): QRadar "
    "mapping from AQL device name to device type id, taken from  DataBase – *PLEASE "
    "DO NOT CHANGE THIS MAPPING*\n"
    "- `service_devicetype`: services mapping\n"
    "- `product_devicetype`: products mapping\n"
)

licensing = (
    "## License\n"
    "pySigma-backend-QRadar-AQL is licensed under the MIT [License](./LICENSE).\n"
)

maintainers = (
    "## Maintainers\n"
    "* [Cyber Center of Excellence - IBM](https://github.com/noaakl/)\n"
)


def generate_README():
    content = (
        f"{badges}\n\n"
        f"{pySigma_QRadarAQL}\n\n"
        f"{Backend}\n\n"
        f"{pipelines}\n\n"
        f"{installation}\n\n"
        f"{usage}\n\n"
        f"{QRadar_content_packs}\n\n"
        f"{mappings}\n\n"
        f"{mapping_contribution}\n\n"
        f"{licensing}"
        f"{maintainers}"
    )
    with open("./README.md", 'w') as f:
        f.write(content)


if __name__ == '__main__':
    generate_README()
