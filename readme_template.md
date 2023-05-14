# `PySigma QRadar AQL`
This is the QRadar AQL backend for [pySigma](https://github.com/SigmaHQ/pySigma) which parses and converts [Sigma](https://github.com/SigmaHQ/sigma) Rules into QRadar queries in AQL. It consists of a backend and two pipelines as describes below.


## Backend
- QRadarAQL: It provides the package `sigma.backends.QRadarAQL` with the `QRadarAQLBackend` class.
It converts Sigma log-sources to Qradar device-type using the [Log-source Mapping](./README.md#log-source-mapping).


## Pipelines
Further, it contains the following processing pipelines in `sigma.pipelines.QRadarAQL`:
- QRadarAQL_fields_pipeline: Supports only the `Sigma fields` in the [Field Mapping](./README.md#field-mapping).
- QRadarAQL_payload_pipeline: Uses `UTF8(payload)` instead of fields unsupported by the [Field Mapping](./README.md#field-mapping). For unsupported fields, the following value types are not supported–
   * Boolean
   * Null
   * CIDR
   * Regular Expression
   * Numeric Comparison


## Installation
Installation can be done using Sigma's plugins after installing [sigma-cli](https://github.com/SigmaHQ/sigma-cli#Installation)
```
sigma plugin install QRadarAQL
```

## Usage

### Usage via [Sigma-CLI](https://github.com/SigmaHQ/sigma-cli#usage)
Use `QRadarAQL` as backend, and one of `QRadarAQL_fields` and `QRadarAQL_payload` as pipeline.

##### Input example:
```
sigma convert -t QRadarAQL -p QRadarAQL_payload rules/windows/builtin/application/win_audit_cve.yml -o output_file.txt
```

##### Output example:
```
["SELECT * FROM events WHERE devicetype=12 AND (LOWER(UTF8(payload)) LIKE '%microsoft-windows-audit-cve%' OR LOWER(UTF8(payload)) LIKE '%audit-cve%') AND 'Event ID'=1"]
```

### Usage for developers

##### Input example:
```python
from sigma.collection import SigmaCollection
from sigma.backends.QRadarAQL import QRadarAQLBackend
from sigma.pipelines.QRadarAQL import QRadarAQL_payload_pipeline, QRadarAQL_fields_pipeline
pipeline = QRadarAQL_fields_pipeline  # or QRadarAQL_payload_pipeline
rule = SigmaCollection.from_yaml("""
   logsource:
       category: process_access
       product: windows
   detection:
       selection:
          CallTrace|startswith: 'C:\Windows\System32\ntdll.dll+'
           GrantedAccess:
               - '0x1028'
               - '0x1fffff'
       condition: selection
""")
print(QRadarAQLBackend(pipeline()).convert(rule))
```

##### Output example:
```
["SELECT * FROM events WHERE devicetype=12 AND LOWER('Call Trace') LIKE 'c:\windows\system32 tdll.dll+%' AND ('Granted Access' IN('0x1028', '0x1fffff'))"]
```

## QRadar Content Packs
- [Properties Dictionary](https://exchange.xforce.ibmcloud.com/hub/extension/73f46b27280d30a4b8ec4685da391b1c) (required)
- [Windows Custom Properties](https://exchange.xforce.ibmcloud.com/hub/extension/IBMQRadar:MicrosoftWindowsCustomProperties) (recommended)
- [Linux Custom Properties](https://exchange.xforce.ibmcloud.com/hub/extension/427f5d543cb917916619e6abafc26404) (recommended)

other properties you may find in the [App Exchange](https://exchange.xforce.ibmcloud.com/hub)

## Mapping
{{mappings}}

## Mapping Contribution
Pull requests are welcome. After updating the Mapping, run [generate_readme.py](./sigma/generate_readme.py) for updating the README tables.

###### [Field Mapping](./sigma/pipelines/QRadarAQL/QRadarAQL.py): field mapping from Sigma to AQL
- `field_mapping`: mapping for fields with exact mach from Sigma to AQL
- `host_field_mapping`: mapping for host fields- values with wildcards converts to CIDR
- `unstructured_field_mapping`: mapping for fields that their value is a substring of another field's value- equal sign ('=') will be replaced with 'LIKE' operator
- `unstructured_part_field_mapping`: mapping for fields that are part of another field- equal sign ('=') will be replaced with 'LIKE' operator, and the value transforms to the form '{field}%{value}' 

###### [Log-Source Mapping](./sigma/backends/QRadarAQL/QRadarAQL.py): mapping from Sigma log source to AQL device type id using the `qradar_log_source_mapping` taken from QRadar DataBase
- [qradar_log_source_mapping](./sigma/pipelines/QRadarAQL/QRadarAQL.py): QRadar mapping from AQL device name to device type id, taken from  DataBase – *PLEASE DO NOT CHANGE THIS MAPPING*
- `service_devicetype`: services mapping
- `product_devicetype`: products mapping

## License
pySigma-backend-QRadar-AQL is licensed under the MIT [License](./LICENSE).

## Maintainers
* [Cyber Center of Excellence - IBM](https://github.com/noaakl/)
