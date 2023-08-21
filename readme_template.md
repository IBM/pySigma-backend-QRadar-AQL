# `PySigma QRadar AQL`
This is the QRadar AQL backend for [pySigma](https://github.com/SigmaHQ/pySigma) 
which parses and converts [Sigma](https://github.com/SigmaHQ/sigma) Rules into 
QRadar queries in AQL. It consists of a backend and two pipelines as describes below.
The project is using [pySigma_QRadar_base](https://github.com/IBM/pySigma_QRadar_base)
submodule.


## Backend
- QRadarAQL: It provides the package `sigma.backends.QRadarAQL` with the `QRadarAQLBackend` class.

## Pipelines
Further, it contains the following processing pipelines in `sigma.pipelines.QRadarAQL`:
- QRadarAQL_fields_pipeline: Supports only the `Sigma fields` in the [Field Mapping](./README.md#field-mapping).
- QRadarAQL_payload_pipeline: Uses `UTF8(payload)` instead of fields unsupported by the [Field Mapping](./README.md#field-mapping). For unsupported fields, the following value types are not supported–
   * Boolean
   * Null
   * CIDR
   * Regular Expression
   * Numeric Comparison

## Sigma plugin
### Installation
1. install [sigma-cli](https://github.com/SigmaHQ/sigma-cli#Installation)
2. install with Sigma plugins:
```
sigma plugin install ibm-qradar-aql
```

### Usage
Convert Sigma rules to AQL by using `ibm-qradar-aql` as backend, and one of `qradar-aql-fields` and `qradar-aql-payload` as pipeline:
```
sigma convert -t ibm-qradar-aql -p <qradar-aql-fields | qradar-aql-payload> <rule path> -o <output file name>
```

##### Input example:
*PLEASE NOTE: you should have `Sigma rules` in your project to use the 
following 
command*
```
sigma convert -t ibm-qradar-aql -p qradar-aql-payload rules/windows/create_remote_thread/create_remote_thread_win_keepass.yml -o output_file.txt
```

##### Output example:
```
['SELECT * FROM events WHERE devicetype=12 AND LOWER("Target Process Path") LIKE \'%\\keepass.exe\'']
```

## Develop
### Installation
From `sigma` directory update 
[`pySigma_QRadar_base`](https://github.com/IBM/pySigma_QRadar_base) submodule:
```
git submodule update --init --recursive
```

### Usage
##### Input example:

```python
from sigma.collection import SigmaCollection
from sigma.backends.QRadarAQL import QRadarAQLBackend
from sigma.pipelines.QRadarAQL import QRadarAQL_fields_pipeline

pipeline = QRadarAQL_fields_pipeline  # or QRadarAQL_payload_pipeline
rule = SigmaCollection.from_yaml("""
    logsource:
        product: windows
        category: create_remote_thread
    detection:
        selection:
            TargetImage|endswith: '\KeePass.exe'
        condition: selection
""")
print(QRadarAQLBackend(pipeline()).convert(rule)[0])
```

##### Output example:
```
SELECT * FROM events WHERE devicetype=12 AND LOWER("Target Process Path") LIKE '%\keepass.exe'
```

## QRadar Content Packs
- [Properties Dictionary](https://exchange.xforce.ibmcloud.com/hub/extension/73f46b27280d30a4b8ec4685da391b1c) (required)
- [Windows Custom Properties](https://exchange.xforce.ibmcloud.com/hub/extension/IBMQRadar:MicrosoftWindowsCustomProperties) (recommended)
- [Linux Custom Properties](https://exchange.xforce.ibmcloud.com/hub/extension/427f5d543cb917916619e6abafc26404) (recommended)

other properties you may find in the [App Exchange](https://exchange.xforce.ibmcloud.com/hub)

## Mapping

### Field Mapping
{{field_mapping}}

### Log-Source Mapping

#### Sigma service mapping to QRadar AQL device type
{{service_mapping}}

#### Sigma product mapping to QRadar AQL device type
{{product_mapping}}

## Mapping Contribution
Pull requests are welcome. After updating the Mapping, run 
[generate_readme.py](./generate_readme.py) for updating the mapping tables in 
the README file.

##### [Field Mapping](./sigma/mapping/fields.py): field mapping from Sigma to AQL
- `field_mapping`: mapping for fields with exact mach from Sigma to AQL
- `host_field_mapping`: mapping for host fields- values with wildcards converts to CIDR
- `unstructured_field_mapping`: mapping for fields that their value is a substring of another field's value- equal sign ('=') will be replaced with 'LIKE' operator
- `unstructured_part_field_mapping`: mapping for fields that are part of another field- equal sign ('=') will be replaced with 'LIKE' operator, and the value transforms to the form '{field}%{value}' 

##### Log-Source Mapping: mapping from Sigma log source to AQL device type id
- [aql_log_source_mapping](./sigma/mapping/logsources.py): AQL mapping from 
  device type name to device type id – *PLEASE DO NOT CHANGE THIS MAPPING*
- [aql_service_mapping](./sigma/mapping/services.py): mapping from Sigma 
  services to AQL device type id
- [aql_product_mapping](./sigma/mapping/products.py): mapping from Sigma products 
  to AQL device type id

## License
pySigma-backend-QRadar-AQL is licensed under the MIT [License](./LICENSE).

## Maintainers
* [Cyber Center of Excellence - IBM](https://github.com/noaakl/)
