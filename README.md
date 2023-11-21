# `PySigma QRadar AQL`
This is the QRadar AQL backend for [pySigma](https://github.com/SigmaHQ/pySigma) 
which parses and converts [Sigma](https://github.com/SigmaHQ/sigma) Rules into 
QRadar queries in AQL. It consists of a backend and two pipelines as describes below.
The project is using [pySigma_QRadar_base](https://github.com/IBM/pySigma_QRadar_base)
submodule.


# Backend
- QRadarAQL: It provides the package `sigma.backends.QRadarAQL` with the `QRadarAQLBackend` class.

# Pipelines
Further, it contains the following processing pipelines in `sigma.pipelines.QRadarAQL`:
- QRadarAQL_fields_pipeline: Supports only the `Sigma fields` in the [Field Mapping](./README.md#field-mapping).
- QRadarAQL_payload_pipeline: Uses `UTF8(payload)` instead of fields unsupported by the [Field Mapping](./README.md#field-mapping). For unsupported fields, the following value types are not supported–
   * Boolean
   * Null
   * CIDR
   * Regular Expression
   * Numeric Comparison

# Installation

## PyPI
```
pip install ibm-qradar-aql
```

## Sigma plugin

### Sigma CLI
1. install [sigma-cli](https://github.com/SigmaHQ/sigma-cli#Installation)
2. install with Sigma plugins:
```
sigma plugin install ibm-qradar-aql
```

### pySigma
```python
from sigma.plugins import SigmaPluginDirectory

plugins = SigmaPluginDirectory.default_plugin_directory()
plugins.get_plugin_by_id("ibm-qradar-aql").install()
```

## Usage
Convert Sigma rules to AQL by using `ibm-qradar-aql` as backend, and one of `qradar-aql-fields` and `qradar-aql-payload` as pipeline:

### Sigma CLI
```
sigma convert -t ibm-qradar-aql -p <qradar-aql-fields | qradar-aql-payload> <rule path> -o <output file name>
```

#### Input example:
*PLEASE NOTE: you should have `Sigma rules` in your project to use the 
following 
command*
```
sigma convert -t ibm-qradar-aql -p qradar-aql-payload rules/windows/create_remote_thread/create_remote_thread_win_keepass.yml -o output_file.txt
```

#### Output example:
```
['SELECT * FROM events WHERE devicetype=12 AND LOWER("Target Process Path") LIKE \'%\\keepass.exe\'']
```

### pySigma
#### Input example:

```python
from sigma.collection import SigmaCollection
from sigma.backends.QRadarAQL import QRadarAQLBackend
from sigma.pipelines.QRadarAQL import QRadarAQL_fields_pipeline, QRadarAQL_payload_pipeline

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

#### Output example:
```
SELECT * FROM events WHERE devicetype=12 AND LOWER("Target Process Path") LIKE '%\keepass.exe'
```

# Develop
This project is using 
[pySigma_QRadar_base](https://github.com/IBM/pySigma_QRadar_base) submodule.
After cloning the project, make sure to update the submodule from the `sigma` directory 
by running:
```
git submodule update --init --recursive
```

# QRadar Content Packs
- [Properties Dictionary](https://exchange.xforce.ibmcloud.com/hub/extension/73f46b27280d30a4b8ec4685da391b1c) (required)
- [Windows Custom Properties](https://exchange.xforce.ibmcloud.com/hub/extension/IBMQRadar:MicrosoftWindowsCustomProperties) (recommended)
- [Linux Custom Properties](https://exchange.xforce.ibmcloud.com/hub/extension/427f5d543cb917916619e6abafc26404) (recommended)

other properties you may find in the [App Exchange](https://exchange.xforce.ibmcloud.com/hub)

# Mapping

## Field Mapping
| <u>Sigma field</u>       | <u>QRadar AQL field</u>                                                               |
|:-------------------------|:--------------------------------------------------------------------------------------|
| AccessList               | Rule Name                                                                             |
| AccessMask               | Access Mask                                                                           |
| Accesses                 | Accesses                                                                              |
| AppID                    | Application                                                                           |
| AppId                    | Application                                                                           |
| AppName                  | Application                                                                           |
| AttributeLDAPDisplayName | Username, Account Name, Distinguished Name                                            |
| AttributeValue           | Attribute Old Value, Attribute New Value                                              |
| c-useragent              | User Agent                                                                            |
| cs-user-agent            | User Agent                                                                            |
| cs-username              | Username                                                                              |
| CallTrace                | Call Trace                                                                            |
| CallerProcessName        | Process Path                                                                          |
| cipher                   | Ticket Encryption Type                                                                |
| CommandLine              | Command                                                                               |
| cs-method                | Method                                                                                |
| DestinationHostname      | Destination Hostname                                                                  |
| ErrorCode                | Error Code                                                                            |
| ExceptionCode            | Error Code                                                                            |
| EventID                  | Event ID                                                                              |
| eventSource              | devicetype                                                                            |
| FailureCode              | Error Code                                                                            |
| FileName                 | Filename                                                                              |
| Filename                 | Filename                                                                              |
| GrantedAccess            | Granted Access                                                                        |
| Hashes                   | CONCAT(MD5=, MD5 Hash , SHA1=, SHA1 Hash , SHA256=, SHA256 Hash , IMPHASH=, IMP HASH) |
| HostApplication          | Process Path                                                                          |
| HostName                 | Hostname                                                                              |
| Initiated                | Initiated                                                                             |
| Image                    | Process Path, Process Name                                                            |
| ImageName                | Process Name                                                                          |
| ImagePath                | Process Path                                                                          |
| Imphash                  | IMP Hash                                                                              |
| IntegrityLevel           | Integrity Level                                                                       |
| InterfaceUuid            | Source Interface UUID                                                                 |
| LogonType                | Logon Type                                                                            |
| Message                  | Message                                                                               |
| Name                     | File Path                                                                             |
| ObjectName               | Object Name                                                                           |
| ObjectType               | Object Type                                                                           |
| OriginalFileName         | Filename                                                                              |
| ParentCommandLine        | Parent Command                                                                        |
| ParentImage              | Parent Process Path                                                                   |
| ParentProcessId          | Parent Process ID                                                                     |
| Path                     | File Path                                                                             |
| path                     | File Path                                                                             |
| Payload                  | UTF8(payload)                                                                         |
| payload                  | UTF8(payload)                                                                         |
| PipeName                 | Pipe Name                                                                             |
| ProcessId                | Process ID                                                                            |
| ProcessName              | Process Name                                                                          |
| ProcessPath              | Process Path                                                                          |
| SamAccountName           | SAM Account Name                                                                      |
| Service                  | Service Name                                                                          |
| ServiceFileName          | Service Filename                                                                      |
| ServiceName              | Service Name                                                                          |
| ShareName                | Share Name                                                                            |
| Signed                   | Signed                                                                                |
| Status                   | Status                                                                                |
| StartAddress             | Start Address                                                                         |
| TargetFilename           | Filename                                                                              |
| TargetImage              | Target Process Path                                                                   |
| TargetObject             | Process Name, Target Process Name, Object Name                                        |
| TargetUserName           | Target Username                                                                       |
| TaskName                 | Task Name                                                                             |
| TicketEncryptionType     | Ticket Encryption Type                                                                |
| UserName                 | Username                                                                              |
| Username                 | Username                                                                              |
| md5                      | MD5 Hash                                                                              |
| method                   | Method                                                                                |
| NewTargetUserName        | Target Username                                                                       |
| sha1                     | SHA1 Hash                                                                             |
| sha256                   | SHA256 Hash                                                                           |
| SourceFilename           | filename                                                                              |
| SourceImage              | Source Process Path                                                                   |
| USER                     | Username                                                                              |
| User                     | Username                                                                              |
| userAgent                | User Agent                                                                            |
| user_agent               | User Agent                                                                            |
| eventName                | QIDNAME(qid)                                                                          |
| ImageLoaded              | CONCAT(file directory, /, filename)                                                   |
| DestinationIp            | destinationip                                                                         |
| DestPort                 | destinationport                                                                       |
| DestinationPort          | destinationport                                                                       |
| destination.port         | destinationport                                                                       |
| dst_ip                   | destinationip                                                                         |
| dst_port                 | destinationport                                                                       |
| SourcePort               | sourceport                                                                            |
| src_ip                   | sourceip                                                                              |
| c-uri                    | URL                                                                                   |
| c-uri-extension          | URL                                                                                   |
| c-uri-query              | URL                                                                                   |
| cs-uri                   | URL                                                                                   |
| cs-uri-query             | URL                                                                                   |
| cs-uri-stem              | URL                                                                                   |
| properties.message       | Message                                                                               |
| ScriptBlockText          | Message                                                                               |
| uri                      | URL                                                                                   |
| a0                       | Command                                                                               |
| a1                       | Command                                                                               |
| a2                       | Command                                                                               |
| a3                       | Command                                                                               |
| a4                       | Command                                                                               |
| a5                       | Command                                                                               |

## Log-Source Mapping

### Sigma service mapping to QRadar AQL device type
| <u>Sigma service</u>   | <u>QRadar AQL device type name</u>                     | <u>QRadar AQL device type id</u>   |
|:-----------------------|:-------------------------------------------------------|:-----------------------------------|
| aaa                    | BridgewaterAAA                                         | 143                                |
| apache                 | Apache                                                 | 10                                 |
| auditd                 | LinuxServer                                            | 11                                 |
| auth                   | WindowsAuthServer                                      | 12                                 |
| clamav                 | LinuxServer                                            | 11                                 |
| cloudtrail             | AmazonAWSCloudTrail                                    | 347                                |
| cron                   | LinuxServer                                            | 11                                 |
| exchange               | MicrosoftExchange                                      | 99                                 |
| gcp.audit              | GoogleCloudAudit                                       | 449                                |
| iis                    | IIS                                                    | 13                                 |
| ldp                    | NetScreenIDP                                           | 17                                 |
| lsa-server             | ISA                                                    | 191                                |
| microsoft365portal     | Office365, Office365MessageTrace, Microsoft365Defender | 397, 452, 515                      |
| okta                   | OktaIdentityManagement                                 | 382                                |
| powershell             | WindowsAuthServer                                      | 12                                 |
| rdp                    | LinuxServer, WindowsAuthServer                         | 11, 12                             |
| smbclient-security     | LinuxServer, WindowsAuthServer                         | 11, 12                             |
| sshd                   | LinuxServer                                            | 11                                 |
| sudo                   | LinuxServer                                            | 11                                 |
| syslog                 | LinuxServer, WindowsAuthServer                         | 11, 12                             |
| sysmon                 | WindowsAuthServer                                      | 12                                 |
| taskscheduler          | LinuxServer, WindowsAuthServer                         | 11, 12                             |
| threat_detection       | SAPEnterpriseThreatDetection                           | 424                                |
| windefend              | MicrosoftWindowsDefenderATP                            | 433                                |
| wmi                    | WindowsAuthServer                                      | 12                                 |

### Sigma product mapping to QRadar AQL device type
| <u>Sigma product</u>   | <u>QRadar AQL device type name</u>                                                                                                                                                                                                                                                                                                       | <u>QRadar AQL device type id</u>                                                                                                                   |
|:-----------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------|
| aws                    | AmazonAWSCloudTrail, AWSSecurityHub, AmazonAWSNetworkFirewall, AmazonAWSALBAccessLogs, AmazonAWSWAF, AmazonAWSKubernetes, AmazonAWSRoute53, AmazonCloudFront, AWSVerifiedAccess                                                                                                                                                          | 347, 440, 456, 460, 501, 502, 507, 516, 519                                                                                                        |
| MicrosoftAzure         | MicrosoftAzure                                                                                                                                                                                                                                                                                                                           | 413                                                                                                                                                |
| cisco                  | Pix, IOS, VpnConcentrator, CSA, IDS, FWSM, ASA, CatOS, ACS, Cisco, NAC, Series12000, Series6500, Series7600, SeriesCRS, SeriesISR, IronPort, Aironet, Wism, ACE, CiscoWirelessNCS, Nexus, CiscoWLC, CiscoCallManager, CiscoISE, CiscoCWS, CiscoStealthwatch, CiscoUmbrella, CiscoMeraki, CiscoAMP, CiscoFirepowerThreatDefense, CiscoDuo | 6, 20, 23, 26, 30, 31, 41, 56, 90, 94, 95, 113, 114, 115, 116, 117, 179, 182, 183, 194, 248, 250, 273, 274, 316, 419, 429, 431, 435, 437, 448, 508 |
| gcp                    | GoogleGSuite, GoogleCloudAudit, GoogleCloudPlatformFirewall, GoogleCloudDNS                                                                                                                                                                                                                                                              | 442, 449, 455, 461                                                                                                                                 |
| huawei                 | SSeriesSwitch, ARSeriesRouter                                                                                                                                                                                                                                                                                                            | 269, 283                                                                                                                                           |
| juniper                | NetScreenFirewall, NetScreenIDP, JuniperSA, NetScreenNSM, InfranetController, JuniperRouter, JuniperSBR, JuniperDX, JuniperMSeries, JuniperMXSeries, JuniperTSeries, JuniperEXSeries, JuniperSRX, Avt, SRC, JuniperAltorVGW, SecurityBinaryLogCollector, JuniperMykonosWebSecurity, JuniperWirelessLAN, JuniperDDoSSecure                | 5, 17, 36, 45, 59, 64, 83, 111, 118, 122, 123, 139, 150, 168, 192, 235, 264, 290, 320, 344                                                         |
| linux                  | LinuxServer                                                                                                                                                                                                                                                                                                                              | 11                                                                                                                                                 |
| m365                   | Office365                                                                                                                                                                                                                                                                                                                                | 397                                                                                                                                                |
| macos                  | AppleOSX                                                                                                                                                                                                                                                                                                                                 | 102                                                                                                                                                |
| okta                   | OktaIdentityManagement                                                                                                                                                                                                                                                                                                                   | 382                                                                                                                                                |
| sql                    | MicrosoftSQL                                                                                                                                                                                                                                                                                                                             | 101                                                                                                                                                |
| windows                | WindowsAuthServer                                                                                                                                                                                                                                                                                                                        | 12                                                                                                                                                 |

# Mapping Contribution
Pull requests are welcome. After updating the Mapping, please run 
[generate_readme.py](./generate_readme.py) for updating the mapping tables in 
the README file.

### [Field Mapping](./sigma/mapping/fields.py):
####field mapping from Sigma to AQL
- `field_mapping`: mapping for fields with exact mach from Sigma to AQL
- `host_field_mapping`: mapping for host fields- values with wildcards converts to CIDR
- `unstructured_field_mapping`: mapping for fields that their value is a substring of another field's value- equal sign ('=') will be replaced with 'LIKE' operator
- `unstructured_part_field_mapping`: mapping for fields that are part of another field- equal sign ('=') will be replaced with 'LIKE' operator, and the value transforms to the form '{field}%{value}' 

### Log-Source Mapping:
####mapping from Sigma log source to AQL device type id
- [aql_log_source_mapping](./sigma/mapping/logsources.py): AQL mapping from 
  device type name to device type id – *PLEASE DO NOT CHANGE THIS MAPPING*
- [aql_service_mapping](./sigma/mapping/services.py): mapping from Sigma 
  services to AQL device type id
- [aql_product_mapping](./sigma/mapping/products.py): mapping from Sigma products 
  to AQL device type id

# License
pySigma-backend-QRadar-AQL is licensed under the MIT [License](./LICENSE).

# Maintainers
* [Cyber Center of Excellence - IBM](https://github.com/noaakl/)
