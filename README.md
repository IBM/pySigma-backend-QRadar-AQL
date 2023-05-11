[![Tests](https://github.com/IBM/pySigma-backend-QRadar-AQL/actions/workflows/test.yml/badge.svg)](https://github.com/IBM/pySigma-backend-QRadar-AQL/actions/workflows/test.yml)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/IBM/https://gist.github.com/noaakl/5059eb0cfbb795a57555c0ea20bdef2a/raw/IBM-pySigma-backend-QRadar-AQL.json)
![Status](https://img.shields.io/badge/Status-release-green)


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
<pre>sigma plugin install QRadarAQL</pre>

## Usage
### Usage via [Sigma-CLI](https://github.com/SigmaHQ/sigma-cli#usage)
Use `QRadarAQL` as backend, and one of `QRadarAQL_fields` and `QRadarAQL_payload` as pipeline.
##### Input example:
<pre>sigma convert -t QRadarAQL -p QRadarAQL_payload rules/windows/builtin/application/win_audit_cve.yml -o output_file.txt</pre>
##### Output example:
<pre>["SELECT * FROM events WHERE devicetype=12 AND (LOWER(UTF8(payload)) LIKE '%microsoft-windows-audit-cve%' OR LOWER(UTF8(payload)) LIKE '%audit-cve%') AND 'Event ID'=1"]</pre>
### Usage for developers
##### Input example:
<pre>from sigma.collection import SigmaCollection
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
print(QRadarAQLBackend(pipeline()).convert(rule))</pre>
##### Output example:
<pre>["SELECT * FROM events WHERE devicetype=12 AND LOWER('Call Trace') LIKE 'c:\windows\system32 tdll.dll+%' AND ('Granted Access' IN('0x1028', '0x1fffff'))"]</pre>


## QRadar Content Packs
- [Properties Dictionary](https://exchange.xforce.ibmcloud.com/hub/extension/73f46b27280d30a4b8ec4685da391b1c) (required)
- [Windows Custom Properties](https://exchange.xforce.ibmcloud.com/hub/extension/IBMQRadar:MicrosoftWindowsCustomProperties) (recommended)
- [Linux Custom Properties](https://exchange.xforce.ibmcloud.com/hub/extension/427f5d543cb917916619e6abafc26404) (recommended)

other properties you may find in the [App Exchange](https://exchange.xforce.ibmcloud.com/hub)


## Mapping

### Field Mapping

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
| cs-username              | username                                                                              |
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
| Image                    | Process Path, Process Name                                                            |
| ImageName                | Process Name                                                                          |
| ImagePath                | Process Path                                                                          |
| Imphash                  | IMP Hash                                                                              |
| IntegrityLevel           | Integrity Level                                                                       |
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
| UserName                 | username                                                                              |
| Username                 | username                                                                              |
| dst_ip                   | username                                                                              |
| md5                      | MD5 Hash                                                                              |
| method                   | Method                                                                                |
| NewTargetUserName        | Target Username                                                                       |
| sha1                     | SHA1 Hash                                                                             |
| sha256                   | SHA256 Hash                                                                           |
| SourceImage              | Source Process Path                                                                   |
| src_ip                   | sourceip                                                                              |
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
| dst_port                 | destinationport                                                                       |
| SourcePort               | sourceport                                                                            |
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

### Log-Source Mapping

#### Sigma service name mapping to QRadar device name

| <u>Sigma service</u>   | <u>QRadar device name</u>                              | <u>QRadar device type</u>   |
|:-----------------------|:-------------------------------------------------------|:----------------------------|
| aaa                    | BridgewaterAAA                                         | 143                         |
| apache                 | Apache                                                 | 10                          |
| auditd                 | LinuxServer                                            | 11                          |
| auth                   | WindowsAuthServer                                      | 12                          |
| clamav                 | LinuxServer                                            | 11                          |
| cloudtrail             | AmazonAWSCloudTrail                                    | 347                         |
| cron                   | LinuxServer                                            | 11                          |
| exchange               | MicrosoftExchange                                      | 99                          |
| gcp.audit              | GoogleCloudAudit                                       | 449                         |
| iis                    | IIS                                                    | 13                          |
| ldp                    | NetScreenIDP                                           | 17                          |
| lsa-server             | ISA                                                    | 191                         |
| microsoft365portal     | Office365, Office365MessageTrace, Microsoft365Defender | 397, 452, 515               |
| okta                   | OktaIdentityManagement                                 | 382                         |
| powershell             | WindowsAuthServer                                      | 12                          |
| rdp                    | LinuxServer, WindowsAuthServer                         | 11, 12                      |
| smbclient-security     | LinuxServer, WindowsAuthServer                         | 11, 12                      |
| sshd                   | LinuxServer                                            | 11                          |
| sudo                   | LinuxServer                                            | 11                          |
| syslog                 | LinuxServer, WindowsAuthServer                         | 11, 12                      |
| sysmon                 | WindowsAuthServer                                      | 12                          |
| taskscheduler          | LinuxServer, WindowsAuthServer                         | 11, 12                      |
| threat_detection       | SAPEnterpriseThreatDetection                           | 424                         |
| windefend              | MicrosoftWindowsDefenderATP                            | 433                         |
| wmi                    | WindowsAuthServer                                      | 12                          |



#### Sigma product name mapping to QRadar device name

| <u>Sigma product</u>   | <u>QRadar device name</u>                                                                                                                                                                                                                                                                                                                | <u>QRadar device type</u>                                                                                                                          |
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
