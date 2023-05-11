import copy
import re
import ipaddress
from typing import Optional, Union, Iterable, List

from sigma.exceptions import SigmaValueError
from sigma.modifiers import SigmaContainsModifier
from sigma.processing.conditions import IncludeFieldCondition,\
    DetectionItemProcessingItemAppliedCondition
from sigma.processing.transformations import FieldMappingTransformation,\
    ValueTransformation, DetectionItemTransformation, SetStateTransformation, \
    DropDetectionItemTransformation
from sigma.processing.pipeline import ProcessingItem

# See https://sigmahq-pysigma.readthedocs.io/en/latest/Processing_Pipelines.html
# for further documentation.
from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaRule
from sigma.types import SigmaType, SigmaNumber, SigmaString, SigmaCIDRExpression, \
    SpecialChars

from sigma.backends.QRadarAQL import QRadarAQLBackend

qradar_log_source_mapping = {
    'Snort': 2,
    'CheckPoint': 3,
    'GenericFirewall': 4,
    'NetScreenFirewall': 5,
    'Pix': 6,
    'GenericAuthServer': 7,
    'SOAP': 8,
    'Dragon': 9,
    'Apache': 10,
    'LinuxServer': 11,
    'WindowsAuthServer': 12,
    'IIS': 13,
    'Iptables': 14,
    'Proventia': 15,
    'Classify': 16,
    'NetScreenIDP': 17,
    'EventCRE': 18,
    'UnityOne': 19,
    'IOS': 20,
    'Contivity': 21,
    'ARN': 22,
    'VpnConcentrator': 23,
    'Solaris2': 24,
    'IntruShield': 25,
    'CSA': 26,
    'Enterasys': 28,
    'Sendmail': 29,
    'IDS': 30,
    'FWSM': 31,
    'SiteProtector': 33,
    'Cyberguard': 35,
    'JuniperSA': 36,
    'Contivityv2': 37,
    'TopLayerIPS': 38,
    'GenericDSM': 39,
    'Tripwire': 40,
    'ASA': 41,
    'Niksun': 42,
    'NetScreenNSM': 45,
    'WebProxy': 46,
    'IpAngel': 47,
    'OracleDbAudit': 48,
    'BigIP': 49,
    'SolarisDhcpd': 50,
    'ArrayVPN': 55,
    'CatOS': 56,
    'ProFTPD': 57,
    'LinuxDHCP': 58,
    'InfranetController': 59,
    'JuniperRouter': 64,
    'GenericLogDSM': 67,
    'NSeries': 68,
    'ExtremeWare': 70,
    'Sidewinder': 71,
    'FortiGate': 73,
    'SonicWall': 78,
    'Vericept': 79,
    'SymantecFirewall': 82,
    'JuniperSBR': 83,
    'IBMAIXServer': 85,
    'MetaIP': 86,
    'SymantecSystemCenter': 87,
    'ACS': 90,
    'CounterAct': 92,
    'McAfeeEpo': 93,
    'Cisco': 94,
    'NAC': 95,
    'TippingPointx505': 96,
    'MicrosoftDHCP': 97,
    'MicrosoftIAS': 98,
    'MicrosoftExchange': 99,
    'TrendISVW': 100,
    'MicrosoftSQL': 101,
    'AppleOSX': 102,
    'Bluecoat': 103,
    'Firewall6000': 104,
    'SIMAudit': 105,
    'Threecom8800SeriesSwitch': 106,
    'VPNGateway': 107,
    'NortelTPS': 108,
    'NortelNAS': 110,
    'JuniperDX': 111,
    'SNAREReflector': 112,
    'Series12000': 113,
    'Series6500': 114,
    'Series7600': 115,
    'SeriesCRS': 116,
    'SeriesISR': 117,
    'JuniperMSeries': 118,
    'Firewall5100': 120,
    'JuniperMXSeries': 122,
    'JuniperTSeries': 123,
    'ERS83_8600': 134,
    'ERS25_45_5500': 135,
    'NortelSR': 136,
    'OpenBSD': 138,
    'JuniperEXSeries': 139,
    'PowerBroker': 140,
    'OracleDBListener': 141,
    'Samhain': 142,
    'BridgewaterAAA': 143,
    'NameValuePair': 144,
    'NortelSNAS': 145,
    'StarentHA': 146,
    'SIMNotification': 147,
    'IBMi': 148,
    'FastIronDsm': 149,
    'JuniperSRX': 150,
    'Cryptoshield': 153,
    'Securesphere': 154,
    'Mobility': 155,
    'NetsightASM': 156,
    'HiGuard': 157,
    'SymbolAP': 158,
    'HiPath': 159,
    'Endpointprotection': 160,
    'RACF': 161,
    'RSAAuthenticationManager': 163,
    'ASE': 164,
    'Officescan': 165,
    'XSRSecurityRouters': 166,
    'Securestack': 167,
    'Avt': 168,
    'OSServices': 169,
    'ASeries': 170,
    'B2Series': 171,
    'B3Series': 172,
    'C2Series': 173,
    'C3Series': 174,
    'DSeries': 175,
    'GSeries': 176,
    'ISeries': 177,
    'ControlManager': 178,
    'IronPort': 179,
    'HpUx': 180,
    'Aironet': 182,
    'Wism': 183,
    'Bind': 185,
    'IBMDomino': 186,
    'Tandem': 187,
    'Hedgehog': 188,
    'SybaseAse': 189,
    'ISA': 191,
    'SRC': 192,
    'DefensePro': 193,
    'ACE': 194,
    'Db2': 195,
    'Auditvault': 196,
    'SourcefireDefenseCenter': 197,
    'Vseries': 198,
    'OracleOSAudit': 199,
    'RiskManagerDefaultQuestion': 200,
    'RiskManagerUserQuestion': 201,
    'RiskManagerDefaultSimulation': 202,
    'RiskManagerUserSimulation': 203,
    'RiskManager': 204,
    'QFLOW': 205,
    'PaSeries': 206,
    'AnomalyDetectionEngine': 207,
    'Procurve': 208,
    'Operationsmanager': 209,
    'VmWare': 210,
    'Websphere': 211,
    'UniversalLEEF': 212,
    'F5ASM': 213,
    'FireEyeMPS': 214,
    'Fairwarning': 215,
    'Informix': 216,
    'TopSecret': 217,
    'Nac': 218,
    'Scom': 219,
    'WebGateway': 220,
    'Acf2': 221,
    'ChangeControl': 222,
    'RandomPasswordManager': 223,
    'EnterpriseConsole': 224,
    'DataONTAP': 225,
    'Puremessage': 226,
    'CyberArkVault': 227,
    'ItronSmartMeter': 228,
    'Bit9Parity': 230,
    'IMS': 231,
    'F5FirePass': 232,
    'CitrixNetScaler': 233,
    'F5APM': 234,
    'JuniperAltorVGW': 235,
    'DLP': 236,
    'SolarisBSM': 238,
    'OracleWebLogic': 239,
    'WebSecurityAppliance': 240,
    'Astaro': 241,
    'Infoblox': 243,
    'ControlElement': 244,
    'EDirectory': 245,
    'WinCollect': 246,
    'EMCVShield': 247,
    'CiscoWirelessNCS': 248,
    'Guardium': 249,
    'Nexus': 250,
    'StoneGate': 251,
    'SolarWindsOrion': 252,
    'MicrosoftFEP': 253,
    'GreatBayBeacon': 254,
    'DamballaFailsafe': 255,
    'SiteMinder': 258,
    'IBMzOS': 259,
    'SharePoint': 260,
    'ITCubeAgileSI': 261,
    'EventCREInjected': 262,
    'DCRSSeries': 263,
    'SecurityBinaryLogCollector': 264,
    'TrendMicroDeepDiscovery': 265,
    'TivoliAccessManager': 266,
    'AssetProfiler': 267,
    'VerdasysDigitalGuardian': 268,
    'SSeriesSwitch': 269,
    'CitrixAccessGateway': 270,
    'HBGaryActiveDefense': 271,
    'APCUninterruptiblePowerSupply': 272,
    'CiscoWLC': 273,
    'CiscoCallManager': 274,
    'CRESystem ': 275,
    'IBMCICS': 276,
    'BarracudaFirewall': 278,
    'OpenLDAP': 279,
    'AppSecDbProtect': 280,
    'BarracudaWAF': 281,
    'OSSEC': 282,
    'ARSeriesRouter': 283,
    'SunONELDAP': 284,
    'BlueCatNetworksAdonis': 285,
    'IBMAIXAudit': 286,
    'PGPUniversalServer': 287,
    'KasperskySecurityCenter': 288,
    'IBMTivoliEndpointManager': 289,
    'JuniperMykonosWebSecurity': 290,
    'NominumVantio': 291,
    'Enterasys800SeriesSwitch': 292,
    'IBMzSecureAlert': 293,
    'IBMSecurityNetworkProtectionXGS': 294,
    'IBMSecurityIdentityManager': 295,
    'BigIPAFM': 296,
    'IBMSecurityNetworkIPS': 297,
    'FidelisXPS': 298,
    'ArpeggioSIFTIT': 299,
    'BarracudaWebFilter': 300,
    'BrocadeFabricOS': 302,
    'ThreatGRIDMalwareThreatIntelligencePlatform': 303,
    'IBMSecurityAccessManagerESSO': 304,
    'EMCvCloud': 305,
    'VenusenseUTM': 306,
    'VenusenseFirewall': 307,
    'VenusenseNIPS': 308,
    'ObserveITObserveIT': 309,
    'PireanAccessOne': 311,
    'VenustechVenusense': 312,
    'PostFixMailTransferAgent': 313,
    'OracleFineGrainedAuditing': 314,
    'EMCVCenter': 315,
    'CiscoISE': 316,
    'HoneycombLexiconFileIntegrityMonitor': 318,
    'AcmePacketSessionDirectorSBC': 319,
    'JuniperWirelessLAN': 320,
    'AkamaiKona': 321,
    'PeakflowSp': 330,
    'ZscalerNss': 331,
    'ProofpointEnterpriseProtectionEnterprisePrivacy': 332,
    'H3CComware': 333,
    'H3CSwitch': 334,
    'H3CRouter': 335,
    'H3CWLAN': 336,
    'H3CSecPath': 337,
    'MicrosoftHyperV': 338,
    'CilasoftQJRN400': 339,
    'VormetricDataFirewall': 340,
    'SafeNetDataSecure': 341,
    'Ceilometer': 342,
    'StealthINTERCEPT': 343,
    'JuniperDDoSSecure': 344,
    'ArborNetworksPravail': 345,
    'TrusteerEnterpriseProtection': 346,
    'AmazonAWSCloudTrail': 347,
    'IBMSecurityDirectoryServer': 348,
    'A4Series': 349,
    'B5Series': 350,
    'C5Series': 351,
    'SalesforceSecurityMonitoring': 352,
    'AhnLabPolicyCenter': 353,
    'AvayaVPNGateway': 354,
    'SearchResults': 355,
    'DGTechnologyMEAS': 356,
    'SalesforceSecurityAuditing': 357,
    'CloudPassageHalo': 358,
    'CorreLogAgentforIBMzOS': 359,
    'WatchGuardFirewareOS': 360,
    'IBMFiberlinkMaaS360': 361,
    'TrendMicroDeepDiscoveryAnalyzer': 362,
    'AccessDataInSight': 363,
    'IBMPrivilegedSessionRecorder': 364,
    'CloudFoundry': 365,
    'IBMSmartCloudOrchestrator': 366,
    'UniversalCEF': 367,
    'IBMHealthMetrics': 368,
    'FreeRADIUS': 369,
    'RiverbedSteelCentralNetProfiler': 370,
    'RiverbedSteelCentralNetProfilerAudit': 371,
    'SSHCryptoAuditor': 372,
    'IBMWebSphereDataPower': 373,
    'SymantecCriticalSystemProtection': 374,
    'SafeNetI': 375,
    'IBMFederatedDirectoryServer': 376,
    'HyTrustCloudControl': 377,
    'LastlineEnterprise': 378,
    'GenuaGenugate': 379,
    'IBMSecurityPrivilegeIdentityManager': 380,
    'NetskopeActive': 381,
    'OktaIdentityManagement': 382,
    'OracleEnterpriseManager': 383,
    'MicrosoftDNS': 384,
    'StealthINTERCEPTAnalytics': 385,
    'StealthINTERCEPTAlerts': 386,
    'ClouderaNavigator': 388,
    'SecurityAccessManagerForMobile': 389,
    'SkyhighNetworksCloudSecurityPlatform': 390,
    'ArubaClearPass': 391,
    'IBMSecurityIdentityGovernance': 392,
    'SeculertSeculert': 393,
    'TrendMicroDeepSecurity': 394,
    'EpicSIEM': 395,
    'EnterpriseITSecuritySFSherlock': 396,
    'Office365': 397,
    'ExabeamExabeam': 398,
    'BluecoatWebSecurityService': 399,
    'CarbonBlack': 400,
    'TrendMicroDeepDiscoveryEmailInspector': 401,
    'OnapsisSecurityPlatform': 402,
    'CyberArkPrivilegedThreatAnalytics': 403,
    'PaloAltoEndpointSecurityManager': 404,
    'Box': 405,
    'RadwareAppWall': 406,
    'CrowdStrikeFalconHost': 407,
    'IBMSense': 408,
    'CloudLockCloudSecurityFabric': 409,
    'VectraNetworksVectra': 410,
    'HPNetworkAutomation': 411,
    'IBMQRadarPacketCapture': 412,
    'MicrosoftAzure': 413,
    'KasperskyThreatFeedService': 414,
    'RemoteAdministrator': 415,
    'IllumioAdaptiveSecurityPlatform': 416,
    'Niara': 418,
    'CiscoCWS': 419,
    'CentrifyIdentityPlatform': 420,
    'IBMSANVolumeController': 421,
    'LightCyberMagna': 422,
    'FasooFED': 423,
    'SAPEnterpriseThreatDetection': 424,
    'ImpervaIncapsula': 425,
    'IBMBigFixEDR': 426,
    'CentrifyServerSuite': 427,
    'CarbonBlackProtection': 428,
    'CiscoStealthwatch': 429,
    'CiscoUmbrella': 431,
    'IBMActivityTracker': 432,
    'MicrosoftWindowsDefenderATP': 433,
    'VMWareAppDefense': 434,
    'CiscoMeraki': 435,
    'AmazonGuardDuty': 436,
    'CiscoAMP': 437,
    'TrendMicroDeepDiscoveryDirector': 438,
    'Nginx': 439,
    'AWSSecurityHub': 440,
    'GoogleGSuite': 442,
    'MicrosoftAzureSecurityCenter': 443,
    'osquery': 444,
    'MicrosoftAzureActiveDirectory': 445,
    'KubernetesAuditing': 446,
    'IBMCloudIdentity': 447,
    'CiscoFirepowerThreatDefense': 448,
    'GoogleCloudAudit': 449,
    'NetgatePfSense': 450,
    'IBMSecurityTrusteer': 451,
    'Office365MessageTrace': 452,
    'IBMDLCMetrics': 453,
    'SysFlowTelemetry': 454,
    'GoogleCloudPlatformFirewall': 455,
    'AmazonAWSNetworkFirewall': 456,
    'TrendApexCentral': 457,
    'Cloudflare': 458,
    'AmazonAWSALBAccessLogs': 460,
    'GoogleCloudDNS': 461,
    'QRadarAppLogger': 500,
    'AmazonAWSWAF': 501,
    'AmazonAWSKubernetes': 502,
    'ZscalerPrivateAccess': 503,
    'RedhatKubernetes': 504,
    'Suricata': 506,
    'AmazonAWSRoute53': 507,
    'CiscoDuo': 508,
    'IBMSecurityReaQta': 512,
    'Microsoft365Defender': 515,
    'AmazonCloudFront': 516,
    'IBMSecurityRandoriRecon': 517,
    'AWSVerifiedAccess': 519,
    'IBMCustomDSM': 4000,
    'IBMQRadarNetworkThreatAnalyticsCustom': 4001,
    'IBMDNSAnalyzer': 4002
}

custom_log_source_mapping = {
    'AzureActiveDirectory': 445,
    'SecurityComplianceCenter': 443,
    'securityhub.amazonaws.com': 440,
    'route53.amazonaws.com': 507,
    'Exchange': 99,
    'cloudtrail.amazonaws.com': 347,
    'guardduty.amazonaws.com': 436,
    'eks.amazonaws.com': 502,
    'elasticache.amazonaws.com': 502,
    's3.amazonaws.com': 347,
}

### Fields
field_mapping = {
    "AccessList": "Rule Name",
    "AccessMask": "Access Mask",
    "Accesses": "Accesses",
    "AppID": "Application",
    "AppId": "Application",
    "AppName": "Application",
    "AttributeLDAPDisplayName": ["Username", "Account Name", "Distinguished Name"],
    "AttributeValue": ["Attribute Old Value", "Attribute New Value"],
    "c-useragent": "User Agent",
    "cs-user-agent": "User Agent",
    "cs-username": "username",
    "CallTrace": "Call Trace",
    "CallerProcessName": "Process Path",
    "cipher": "Ticket Encryption Type",
    "CommandLine": "Command",
    "cs-method": "Method",
    "DestinationHostname": "Destination Hostname",
    "ErrorCode": "Error Code",
    "ExceptionCode": "Error Code",
    "EventID": "Event ID",
    "eventSource": "devicetype",  # Log Source Type - LOGSOURCETYPENAME(devicetype)
    "FailureCode": "Error Code",
    "FileName": "Filename",
    "Filename": "Filename",
    "GrantedAccess": "Granted Access",
    "Hashes": "CONCAT('MD5=', 'MD5 Hash ', 'SHA1=', 'SHA1 Hash ', 'SHA256=', 'SHA256 "
              "Hash ', 'IMPHASH=', 'IMP HASH')",
    # "Hashes": ['MD5 Hash', 'SHA1 Hash', 'SHA256 Hash', 'File Hash'],
    "HostApplication": "Process Path",
    "HostName": "Hostname",
    "Image": ["Process Path", "Process Name"],
    "ImageName": "Process Name",
    "ImagePath": "Process Path",
    "Imphash": "IMP Hash",
    "IntegrityLevel": "Integrity Level",
    "LogonType": "Logon Type",
    "Message": "Message",
    "Name": "File Path",
    "ObjectName": "Object Name",
    "ObjectType": "Object Type",
    "OriginalFileName": "Filename",
    "ParentCommandLine": "Parent Command",
    "ParentImage": "Parent Process Path",
    "ParentProcessId": "Parent Process ID",
    "Path": "File Path",
    "path": "File Path",
    "Payload": "UTF8(payload)",
    "PipeName": "Pipe Name",
    "ProcessId": "Process ID",
    "ProcessName": "Process Name",
    "ProcessPath": "Process Path",
    # "Product": "Product",
    "SamAccountName": "SAM Account Name",
    "Service": "Service Name",
    "ServiceFileName": "Service Filename",
    "ServiceName": "Service Name",
    "ShareName": "Share Name",
    "Signed": "Signed",
    "Status": "Status",
    "StartAddress": "Start Address",
    "TargetFilename": "Filename",
    "TargetImage": "Target Process Path",
    "TargetObject": ["Process Name", "Target Process Name", "Object Name"],
    "TargetUserName": "Target Username",
    "TaskName": "Task Name",
    "TicketEncryptionType": "Ticket Encryption Type",
    "UserName": "username",
    "Username": "username",
    "dst_ip": "username",
    "md5": "MD5 Hash",
    "method": "Method",
    "NewTargetUserName": "Target Username",
    "sha1": "SHA1 Hash",
    "sha256": "SHA256 Hash",
    "SourceImage": "Source Process Path",
    "src_ip": "sourceip",
    "USER": "Username",
    "User": "Username",
    "userAgent": "User Agent",
    "user_agent": "User Agent",

    # Functions
    "eventName": "QIDNAME(qid)",
    "ImageLoaded": "CONCAT('file directory', '/', filename)",
}

host_field_mapping = {
    "DestinationIp": "destinationip",
    "DestPort": "destinationport",
    "DestinationPort": "destinationport",
    "destination.port": "destinationport",
    "dst_port": "destinationport",
    "SourcePort": "sourceport",
}

unstructured_field_mapping = {
    "c-uri": "URL",
    "c-uri-extension": "URL",
    "c-uri-query": "URL",
    "cs-uri": "URL",
    "cs-uri-query": "URL",
    "cs-uri-stem": "URL",
    "properties.message": "Message",
    "ScriptBlockText": "Message",
    "uri": "URL",
}

unstructured_part_field_mapping = {
    "a0": "Command",
    "a1": "Command",
    "a2": "Command",
    "a3": "Command",
    "a4": "Command",
    "a5": "Command",
}

qradar_field_mapping = {
    **field_mapping,
    **host_field_mapping,
    **unstructured_field_mapping,
    **unstructured_part_field_mapping,
}


class HostFieldsValueTransformation(ValueTransformation):
    """
    Converting host fields' values with wildcard to CIDR.
    Supports only 'startswith' operator.
    """

    ipv6_split = ':'
    ipv4_split = '.'

    def create_ip(self, val, default, count, spliter):
        """Creates the IP range of the CIDR"""
        if '::' in val:
            val = str(ipaddress.ip_address(val).exploded)
        ip_octets = [default] * count
        val_octets = val.split(spliter)
        for i in range(count):
            if len(val_octets) > i:
                ip_octets[i] = val_octets[i] or default
        ip = spliter.join(octet for octet in ip_octets)
        return ipaddress.ip_address(ip)

    def CIDR(self, val):
        """Creates IPv4 or IPv6 CIDR"""
        if self.ipv6_split in val or re.search('[a-zA-Z]', val):
            count = 8
            start = '0000'
            end = 'ffff'
            spliter = self.ipv6_split
        else:
            count = 4
            start = '0'
            end = '255'
            spliter = self.ipv4_split
        start_ip = self.create_ip(val, start, count, spliter)
        end_ip = self.create_ip(val, end, count, spliter)
        cidr_expression = list(ipaddress.summarize_address_range(start_ip, end_ip))[0]
        return str(cidr_expression)

    def apply_value(
            self, field: str, val: SigmaType
    ) -> Optional[Union[SigmaType, Iterable[SigmaType]]]:
        if field in host_field_mapping and val.contains_special():
            if val.startswith(SpecialChars.WILDCARD_MULTI):
                operator = (
                    'contains' if val.endswith(SpecialChars.WILDCARD_MULTI)
                    else 'endswith'
                )
                raise SigmaValueError(
                    f"the host field '{field}' does not support '{operator}' "
                    f"operator. please change to 'startswith' or specify an exact"
                    f"match."
                )
            if val.endswith(SpecialChars.WILDCARD_MULTI):
                val = val[:-1]
            try:
                cidr_expression = self.CIDR(str(val))
                return SigmaCIDRExpression(cidr_expression)
            except:
                raise ValueError(f"Value {val} can not be transformed to a valid IPv4 "
                                 f"or IPv6 CIDR expression")
        return None


class UnstructuredFieldsTransformation(DetectionItemTransformation):
    """
    Handles unstructured fields.
    Adds SigmaContainsModifier to detection item with unstructured field,
    lower string values,
    converts the values of unstructured fields which are part of a field to the form
    {field}%{value}.
    """

    def apply_detection_item(
            self, detection_item: SigmaDetectionItem
    ) -> Optional[Union[SigmaDetection, SigmaDetectionItem]]:
        field = detection_item.field
        value = detection_item.value
        if (
                field in unstructured_field_mapping or
                field in unstructured_part_field_mapping or
                field not in qradar_field_mapping
        ):
            if isinstance(value, list):
                if isinstance(value[0], SigmaNumber):
                    value[0] = SigmaString(str(value[0]))
                elif isinstance(value[0], SigmaString):
                    if field in unstructured_part_field_mapping:
                        if value[0].s[0] == SpecialChars.WILDCARD_MULTI:
                            field_value = f'{field}{str(value[0])}'
                        else:
                            field_value = f'{field}%{str(value[0])}'
                        value[0] = SigmaString(field_value.lower())
                    else:
                        value[0] = SigmaString(str(value[0]).lower())
            return SigmaDetectionItem(
                field=field,
                modifiers=[SigmaContainsModifier],
                value=value,
            )
        return detection_item


class QRadarFieldMappingTransformation(FieldMappingTransformation):
    """
    Map a field name to one or multiple different, and quote if the field contains
    spaces and doesn't contain parentheses.
    """

    def apply_field_name(self, field: str) -> Union[str, List[str]]:
        parentheses_and_no_spacing = re.compile(QRadarAQLBackend.field_quote_pattern)
        mappings = copy.deepcopy(self.get_mapping(field)) or []
        if isinstance(mappings, str):
            mappings = [mappings]
        for i, mapping in enumerate(mappings):
            if not parentheses_and_no_spacing.match(mapping):
                mappings[i] = "'" + mapping + "'"
        return mappings


class SetEventSourceTransformation(SetStateTransformation):
    """
    set the logsources values from the field devicetype in state, to use it in the
    backend's finalize query
    """

    def device_type_mapping(
            self, field: str, val: SigmaType
    ) -> Optional[Union[SigmaType, Iterable[SigmaType]]]:
        log_sources = {**qradar_log_source_mapping, **custom_log_source_mapping}
        str_value = str(val)
        if field == "devicetype":
            if str_value in log_sources:
                return log_sources[str_value]
            raise SigmaValueError(
                f"'{val}' is not a supported log source type"
            )
        return None

    def detection_log_sources(self, detection: SigmaDetection, device_types: list):
        for i, detection_item in enumerate(detection.detection_items):
            if isinstance(detection_item,
                          SigmaDetection):  # recurse into nested detection items
                self.detection_log_sources(detection_item, device_types)
            else:
                for value in detection_item.value:
                    res = self.device_type_mapping(detection_item.field, value)
                    if res:
                        if isinstance(res, Iterable) and not isinstance(res, SigmaType):
                            device_types.extend(res)
                        else:
                            device_types.append(res)
                        self.processing_item_applied(detection_item)
        return device_types

    def apply(self, pipeline, rule: SigmaRule) -> None:
        device_types = []
        for detection in rule.detection.detections.values():
            log_source = self.detection_log_sources(detection, device_types) or []
            device_types.extend(log_source)
        self.val = device_types
        super().apply(pipeline, rule)


class SetTableTransformation(SetStateTransformation):
    """set the table name in state, to use it in the backend's finalize query"""

    def apply(self, pipeline, rule: SigmaRule) -> None:
        is_flow = (
                rule.logsource.product == "qflow" or
                rule.logsource.product == "ipfix" or
                rule.logsource.service == "netflow" or
                rule.logsource.category == "flow"
        )
        self.val = "flows" if is_flow else "events"
        super().apply(pipeline, rule)


base_pipeline_items = [
    ProcessingItem(
        identifier="host_fields_value",
        transformation=HostFieldsValueTransformation(),
    ),
    ProcessingItem(
        identifier="unstructured_fields",
        transformation=UnstructuredFieldsTransformation(),
    ),
    ProcessingItem(
        identifier="qradar_fields",
        transformation=QRadarFieldMappingTransformation(
            qradar_field_mapping
        ),
    ),
    ProcessingItem(
        identifier="set_log_source_type",
        field_name_conditions=[IncludeFieldCondition(['devicetype'])],
        transformation=SetEventSourceTransformation("device_types", []),
    ),
    ProcessingItem(
        identifier="drop_field_log_source_type",
        field_name_conditions=[IncludeFieldCondition(['devicetype'])],
        detection_item_conditions=[
            DetectionItemProcessingItemAppliedCondition('set_log_source_type')],
        transformation=DropDetectionItemTransformation(),
    ),
    ProcessingItem(
        identifier="qradar_table",
        transformation=SetTableTransformation('table', None),
    ),
]
