import re

from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError, SigmaValueError
from sigma.rule import SigmaRule
from sigma.conversion.base import TextQueryBackend
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT, \
    ConditionValueExpression, \
    ConditionFieldEqualsValueExpression
from sigma.types import SigmaCompareExpression, SigmaString, SpecialChars
from typing import ClassVar, Dict, Tuple, Any, Union, Pattern


def number_as_string(value):
    number_string: ClassVar[Pattern] = re.compile("^[0-9%']*$")
    return number_string.match(value)


class QRadarAQLBackend(TextQueryBackend):
    """QRadar backend."""
    # See the pySigma documentation for further infromation:
    # https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html

    table = 'events'

    service_devicetype = {
        "aaa": [143],
        "apache": [10],
        "auditd": [11],  # LinuxServer
        "auth": [12],  # Microsoft Windows auth
        "clamav": [11],  # LinuxServer
        "cloudtrail": [347],
        "cron": [11],  # LinuxServer
        "exchange": [99],
        "gcp.audit": [449],  # GoogleCloudAudit
        "iis": [13],
        "ldp": [17],
        "lsa-server": [191],
        "microsoft365portal": [
            397,  # Office365
            452,  # Office365MessageTrace
            515,  # Microsoft365Defender
        ],
        "okta": [382],
        "powershell": [12],  # Microsoft Windows
        "rdp": [
            11,  # LinuxServer
            12,  # Microsoft Windows
        ],
        "smbclient-security": [
            11,  # LinuxServer
            12,  # Microsoft Windows
        ],
        "sshd": [11],  # LinuxServer
        "sudo": [11],  # LinuxServer
        "syslog": [
            11,  # LinuxServer
            12,  # Microsoft Windows
        ],
        "sysmon": [12],  # Microsoft Windows
        "taskscheduler": [
            11,  # LinuxServer
            12,  # Microsoft Windows
        ],
        "threat_detection": [424],
        "windefend": [433],
        "wmi": [12],  # Microsoft Windows
    }

    product_devicetype = {
        "aws": [
            347,  # AmazonAWSCloudTrail
            440,  # AWS Security Hub
            456,  # AmazonAWSNetworkFirewall,
            460,  # AmazonAWSALBAccess Logs
            501,  # AmazonAWSWAF
            502,  # AmazonAWSKubernetes
            507,  # AmazonRoute53
            516,  # AmazonAWSCloudFront
            519,  # AWSVerifiedAccess
        ],
        "MicrosoftAzure": [413],
        "cisco": [
            6,  # Pix
            20,  # IOC
            23,  # VpnConcentrator
            26,  # CSA
            30,  # IDS
            31,  # FWSM
            41,  # ASA
            56,  # CiscoCatOS
            90,  # Cisco ACS
            94,  # Cisco CSA-syslog
            95,  # Cisco NAC
            113,  # Cisco 12000 Series Routers
            114,  # Cisco 6500 Series Switches
            115,  # Cisco 7600 Series Routers
            116,  # Cisco Carrier Routing System
            117,  # Cisco Integrated Services Router
            179,  # Cisco IronPort
            182,  # Aironet
            183,  # Wism
            194,  # ACE
            248,  # CiscoWirelessNCS
            250,  # CiscoNexus
            273,  # CiscoWLC
            274,  # CiscoCallManager
            316,  # CiscoISE
            419,  # CiscoCWS
            429,  # CiscoStealthwatch
            431,  # CiscoUmbrella
            435,  # CiscoMeraki
            437,  # CiscoAMP
            448,  # CiscoFirepowerThreatDefense
            508,  # CiscoDuo
        ],
        "gcp": [
            442,  # GoogleGSuite
            449,  # GoogleCloudAudit
            455,  # GoogleCloudPlatformFirewall
            461,  # GoogleCloudDNS
        ],
        "huawei": [
            269,  # HuaweiSSeriesSwitch
            283,  # ARSeriesRouter
        ],
        "juniper": [
            5,  # NetScreenFirewall
            17,  # NetScreenIDP
            36,  # JuniperSA
            45,  # NetscreenNSM
            59,  # InfranetController
            64,  # JuniperRouter
            83,  # JuniperSBR
            111,  # JuniperDX
            118,  # Juniper M Series
            122,  # Juniper MX Series
            123,  # Juniper T Series
            139,  # Juniper EX Series
            150,  # JuniperSRX
            168,  # Juniper
            192,  # SRC
            235,  # JuniperAltorVGW
            264,  # JuniperBinary
            290,  # JuniperMykonosWebSecurity
            320,  # JuniperWLAN
            344,  # JuniperDDosSecure
        ],
        "linux": [11],
        "m365": [397],
        "macos": [102],
        "okta": [382],
        "sql": [101],
        "windows": [12]
    }

    name: ClassVar[str] = "QRadar backend"
    formats: Dict[str, str] = {
        "default": "Plain QRadar queries",
    }
    requires_pipeline: bool = True  # does the backend requires that a processing
    # pipeline is provided? This information can be used by user interface programs
    # like Sigma CLI to warn users about inappropriate usage of the backend.

    precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (
        ConditionNOT, ConditionAND, ConditionOR)
    group_expression: ClassVar[
        str] = "({expr})"  # precedence override grouping as format string

    # Generated query tokens
    token_separator: str = " "  # separator inserted between all boolean operators
    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = "AND"
    not_token: ClassVar[str] = "NOT"
    eq_token: ClassVar[
        str] = "="  # Token inserted between field and value (without separator)

    # String output
    ## Fields
    ### Quoting

    field_quote: ClassVar[
        str] = "'"  # Character used to quote field characters if field_quote_pattern
    # doesn't match
    field_quote_pattern: ClassVar[Pattern] = re.compile(
        "^\S+$|.*\([^()]*\).*")  # Quote field names if this pattern
    # doesn't match- contains spacing or doesn't contain parentheses
    field_quote_pattern_negation: ClassVar[
        bool] = True  # Negate field_quote_pattern result. Field name is quoted if
    # pattern doesn't match if set to True

    ## Values
    str_quote: ClassVar[
        str] = "'"  # string quoting character (added as escaping character)
    escape_char: ClassVar[
        str] = "'"  # Escaping character for special characrers inside string
    wildcard_multi: ClassVar[str] = "%"  # Character used as multi-character wildcard
    wildcard_single: ClassVar[str] = "_"  # Character used as single-character wildcard
    add_escaped: ClassVar[
        str] = "'"  # Characters quoted in addition to wildcards and string quote
    filter_chars: ClassVar[str] = ""  # Characters filtered
    bool_values: ClassVar[Dict[bool, str]] = {
        # Values to which boolean values are mapped.
        True: "true",
        False: "false",
    }

    # Special expression if wildcards can't be matched with the eq_token operator
    wildcard_match_str_expression: ClassVar[
        str] = "LOWER({field}) LIKE {value}"
    wildcard_match_num_expression: ClassVar[
        str] = "{field} LIKE {value}"

    # Regular expressions
    re_expression: ClassVar[str] = "{field} MATCHES '{regex}'"  # Regular
    # expression query as format string
    re_escape_char: ClassVar[
        str] = "'"  # Character used for escaping in regular expressions
    re_escape: ClassVar[Tuple[str]] = ("'",)  # List of strings that are escaped
    re_escape_escape_char: bool = True  # If True, the escape character is also escaped

    # cidr expressions
    cidr_wildcard: ClassVar[str] = "_"  # Character used as single wildcard
    cidr_expression: ClassVar[
        str] = "INCIDR('{value}', {field})"  # CIDR expression query as format string
    cidr_in_list_expression: ClassVar[
        str] = "{field} IN({value})"  # CIDR expression query as format string

    # Numeric comparison operators
    compare_op_expression: ClassVar[
        str] = "{field} {operator} {value}"  # Compare operation query as format string
    # Mapping between CompareOperators elements and strings used as replacement for
    # {operator} in compare_op_expression
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    # Null/None expressions
    field_null_expression: ClassVar[
        str] = "{field} IS NULL"  # Expression for field has null value as format string

    # Field value in list,
    # e.g. "field in (value list)" or "field containsall (value list)"
    convert_or_as_in: ClassVar[bool] = True  # Convert OR as in-expression
    convert_and_as_in: ClassVar[bool] = False  # Convert AND as in-expression
    in_expressions_allow_wildcards: ClassVar[bool] = False  # Only plain values are
    # converted into in-expression

    field_in_list_expression: ClassVar[
        str] = "{field} {op}({list})"  # Expression for field in list of values as
    # format string
    or_in_operator: ClassVar[
        str] = "IN"  # Operator used to convert OR into in-expressions. Must be set
    # if convert_or_as_in is set
    # and_in_operator: ClassVar[
    list_separator: ClassVar[str] = ", "  # List element separator

    # Value not bound to a field
    events_unbound_value_str_expression: ClassVar[
        str] = "LOWER(UTF8(payload)) LIKE {value}"  # string value not bound to a
    # field format
    events_unbound_value_num_expression: ClassVar[
        str] = "UTF8(payload) LIKE {value}"  # num value not bound to a field format
    events_unbound_value_re_expression: ClassVar[
        str] = "UTF8(payload) MATCHES {value}"  # re value not bound to a field format
    flows_unbound_value_str_expression: ClassVar[str] = (
        "LOWER(UTF8(sourcepayload)) LIKE {value} OR"
        "LOWER(UTF8(destinationpayload)) LIKE {value}"
    )
    flows_unbound_value_num_expression: ClassVar[str] = (
        "UTF8(sourcepayload) LIKE {value} OR UTF8(destinationpayload) LIKE {value}"
    )
    flows_unbound_value_re_expression: ClassVar[str] = (
        "UTF8(sourcepayload) LIKE {value} OR UTF8(destinationpayload) MATCHES {value}"
    )

    # Query finalization: appending and concatenating deferred query part
    deferred_start: ClassVar[
        str] = ""  # String used as separator between main query and deferred parts
    deferred_separator: ClassVar[
        str] = ""  # String used to join multiple deferred query parts
    deferred_only_query: ClassVar[
        str] = ""  # String used as query if final query only contains deferred
    # expression

    # implement custom methods for query elements not covered by the default backend base
    # Documentation: https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html

    def convert_value_str(self, s: SigmaString, state: ConversionState) -> str:
        """
        Convert a SigmaString into a plain string which can be used in query.
        Escape only chars in self.add_escaped
        """
        converted = ""
        escaped_chars = self.add_escaped

        for c in s:
            if isinstance(c, str):  # c is plain character
                if c in self.filter_chars:  # Skip filtered characters
                    continue
                if c in escaped_chars:
                    converted += self.escape_char
                converted += c
            else:  # special handling for special characters
                if c == SpecialChars.WILDCARD_MULTI:
                    if self.wildcard_multi is not None:
                        converted += self.wildcard_multi
                    else:
                        raise SigmaValueError(
                            "Multi-character wildcard not specified for conversion")
                elif c == SpecialChars.WILDCARD_SINGLE:
                    if self.wildcard_single is not None:
                        converted += self.wildcard_single
                    else:
                        raise SigmaValueError(
                            "Single-character wildcard not specified for conversion")

        if self.decide_string_quoting(s):
            return self.quote_string(converted)
        else:
            return converted

    def convert_condition_as_in_expression(
            self, cond: Union[ConditionOR, ConditionAND], state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field in value list conditions:
        adding quote to numeric values"""
        return self.field_in_list_expression.format(
            field=self.escape_and_quote_field(cond.args[0].field),
            op=self.or_in_operator if isinstance(
                cond, ConditionOR) else self.and_in_operator,
            list=self.list_separator.join([
                self.convert_value_str(arg.value, state)
                if isinstance(arg.value, SigmaString)  # string escaping and quoting
                else f"'{arg.value}'"  # value is number
                for arg in cond.args
            ]),
        )

    def convert_condition_val_str(
            self, cond: ConditionValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of value-only strings:
        the unbound value expression depends on the table name and the value type-
        string is wrapped with 'LOWER' for using 'LIKE' instead of 'ILIKE' for better
        performance"""
        table = state.processing_state.get('table', self.table)
        value = self.convert_value_str(cond.value, state)
        if number_as_string(value):
            return self.__getattribute__(
                table + "_unbound_value_num_expression").format(
                value=value)
        return self.__getattribute__(
            table + "_unbound_value_str_expression").format(
            value=value.lower())

    def convert_condition_val_num(
            self, cond: ConditionValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of value-only numbers:
        the unbound value expression depends on the table name"""
        table = state.processing_state.get('table', self.table)
        return self.__getattribute__(
            table + "_unbound_value_num_expression").format(
            value=cond.value)

    def convert_condition_val_re(
            self, cond: ConditionValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of value-only regular expressions:
        the unbound value expression depends on the table name"""
        table = state.processing_state.get('table', self.table)
        return self.__getattribute__(
            table + "_unbound_value_re_expression").format(
            value=self.convert_value_re(cond.value, state))

    def convert_condition_not(
            self, cond: ConditionNOT, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of NOT conditions:
        create 'NOT()' function"""
        arg = cond.args[0]
        try:
            if arg.__class__ in self.precedence:  # group if AND, OR condition negated
                return self.not_token + '(' + self.convert_condition_group(arg,
                                                                           state) + ')'
            else:
                expr = self.convert_condition(arg, state)
                if isinstance(expr, DeferredQueryExpression):  # negate deferred
                    # expression and pass it to parent
                    return expr.negate()
                else:  # convert negated expression to string
                    return self.not_token + '(' + expr + ')'
        except TypeError:  # pragma: no cover
            raise SigmaFeatureNotSupportedByBackendError(
                "Operator 'not' not supported by the backend")

    def convert_condition_field_eq_val_str(
            self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = string value expressions:
        for string contains wildcard convert to wildcard match expression and lower
        string value"""
        field = cond.field
        if (  # wildcard match expression: string contains wildcard
                cond.value.contains_special()
        ):
            value = self.convert_value_str(cond.value, state)
            if number_as_string(value):
                expr = self.wildcard_match_num_expression
                value = value
            else:
                expr = self.wildcard_match_str_expression
            return expr.format(field=self.escape_and_quote_field(field),
                               value=value.lower())
        return super().convert_condition_field_eq_val_str(cond, state)

    def device_type_expression(self, rule, device_types):
        """Creates an expression to match the rule's log source:
       using 'devicetype' field instead of 'LOGSOURCETYPENAME()' function for better
       performance"""
        device_type = ''
        log_sources_devicetype = set(
            (self.product_devicetype.get(rule.logsource.product, []) +
             self.service_devicetype.get(rule.logsource.service, [])) +
            device_types)
        if len(log_sources_devicetype) == 1:
            device_type = f'devicetype={next(iter(log_sources_devicetype))}'
        elif len(log_sources_devicetype) > 1:
            device_type = self.field_in_list_expression.format(
                field="devicetype",
                op=self.or_in_operator,
                list=self.list_separator.join(
                    [str(log_source) for log_source in log_sources_devicetype]),
            )
        return f'{device_type} {self.and_token} ' if device_type else device_type

    def finalize_query_default(self, rule: SigmaRule, query: str, index: int,
                               state: ConversionState) -> Any:
        table = state.processing_state.get('table', self.table)
        device_types = state.processing_state.get('device_types', [])
        fields = "*" if len(rule.fields) == 0 else f"*, {', '.join(rule.fields)}"
        match_device_type = self.device_type_expression(
            rule=rule, device_types=device_types
        )
        qradar_query = f'SELECT {fields} FROM {table} WHERE {match_device_type}{query}'
        return qradar_query
