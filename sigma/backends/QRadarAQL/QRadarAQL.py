import re

from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.exceptions import SigmaValueError
from sigma.rule import SigmaRule
from sigma.conditions import ConditionAND, ConditionOR, ConditionValueExpression, \
    ConditionFieldEqualsValueExpression
from sigma.types import SigmaString, SpecialChars
from typing import ClassVar, Tuple, Any, Union, Pattern

from sigma.mapping.products import aql_product_mapping
from sigma.mapping.services import aql_service_mapping
from sigma.pySigma_QRadar_base.QRadarBackend import QRadarBackend, number_as_string


class QRadarAQLBackend(QRadarBackend):
    """QRadar backend."""
    # See the pySigma documentation for further infromation:
    # https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html

    service_devicetype = aql_service_mapping
    product_devicetype = aql_product_mapping

    table = 'events'

    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = "AND"
    not_token: ClassVar[str] = "NOT"

    eq_token: ClassVar[
        str] = "="  # Token inserted between field and value (without separator)

    # String output
    ## Fields
    ### Quoting

    field_quote_pattern: ClassVar[Pattern] = re.compile(
        "^\S+$|.*\([^()]*\).*")  # Quote field names if this pattern
    # doesn't match- contains spacing or doesn't contain parentheses

    ## Values
    wildcard_multi: ClassVar[str] = "%"  # Character used as multi-character wildcard
    wildcard_single: ClassVar[str] = "_"  # Character used as single-character wildcard
    add_escaped: ClassVar[
        str] = "'"  # Characters quoted in addition to wildcards and string quote

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

    # Null/None expressions
    field_null_expression: ClassVar[
        str] = "{field} IS NULL"  # Expression for field has null value as format string

    # Field value in list,
    # e.g. "field in (value list)" or "field containsall (value list)"
    convert_and_as_in: ClassVar[bool] = False  # Convert AND as in-expression
    in_expressions_allow_wildcards: ClassVar[bool] = False  # Only plain values are
    # converted into in-expression

    field_in_list_expression: ClassVar[
        str] = "{field} {op}({list})"  # Expression for field in list of values as
    # format string
    or_in_operator: ClassVar[
        str] = "IN"  # Operator used to convert OR into in-expressions. Must be set
    device_type_or_in_operator: ClassVar[
        str] = "IN"  # Operator used to convert OR into in-expressions. Must be set
    # if convert_or_as_in is set

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

    def finalize_query_default(self, rule: SigmaRule, query: str, index: int,
                               state: ConversionState) -> Any:
        table = state.processing_state.get('table', self.table)
        fields = "*" if len(rule.fields) == 0 else f"*, {', '.join(rule.fields)}"
        device_types = state.processing_state.get('device_types', [])
        match_device_type = self.device_type_expression(
            rule=rule, device_type_field_name='devicetype', device_types=device_types
        )
        query = (
            f'({query})' if self.use_parenthesis(match_device_type, query) else query
        )
        full_query = match_device_type.format(query=query)
        qradar_query = f'SELECT {fields} FROM {table} WHERE {full_query}'
        return qradar_query
