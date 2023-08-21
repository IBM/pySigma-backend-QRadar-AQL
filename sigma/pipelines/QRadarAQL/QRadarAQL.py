import ipaddress
from typing import Optional, Union, Iterable

from sigma.exceptions import SigmaValueError
from sigma.modifiers import SigmaContainsModifier
from sigma.processing.conditions import IncludeFieldCondition, \
    DetectionItemProcessingItemAppliedCondition
from sigma.processing.pipeline import ProcessingPipeline
from sigma.processing.transformations import ValueTransformation, DetectionItemTransformation, SetStateTransformation, \
    DropDetectionItemTransformation
from sigma.processing.pipeline import ProcessingItem

# See https://sigmahq-pysigma.readthedocs.io/en/latest/Processing_Pipelines.html
# for further documentation.
from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaRule
from sigma.types import SigmaType, SigmaNumber, SigmaString, SigmaCIDRExpression, \
    SpecialChars

from sigma.backends.QRadarAQL import QRadarAQLBackend
from sigma.mapping.fields import host_field_mapping, \
    unstructured_field_mapping, unstructured_part_field_mapping, aql_field_mapping
from sigma.mapping.logsources import aql_log_source_mapping
from sigma.pySigma_QRadar_base.QRadarPipeline import SetEventSourceTransformation, \
    QRadarFieldMappingTransformation, ip_type, IPV6, IPV4
from sigma.pySigma_QRadar_base.QRadarFieldsPipeline import QRadar_fields_pipeline
from sigma.pySigma_QRadar_base.QRadarPayloadPipeline import QRadar_payload_pipeline


def create_ip(val, default, count, spliter):
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


class HostFieldsValueTransformation(ValueTransformation):
    """
    Converting host fields' values with wildcard to CIDR.
    Supports only 'startswith' operator.
    """

    ipv6_split = ':'
    ipv4_split = '.'

    def CIDR(self, val):
        """Creates IPv4 or IPv6 CIDR"""
        ip = ip_type(val)
        if ip == IPV6:
            count = 8
            start = '0000'
            end = 'ffff'
            spliter = self.ipv6_split
        elif ip == IPV4:
            count = 4
            start = '0'
            end = '255'
            spliter = self.ipv4_split
        else:
            return None
        start_ip = create_ip(val, start, count, spliter)
        end_ip = create_ip(val, end, count, spliter)
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
            except Exception as e:
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
                field not in aql_field_mapping
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
        identifier="aql_field_mapping",
        transformation=QRadarFieldMappingTransformation(
            mapping=aql_field_mapping,
            field_quote_pattern=QRadarAQLBackend.field_quote_pattern
        ),
    ),
    ProcessingItem(
        identifier="set_log_source_type",
        field_name_conditions=[IncludeFieldCondition(['devicetype'])],
        transformation=SetEventSourceTransformation(
            key="device_types", val=[], device_type_field_name='devicetype',
            log_source_mapping=aql_log_source_mapping
        ),
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


def QRadarAQL_fields_pipeline() -> ProcessingPipeline:
    """
    Pipeline supporting only fields that can be mapped
    """
    return QRadar_fields_pipeline(
        base_pipeline_items=base_pipeline_items,
        field_mapping=aql_field_mapping
    )


def QRadarAQL_payload_pipeline() -> ProcessingPipeline:
    """
    Pipeline supporting all fields, and converting unmapped fields to 'UTF8(payload)'
    """
    return QRadar_payload_pipeline(
        base_pipeline_items=base_pipeline_items,
        field_mapping=aql_field_mapping,
        number_value_format='{field}%{str_val}'
    )
