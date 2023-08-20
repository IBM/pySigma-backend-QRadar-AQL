import re
import warnings
from dataclasses import dataclass
from typing import Union, Optional

from sigma.exceptions import SigmaTransformationError
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import DetectionItemTransformation, \
    DetectionItemFailureTransformation
from sigma.rule import SigmaDetectionItem, SigmaDetection
from sigma.types import SigmaRegularExpression, SigmaNull, SigmaCompareExpression, \
    SigmaNumber, SigmaString, SigmaBool, SigmaCIDRExpression, SigmaExpansion

# from sigma.backends.QRadarAQL.QRadarAQL import number_as_string
from sigma.pipelines.QRadarAQL.QRadarAQL import qradar_field_mapping, base_pipeline_items


def number_as_string(value):
    number_string = re.compile("^[0-9%']*$")
    return number_string.match(value)


class ValueTypeFailureTransformation(DetectionItemFailureTransformation):
    """
    Raise a SigmaTransformationError with the provided message for unsupported value
    types when using payload.
    The supported value types are 'Boolean', 'Regular expression', 'CIDR', 'Null'.

    Raise a warning with a message for 'Numeric' value when using payload.
    """
    message: str

    def apply_detection_item(self, detection_item: SigmaDetectionItem) -> None:
        value_type = ""
        field = detection_item.field
        value = detection_item.value
        if field not in qradar_field_mapping:
            if isinstance(value, SigmaCompareExpression):
                value_type = "Numeric comparison operation"
            elif isinstance(value, list):
                for i, val in enumerate(value):
                    str_val = str(val)
                    if isinstance(val, SigmaNull) or not val:
                        value_type = "Null value"
                    # SigmaContainsModifier incompatible to number values
                    elif isinstance(val, SigmaNumber) or number_as_string(str_val):
                        if not field:
                            number_value = SigmaString(str_val)
                            warnings.warn(
                                f"Using numeric value as keyword might cause "
                                f"false positives, please specify the keyword value "
                                f"to a field"
                            )
                        else:
                            number_value = SigmaString(f'{field}%{str_val}')
                            warnings.warn(
                                f"Using numeric value for unsupported field might "
                                f"cause partial results, please use a supported field "
                                f"instead of '{field}'"
                            )
                        detection_item.value[i] = number_value
                    elif isinstance(val, SigmaBool) or (
                            isinstance(val, SigmaString) and
                            val in ['true', 'false']
                    ):
                        value_type = "Boolean value"
                    elif isinstance(val, SigmaRegularExpression):
                        value_type = "Regular expression value"
                    elif isinstance(val, SigmaCIDRExpression):
                        value_type = "CIDR expression"
            if value_type:
                raise SigmaTransformationError(
                    self.message.format(value_type=value_type, field=field))


@dataclass
class UnsupportedFieldsTransformation(DetectionItemTransformation):
    """
    Drop unsupported field to create unbound value expression using UTF8(payload).
    Raise a warning about performance issues.
    """

    field_mapping: dict = None

    def apply_detection_item(
            self, detection_item: SigmaDetectionItem
    ) -> Optional[Union[SigmaDetection, SigmaDetectionItem]]:
        field = detection_item.field
        value = detection_item.value
        if field not in self.field_mapping:
            improve = (f"use a supported field instead of '{field}'" if field else
                       "specify the keyword value to a field")
            warnings.warn(
                f"Using 'UTF8(payload)' might cause performance issues, "
                f"please {improve}"
            )
            if field:
                if isinstance(value, list) and isinstance(value[0], SigmaExpansion):
                    # SigmaExpansion value has to have a field
                    detection_item.field = 'Payload'
                else:
                    detection_item.field = None
        return detection_item


def QRadarAQL_payload_pipeline() -> ProcessingPipeline:
    """
    Pipeline supporting all fields, and converting unmapped fields to 'UTF8(payload)'
    """
    return ProcessingPipeline(
        name="QRadar AQL",
        priority=20,
        items=[
                  ProcessingItem(
                      identifier="unsupported_value_types_for_unsupported_fields",
                      transformation=ValueTypeFailureTransformation(
                          "{value_type} is not supported "
                          "for the unsupported field '{field}'"),
                  ),
                  ProcessingItem(
                      identifier="using_payload_for_unsupported_fields",
                      transformation=UnsupportedFieldsTransformation(),
                  ),
              ] + base_pipeline_items
    )
