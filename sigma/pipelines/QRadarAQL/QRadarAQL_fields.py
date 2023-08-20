from dataclasses import dataclass

from sigma.exceptions import SigmaTransformationError
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import DetectionItemFailureTransformation
from sigma.rule import SigmaDetectionItem

from sigma.pipelines.QRadarAQL.QRadarAQL import qradar_field_mapping, \
    base_pipeline_items


@dataclass
class FieldMappingFailureTransformation(DetectionItemFailureTransformation):
    """
    Raise a SigmaTransformationError with the provided message for unsupported fields.
    The supported field are the fields in 'qradar_field_mapping' and can be found on
    'sigma.pipelines.QRadar.QRadar'
    """
    field_mapping: dict

    def apply_detection_item(self, detection_item: SigmaDetectionItem) -> None:
        field = detection_item.field
        if field not in self.field_mapping:
            raise SigmaTransformationError(self.message.format(field=field))


def QRadarAQL_fields_pipeline() -> ProcessingPipeline:
    """
    Pipeline supporting only fields that can be mapped
    """
    processing_pipeline = ProcessingPipeline(
        name="Qradar AQL",
        priority=20,
        items=[
                  ProcessingItem(
                      identifier="QRadar_unsupported_fields",
                      transformation=FieldMappingFailureTransformation(
                          message="field '{field}' is not supported",
                          field_mapping=qradar_field_mapping,
                      ),
                  ),
              ] + base_pipeline_items
    )
    return processing_pipeline
