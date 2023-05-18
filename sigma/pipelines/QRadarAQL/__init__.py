from .QRadarAQL_payload import QRadarAQL_payload_pipeline
from .QRadarAQL_fields import QRadarAQL_fields_pipeline


pipelines = {
    "qradar-aql-payload": QRadarAQL_payload_pipeline,
    "qradar-aql-fields": QRadarAQL_fields_pipeline,
}
