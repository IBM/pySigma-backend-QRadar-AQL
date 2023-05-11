from .QRadarAQL_payload import QRadarAQL_payload_pipeline
from .QRadarAQL_fields import QRadarAQL_fields_pipeline


pipelines = {
    "QRadarAQL_payload": QRadarAQL_payload_pipeline,
    "QRadarAQL_fields": QRadarAQL_fields_pipeline,
}
