from sigma.pipelines.QRadarAQL.QRadarAQL import QRadarAQL_payload_pipeline, \
    QRadarAQL_fields_pipeline

pipelines = {
    "qradar-aql-payload": QRadarAQL_payload_pipeline,
    "qradar-aql-fields": QRadarAQL_fields_pipeline,
}
