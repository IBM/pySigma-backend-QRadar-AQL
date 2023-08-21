from sigma.pySigma_QRadar_base.generate_readme_mapping import generate_mapping
from sigma.mapping.fields import aql_field_mapping
from sigma.mapping.logsources import aql_log_source_mapping
from sigma.mapping.products import aql_product_mapping
from sigma.mapping.services import aql_service_mapping


AQL = {
    "log_source_name": "QRadar AQL device type",
    "fields": aql_field_mapping,
    "log_sources": aql_log_source_mapping,
    "product": aql_product_mapping,
    "service": aql_service_mapping
}


if __name__ == '__main__':
    generate_mapping(AQL)
