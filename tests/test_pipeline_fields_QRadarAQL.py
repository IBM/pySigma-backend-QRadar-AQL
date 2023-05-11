import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaTransformationError

from sigma.backends.QRadarAQL import QRadarAQLBackend
from sigma.pipelines.QRadarAQL import QRadarAQL_fields_pipeline


def test_QRadar_in_expression_field_name_not_in_mapping_query_exception():
    with pytest.raises(SigmaTransformationError):
        QRadarAQLBackend(QRadarAQL_fields_pipeline()).convert(
            SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldName:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """)
        )


def test_QRadar_field_name_not_in_mapping_str_value_exception():
    with pytest.raises(SigmaTransformationError):
        assert QRadarAQLBackend(QRadarAQL_fields_pipeline()).convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        fieldName: value
                    condition: sel
            """)
        )
