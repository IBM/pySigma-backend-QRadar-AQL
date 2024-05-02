import pytest
from sigma.collection import SigmaCollection

from sigma.backends.QRadarAQL import QRadarAQLBackend
from sigma.pipelines.QRadarAQL.QRadarAQL import QRadarAQL_payload_pipeline


@pytest.fixture
def aql_backend():
    return QRadarAQLBackend()


def test_QRadar_all_modifier(aql_backend: QRadarAQLBackend):
    assert QRadarAQLBackend(QRadarAQL_payload_pipeline()).convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    commandline|contains|all:
                        - 'test 1'
                        - 'test 2'
                condition: sel
        """)
    ) == [
                "SELECT * FROM events WHERE LOWER(UTF8(payload)) LIKE '%test 1%' AND LOWER(UTF8(payload)) LIKE '%test 2%'"
         ]

