import warnings

import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaTransformationError

from sigma.backends.QRadarAQL import QRadarAQLBackend
from sigma.pipelines.QRadarAQL.QRadarAQL import QRadarAQL_payload_pipeline


def test_QRadar_field_with_spaces():
    assert QRadarAQLBackend(QRadarAQL_payload_pipeline()).convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    EventID:
                        - value
                condition: sel
            fields:
                - EventID
        """)
    ) == [
               'SELECT *, "Event ID" FROM events WHERE "Event ID"=\'value\''
           ]


def test_QRadar_field_with_parentheses():
    assert QRadarAQLBackend(QRadarAQL_payload_pipeline()).convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    ImageLoaded:
                        - value
                condition: sel
            fields:
                - ImageLoaded
        """)
    ) == [
               "SELECT *, CONCAT('file directory', '/', filename) FROM events WHERE "
               "CONCAT('file directory', '/', filename)='value'"
           ]


def test_QRadar_in_expression_with_int_value():
    assert QRadarAQLBackend(QRadarAQL_payload_pipeline()).convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    EventID:
                        - 1
                        - 2
                condition: sel
            fields:
                - EventID
        """)
    ) == [
               'SELECT *, "Event ID" FROM events WHERE "Event ID" IN(\'1\', \'2\')'
           ]


def test_QRadar_in_expression_field_name_not_in_mapping_query():
    assert QRadarAQLBackend(QRadarAQL_payload_pipeline()).convert(
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
    ) == [
        "SELECT * FROM events WHERE LOWER(UTF8(payload)) LIKE '%valuea%' OR LOWER(UTF8("
        "payload)) LIKE '%valueb%' OR LOWER(UTF8(payload)) LIKE '%valuec%'"
    ]


def test_QRadar_regex_field_name_not_in_mapping_query():
    with pytest.raises(SigmaTransformationError):
        assert QRadarAQLBackend(QRadarAQL_payload_pipeline()).convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        fieldName|re: foo.*bar
                    condition: sel
            """)
        )


def test_QRadar_cidr_field_name_not_in_mapping_query():
    with pytest.raises(SigmaTransformationError):
        assert QRadarAQLBackend(QRadarAQL_payload_pipeline()).convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        fieldName|cidr: 192.168.0.0/16
                    condition: sel
            """)
        )


def test_QRadar_field_name_not_in_mapping_bool_value():
    with pytest.raises(SigmaTransformationError):
        assert QRadarAQLBackend(QRadarAQL_payload_pipeline()).convert(
            SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldName: 'true'
                condition: sel
        """)
        )


def test_QRadar_field_name_not_in_mapping_null_value():
    with pytest.raises(SigmaTransformationError):
        QRadarAQLBackend(QRadarAQL_payload_pipeline()).convert(
            SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldName: null
                condition: sel
        """)
        )


def test_QRadar_field_name_not_in_mapping_empty_value():
    with pytest.raises(SigmaTransformationError):
        QRadarAQLBackend(QRadarAQL_payload_pipeline()).convert(
            SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldName: ''
                condition: sel
        """)
        )


def test_QRadar_field_name_not_in_mapping_str_value():
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        assert QRadarAQLBackend(QRadarAQL_payload_pipeline()).convert(
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
        ) == [
                   "SELECT * FROM events WHERE LOWER(UTF8(payload)) LIKE '%value%'"
               ]
        assert len(w) == 1
        warn = w[0]
        assert issubclass(warn.category, UserWarning)
        assert "payload search" in str(warn.message)


def test_QRadar_field_name_not_in_mapping_num_value():
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        assert QRadarAQLBackend(QRadarAQL_payload_pipeline()).convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        fieldName: 1
                    condition: sel
            """)
        ) == [
                   "SELECT * FROM events WHERE LOWER(UTF8(payload)) LIKE "
                   "'%fieldname%1%'"
               ]
        assert len(w) == 2
        number_warn, payload_warn = w
        assert issubclass(payload_warn.category, UserWarning)
        assert issubclass(number_warn.category, UserWarning)
        assert "payload search" in str(payload_warn.message)
        assert "numeric" in str(number_warn.message)


def test_QRadar_keywords_query():
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        assert QRadarAQLBackend(QRadarAQL_payload_pipeline()).convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    keywords:
                        - keyword1
                        - keyword2
                        - keyword3
                    condition: keywords
            """)
        ) == [
                   "SELECT * FROM events WHERE LOWER(UTF8(payload)) LIKE '%keyword1%' "
                   "OR LOWER(UTF8(payload)) LIKE '%keyword2%' OR LOWER(UTF8(payload)) "
                   "LIKE '%keyword3%'"
               ]
        assert len(w) == 1
        for warn in w:
            assert issubclass(warn.category, UserWarning)
            assert "payload search" in str(warn.message)


def test_QRadar_num_as_string_value():
    assert QRadarAQLBackend(QRadarAQL_payload_pipeline()).convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldName: '1'
                condition: sel
        """)
    ) == [
               "SELECT * FROM events WHERE LOWER(UTF8(payload)) LIKE '%fieldname%1%'"
           ]

def test_QRadar_all_modifier():
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

