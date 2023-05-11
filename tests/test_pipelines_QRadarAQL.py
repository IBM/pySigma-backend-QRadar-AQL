import pytest
from sigma.exceptions import SigmaValueError, SigmaTransformationError

from sigma.backends.QRadarAQL import QRadarAQLBackend
from sigma.collection import SigmaCollection

from sigma.pipelines.QRadarAQL import QRadarAQL_payload_pipeline
from sigma.pipelines.QRadarAQL import QRadarAQL_fields_pipeline


def test_qradar_field_mapping_unstructured_field():
    for pipeline in [QRadarAQL_payload_pipeline, QRadarAQL_fields_pipeline]:
        assert QRadarAQLBackend(pipeline()).convert(
            SigmaCollection.from_yaml(f"""
                title: Test
                status: test
                logsource:
                    product: windows
                    service: sysmon 
                detection:
                    sel:
                        CommandLine: val1
                        ImagePath: val2
                        uri: val3
                    condition: sel
            """)
        ) == [
                   "SELECT * FROM events WHERE devicetype=12 AND Command='val1' AND "
                   "'Process Path'='val2' AND LOWER(URL) LIKE '%val3%'"
               ]


def test_qradar_field_mapping_unstructured_part_field():
    for pipeline in [QRadarAQL_payload_pipeline, QRadarAQL_fields_pipeline]:
        assert QRadarAQLBackend(pipeline()).convert(
            SigmaCollection.from_yaml(f"""
                title: Test
                status: test
                logsource:
                    product: windows
                    service: sysmon 
                detection:
                    sel:
                        a1: val1
                        a2: val2
                    condition: sel
            """)
        ) == [
                   "SELECT * FROM events WHERE devicetype=12 AND LOWER(Command) LIKE "
                   "'%a1%val1%' AND LOWER(Command) LIKE '%a2%val2%'"
               ]


def test_qradar_field_mapping_unstructured_part_field_contains():
    for pipeline in [QRadarAQL_payload_pipeline, QRadarAQL_fields_pipeline]:
        assert QRadarAQLBackend(pipeline()).convert(
            SigmaCollection.from_yaml(f"""
                title: Test
                status: test
                logsource:
                    product: windows
                    service: sysmon 
                detection:
                    sel:
                        a1|contains: val1
                        a2|startswith: val2
                        a3|endswith: val3
                    condition: sel
            """)
        ) == [
                   "SELECT * FROM events WHERE devicetype=12 AND LOWER(Command) LIKE "
                   "'%a1%val1%' AND LOWER(Command) LIKE '%a2%val2%' AND LOWER("
                   "Command) LIKE '%a3%val3%'"
               ]


def test_qradar_field_mapping_unstructured_field_number_value():
    for pipeline in [QRadarAQL_payload_pipeline, QRadarAQL_fields_pipeline]:
        assert QRadarAQLBackend(pipeline()).convert(
            SigmaCollection.from_yaml(f"""
                title: Test
                status: test
                logsource:
                    product: test
                detection:
                    sel:
                        properties.message: 3
                    condition: sel
            """)
        ) == [
                   "SELECT * FROM events WHERE Message LIKE '%3%'"
               ]


def test_qradar_list_field_mapping():
    for pipeline in [QRadarAQL_payload_pipeline, QRadarAQL_fields_pipeline]:
        assert QRadarAQLBackend(pipeline()).convert(
            SigmaCollection.from_yaml(f"""
                title: Test
                status: test
                logsource:
                    product: windows
                    service: sysmon 
                detection:
                    sel:
                        CommandLine: val1
                        Image: val2
                    condition: sel
            """)
        ) == [
                   "SELECT * FROM events WHERE devicetype=12 AND Command='val1' AND "
                   "('Process Path'='val2' OR 'Process Name'='val2')"
               ]


def test_qradar_concat():
    for pipeline in [QRadarAQL_payload_pipeline, QRadarAQL_fields_pipeline]:
        assert QRadarAQLBackend(pipeline()).convert(
            SigmaCollection.from_yaml(f"""
                title: Test
                status: test
                logsource:
                    category: test_category
                detection:
                    sel:
                        ImageLoaded: 'C:\Program Files\Dell\SARemediation\plugin\log.dll'
                    condition: sel
            """)
        ) == [
                   "SELECT * FROM events WHERE CONCAT("
                   "'file directory', '/', filename)='C:\Program "
                   "Files\Dell\SARemediation\plugin\log.dll'"
               ]


def test_qradar_only_log_source_detection():
    for pipeline in [QRadarAQL_payload_pipeline, QRadarAQL_fields_pipeline]:
        with pytest.raises(TypeError):
            assert QRadarAQLBackend(pipeline()).convert(
                SigmaCollection.from_yaml(f"""
                    title: Test
                    status: test
                    logsource:
                        category: test_category
                    detection:
                        sel:
                            eventSource: 'WindowsAuthServer'
                        condition: sel
                """)
            )


def test_qradar_log_source_value_mapping_with_logsource_devicetype():
    for pipeline in [QRadarAQL_payload_pipeline, QRadarAQL_fields_pipeline]:
        assert QRadarAQLBackend(pipeline()).convert(
            SigmaCollection.from_yaml(f"""
                title: Test
                status: test
                logsource:
                    service: apache
                detection:
                    sel:
                        eventSource: 'WindowsAuthServer'
                        eventName: 'Potential ransomware activity'
                    condition: sel
            """)
        ) == [
                   "SELECT * FROM events WHERE devicetype IN(10, 12) AND QIDNAME("
                   "qid)='Potential ransomware activity'"
               ]


def test_qradar_log_source_not_supported_value_mapping():
    for pipeline in [QRadarAQL_payload_pipeline, QRadarAQL_fields_pipeline]:
        with pytest.raises(SigmaValueError):
            assert QRadarAQLBackend(pipeline()).convert(
                SigmaCollection.from_yaml(f"""
                    title: Test
                    status: test
                    logsource:
                        category: test_category
                    detection:
                        sel:
                            eventSource: val
                        condition: sel
                """)
            )


def test_QRadar_wildcard_unstructured_fields():
    for pipeline in [QRadarAQL_payload_pipeline, QRadarAQL_fields_pipeline]:
        assert QRadarAQLBackend(pipeline()).convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                detection:
                    selection:
                        properties.message: Add user
                    condition: selection
            """)
        ) == [
                   "SELECT * FROM events WHERE LOWER(Message) LIKE '%add user%'"

               ]


def test_QRadar_wildcard_unstructured_fields_or_condition():
    for pipeline in [QRadarAQL_payload_pipeline, QRadarAQL_fields_pipeline]:
        assert QRadarAQLBackend(pipeline()).convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                detection:
                    selection:
                        properties.message:
                        - Add user
                        - Delete user
                    condition: selection
            """)
        ) == [
                   "SELECT * FROM events WHERE LOWER(Message) LIKE '%add user%' "
                   "OR LOWER(Message) LIKE '%delete user%'"

               ]


def test_QRadar_host_fields_ipv6_to_cidr():
    for pipeline in [QRadarAQL_payload_pipeline, QRadarAQL_fields_pipeline]:
        assert QRadarAQLBackend(pipeline()).convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                detection:
                    selection:
                        ProcessPath|endswith: '/file'
                        DestinationIp|startswith: 
                        - '::1'
                        - 'fd'
                    condition: selection
            """)
        ) == [
                   "SELECT * FROM events WHERE LOWER('Process Path') LIKE '%/file' "
                   "AND (INCIDR('::1/128', destinationip) OR INCIDR('fd::/16', "
                   "destinationip))"
               ]


def test_QRadar_host_fields_ipv4_to_cidr():
    for pipeline in [QRadarAQL_payload_pipeline, QRadarAQL_fields_pipeline]:
        assert QRadarAQLBackend(pipeline()).convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                detection:
                    selection:
                        DestinationIp|startswith: 
                        - '127.'
                        - '172.21.'
                    condition: selection
            """)
        ) == [
                   "SELECT * FROM events WHERE INCIDR('127.0.0.0/8', "
                   "destinationip) OR INCIDR('172.21.0.0/16', destinationip)"
               ]
