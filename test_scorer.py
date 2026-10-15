from backend.database import get_connection
from backend.scorer import (
    calculate_threat_score,
    determine_severity,
    score_incidents,
)


def add_event(source_ip, service, event_type, details=""):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO events (
            timestamp,
            source_ip,
            service,
            event_type,
            details
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            "2026-09-21 10:00:00",
            source_ip,
            service,
            event_type,
            details,
        ),
    )

    connection.commit()
    connection.close()


def test_brute_force_score():
    assert calculate_threat_score("BRUTE_FORCE") == 70


def test_port_scan_score():
    assert calculate_threat_score("PORT_SCAN") == 60


def test_suspicious_access_score():
    assert calculate_threat_score("SUSPICIOUS_ACCESS") == 40


def test_abnormal_traffic_score():
    assert calculate_threat_score("ABNORMAL_TRAFFIC") == 50


def test_severity_levels():
    assert determine_severity(30) == "LOW"
    assert determine_severity(40) == "MEDIUM"
    assert determine_severity(60) == "HIGH"
    assert determine_severity(80) == "CRITICAL"


def test_brute_force_is_scored_correctly(test_database):
    for _ in range(5):
        add_event(
            "192.168.1.110",
            "SSH",
            "LOGIN_FAILED",
            "Failed login",
        )

    incidents = score_incidents()

    assert len(incidents) == 1
    assert incidents[0]["attack_type"] == "BRUTE_FORCE"
    assert incidents[0]["threat_score"] == 70
    assert incidents[0]["severity"] == "HIGH"