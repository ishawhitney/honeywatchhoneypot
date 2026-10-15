from backend.database import get_connection
from backend.detector import (
    detect_abnormal_traffic,
    detect_brute_force,
    detect_port_scan,
    detect_suspicious_access,
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


def test_detect_brute_force(test_database):
    for _ in range(5):
        add_event(
            "192.168.1.100",
            "SSH",
            "LOGIN_FAILED",
            "Failed login",
        )

    results = detect_brute_force()

    assert len(results) == 1
    assert results[0]["source_ip"] == "192.168.1.100"
    assert results[0]["attempts"] == 5


def test_detect_port_scan(test_database):
    ports = [21, 22, 23, 80]

    for port in ports:
        add_event(
            "192.168.1.101",
            f"PORT_{port}",
            "PORT_PROBE",
            f"Probe port {port}",
        )

    results = detect_port_scan()

    assert len(results) == 1
    assert results[0]["source_ip"] == "192.168.1.101"
    assert results[0]["ports_probed"] == 4


def test_detect_suspicious_access(test_database):
    add_event(
        "192.168.1.102",
        "SSH",
        "SUSPICIOUS_COMMAND",
        "Suspicious command",
    )

    results = detect_suspicious_access()

    assert len(results) == 1
    assert results[0]["source_ip"] == "192.168.1.102"
    assert results[0]["suspicious_events"] == 1


def test_detect_abnormal_traffic(test_database):
    for number in range(8):
        add_event(
            "192.168.1.103",
            "HTTP",
            "HIGH_FREQUENCY_REQUEST",
            f"Request {number + 1}",
        )

    results = detect_abnormal_traffic()

    assert len(results) == 1
    assert results[0]["source_ip"] == "192.168.1.103"
    assert results[0]["request_count"] == 8