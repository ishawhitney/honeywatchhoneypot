from backend.database import get_connection
from backend import simulator


def count_events():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("SELECT COUNT(*) AS total FROM events")
    result = cursor.fetchone()

    connection.close()

    return result["total"]


def test_simulator_events_are_saved(test_database, monkeypatch):
    monkeypatch.setattr(simulator.time, "sleep", lambda _: None)

    events = simulator.generate_brute_force_attack()

    assert len(events) == 6
    assert count_events() == 6


def test_normal_activity_is_saved(test_database, monkeypatch):
    monkeypatch.setattr(simulator.time, "sleep", lambda _: None)

    event = simulator.generate_normal_activity()

    assert event is not None
    assert count_events() == 1


def test_port_scan_is_saved(test_database, monkeypatch):
    monkeypatch.setattr(simulator.time, "sleep", lambda _: None)

    events = simulator.generate_port_scan()

    assert len(events) == 6
    assert count_events() == 6


def test_suspicious_access_is_saved(test_database, monkeypatch):
    monkeypatch.setattr(simulator.time, "sleep", lambda _: None)

    events = simulator.generate_suspicious_access()

    assert len(events) == 2
    assert count_events() == 2


def test_abnormal_traffic_is_saved(test_database, monkeypatch):
    monkeypatch.setattr(simulator.time, "sleep", lambda _: None)

    events = simulator.generate_abnormal_traffic()

    assert len(events) == 10
    assert count_events() == 10


def test_simulator_event_types(test_database, monkeypatch):
    monkeypatch.setattr(simulator.time, "sleep", lambda _: None)

    events = simulator.generate_brute_force_attack()

    assert all(event.event_type == "LOGIN_FAILED" for event in events)