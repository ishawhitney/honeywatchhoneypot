from datetime import datetime

from backend.database import get_connection
from backend.models import Event

def log_event(event: Event):
    """
    Stores a security event in the HoneyWatch database.
    """

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
            event.timestamp,
            event.source_ip,
            event.service,
            event.event_type,
            event.details
        )
    )

    connection.commit()
    connection.close()


def create_event(
    source_ip: str,
    service: str,
    event_type: str,
    details: str = ""
):
    """
    Creates a new Event with the current timestamp
    and stores it in the database.
    """

    event = Event(
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        source_ip=source_ip,
        service=service,
        event_type=event_type,
        details=details
    )

    log_event(event)

    return event


if __name__ == "__main__":

    test_event = create_event(
        source_ip="192.168.1.25",
        service="SSH",
        event_type="LOGIN_FAILED",
        details="Invalid username or password"
    )

    print("Test event logged successfully.")
    print(test_event)