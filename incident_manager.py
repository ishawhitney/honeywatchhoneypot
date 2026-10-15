from datetime import datetime

from backend.database import get_connection
from backend.scorer import score_incidents


def save_incident(incident):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id
        FROM incidents
        WHERE source_ip = ?
        AND attack_type = ?
        AND severity = ?
        AND threat_score = ?
        AND status = 'OPEN'
        LIMIT 1
        """,
        (
            incident["source_ip"],
            incident["attack_type"],
            incident["severity"],
            incident["threat_score"],
        )
    )

    existing_incident = cursor.fetchone()

    if existing_incident:
        connection.close()
        return existing_incident["id"]

    cursor.execute(
        """
        INSERT INTO incidents (
            start_time,
            end_time,
            source_ip,
            attack_type,
            severity,
            threat_score,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            None,
            incident["source_ip"],
            incident["attack_type"],
            incident["severity"],
            incident["threat_score"],
            "OPEN",
        )
    )

    incident_id = cursor.lastrowid

    connection.commit()
    connection.close()

    return incident_id


def process_incidents():
    incidents = score_incidents()

    processed_incidents = []

    for incident in incidents:
        incident_id = save_incident(incident)

        incident_with_id = incident.copy()
        incident_with_id["id"] = incident_id

        processed_incidents.append(incident_with_id)

    return processed_incidents


def get_incidents():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            start_time,
            end_time,
            source_ip,
            attack_type,
            severity,
            threat_score,
            status
        FROM incidents
        ORDER BY id DESC
        """
    )

    incidents = cursor.fetchall()

    connection.close()

    return incidents


def close_incident(incident_id):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE incidents
        SET
            end_time = ?,
            status = 'CLOSED'
        WHERE id = ?
        """,
        (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            incident_id,
        )
    )

    connection.commit()

    updated = cursor.rowcount > 0

    connection.close()

    return updated


if __name__ == "__main__":
    print("\n=== HoneyWatch Incident Manager ===\n")

    processed_incidents = process_incidents()

    print(f"Processed {len(processed_incidents)} incident(s).\n")

    for incident in processed_incidents:
        print(
            f"{incident['source_ip']} | "
            f"{incident['attack_type']} | "
            f"{incident['severity']} | "
            f"Score: {incident['threat_score']}"
        )