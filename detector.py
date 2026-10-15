from backend.database import get_connection


def get_rule_threshold(attack_type, default_threshold):
    """
    Get the threshold for an attack type from the rules table.
    Uses the default value if the rule is not found.
    """
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT threshold
        FROM rules
        WHERE attack_type = ?
        LIMIT 1
        """,
        (attack_type,)
    )

    result = cursor.fetchone()
    connection.close()

    if result is None:
        return default_threshold

    return result["threshold"]


def detect_brute_force():
    threshold = get_rule_threshold(
        "BRUTE_FORCE",
        5
    )

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT source_ip, COUNT(*) AS attempts
        FROM events
        WHERE service = 'SSH'
        AND event_type = 'LOGIN_FAILED'
        GROUP BY source_ip
        HAVING COUNT(*) >= ?
        """,
        (threshold,)
    )

    results = cursor.fetchall()
    connection.close()

    return results


def detect_port_scan():
    threshold = get_rule_threshold(
        "PORT_SCAN",
        4
    )

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT source_ip, COUNT(DISTINCT service) AS ports_probed
        FROM events
        WHERE event_type = 'PORT_PROBE'
        GROUP BY source_ip
        HAVING COUNT(DISTINCT service) >= ?
        """,
        (threshold,)
    )

    results = cursor.fetchall()
    connection.close()

    return results


def detect_suspicious_access():
    threshold = get_rule_threshold(
        "SUSPICIOUS_ACCESS",
        1
    )

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT source_ip, COUNT(*) AS suspicious_events
        FROM events
        WHERE event_type = 'SUSPICIOUS_COMMAND'
        GROUP BY source_ip
        HAVING COUNT(*) >= ?
        """,
        (threshold,)
    )

    results = cursor.fetchall()
    connection.close()

    return results


def detect_abnormal_traffic():
    threshold = get_rule_threshold(
        "ABNORMAL_TRAFFIC",
        8
    )

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT source_ip, COUNT(*) AS request_count
        FROM events
        WHERE service = 'HTTP'
        AND event_type = 'HIGH_FREQUENCY_REQUEST'
        GROUP BY source_ip
        HAVING COUNT(*) >= ?
        """,
        (threshold,)
    )

    results = cursor.fetchall()
    connection.close()

    return results


def run_detection():
    detections = {
        "brute_force": detect_brute_force(),
        "port_scan": detect_port_scan(),
        "suspicious_access": detect_suspicious_access(),
        "abnormal_traffic": detect_abnormal_traffic()
    }

    return detections