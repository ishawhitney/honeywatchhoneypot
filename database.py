import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_DIR = BASE_DIR / "database"
DATABASE_DIR.mkdir(exist_ok=True)

DATABASE_PATH = DATABASE_DIR / "honeywatch.db"


def get_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            service TEXT NOT NULL,
            event_type TEXT NOT NULL,
            details TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            start_time TEXT NOT NULL,
            end_time TEXT,
            source_ip TEXT,
            attack_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            threat_score INTEGER NOT NULL,
            status TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service_name TEXT NOT NULL,
            port INTEGER NOT NULL,
            status TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_name TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            threshold INTEGER NOT NULL
        )
    """)

    # Add source_ip to older databases if it does not exist.
    cursor.execute("PRAGMA table_info(incidents)")
    incident_columns = [
        column["name"] for column in cursor.fetchall()
    ]

    if "source_ip" not in incident_columns:
        cursor.execute(
            "ALTER TABLE incidents ADD COLUMN source_ip TEXT"
        )

    # Remove duplicate detection rules from older databases.
    cursor.execute("""
        DELETE FROM rules
        WHERE id NOT IN (
            SELECT MIN(id)
            FROM rules
            GROUP BY rule_name
        )
    """)

    # Make rule names unique for future inserts.
    cursor.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS
        idx_rules_rule_name
        ON rules(rule_name)
    """)

    # Default HoneyWatch detection rules.
    default_rules = [
        (
            "SSH Failed Login Rule",
            "BRUTE_FORCE",
            5
        ),
        (
            "Port Probe Rule",
            "PORT_SCAN",
            4
        ),
        (
            "Suspicious Command Rule",
            "SUSPICIOUS_ACCESS",
            1
        ),
        (
            "HTTP Frequency Rule",
            "ABNORMAL_TRAFFIC",
            8
        )
    ]

    for rule in default_rules:
        cursor.execute(
            """
            INSERT OR IGNORE INTO rules (
                rule_name,
                attack_type,
                threshold
            )
            VALUES (?, ?, ?)
            """,
            rule
        )

    connection.commit()
    connection.close()


def get_detection_rules():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            rule_name,
            attack_type,
            threshold
        FROM rules
        ORDER BY id
    """)

    rules = cursor.fetchall()

    connection.close()

    return rules


if __name__ == "__main__":
    initialize_database()

    print("HoneyWatch database initialized successfully.")
    print(f"Database location: {DATABASE_PATH}")

    print("\nDetection rules:")

    for rule in get_detection_rules():
        print(
            f"- {rule['rule_name']}: "
            f"{rule['attack_type']} "
            f"(threshold={rule['threshold']})"
        )