from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.database import (
    get_connection,
    get_detection_rules,
    initialize_database,
)
from backend.incident_manager import (
    close_incident,
    get_incidents as get_saved_incidents,
    process_incidents,
)
from backend.simulator import (
    generate_abnormal_traffic,
    generate_brute_force_attack,
    generate_normal_activity,
    generate_port_scan,
    generate_suspicious_access,
)


app = FastAPI(
    title="HoneyWatch API",
    description="Honeypot Attack Detection and Monitoring System",
    version="1.0.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


initialize_database()


@app.get("/")
def root():
    return {
        "system": "HoneyWatch",
        "status": "online",
        "message": "Honeypot Attack Detection and Monitoring System",
    }


@app.get("/events")
def get_events():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            timestamp,
            source_ip,
            service,
            event_type,
            details
        FROM events
        ORDER BY id DESC
    """)

    events = [dict(row) for row in cursor.fetchall()]

    connection.close()

    return events


@app.get("/incidents")
def get_incidents():
    return get_saved_incidents()


@app.post("/detect")
def detect_attacks():
    incidents = process_incidents()

    return {
        "message": "Detection completed",
        "count": len(incidents),
        "incidents": incidents,
    }


@app.patch("/incidents/{incident_id}/close")
def close_incident_endpoint(incident_id: int):
    success = close_incident(incident_id)

    if not success:
        return {
            "message": "Incident not found",
            "success": False,
        }

    return {
        "message": "Incident closed successfully",
        "success": True,
        "incident_id": incident_id,
    }


@app.post("/simulate")
def run_simulation():
    normal_event = generate_normal_activity()

    brute_force_events = generate_brute_force_attack()

    port_scan_events = generate_port_scan()

    suspicious_access_events = generate_suspicious_access()

    abnormal_traffic_events = generate_abnormal_traffic()

    return {
        "message": "Simulation completed",
        "normal_activity": 1,
        "brute_force_events": len(brute_force_events),
        "port_scan_events": len(port_scan_events),
        "suspicious_access_events": len(suspicious_access_events),
        "abnormal_traffic_events": len(abnormal_traffic_events),
    }


@app.get("/statistics")
def get_statistics():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("SELECT COUNT(*) AS count FROM events")
    total_events = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) AS count FROM incidents")
    total_incidents = cursor.fetchone()["count"]

    cursor.execute("""
        SELECT AVG(threat_score) AS average_score
        FROM incidents
    """)
    average_result = cursor.fetchone()["average_score"]

    cursor.execute("""
        SELECT
            attack_type,
            COUNT(*) AS count
        FROM incidents
        GROUP BY attack_type
        ORDER BY count DESC
    """)
    attack_distribution = [
        dict(row) for row in cursor.fetchall()
    ]

    cursor.execute("""
        SELECT
            severity,
            COUNT(*) AS count
        FROM incidents
        GROUP BY severity
        ORDER BY count DESC
    """)
    severity_distribution = [
        dict(row) for row in cursor.fetchall()
    ]

    connection.close()

    return {
        "total_events": total_events,
        "total_incidents": total_incidents,
        "average_threat_score": round(average_result or 0, 2),
        "attack_distribution": attack_distribution,
        "severity_distribution": severity_distribution,
    }


@app.get("/rules")
def get_rules():
    rules = get_detection_rules()

    return [
        {
            "rule_name": rule["rule_name"],
            "attack_type": rule["attack_type"],
            "threshold": rule["threshold"],
        }
        for rule in rules
    ]