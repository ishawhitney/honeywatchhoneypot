import random
import time

from backend.logger import create_event


# Safe test IP addresses used only for simulation
SIMULATED_IPS = [
    "192.168.1.10",
    "192.168.1.20",
    "192.168.1.25",
    "10.0.0.15",
    "10.0.0.25"
]


def generate_normal_activity():
    """
    Generates normal-looking honeypot activity.
    """

    events = [
        {
            "service": "HTTP",
            "event_type": "HTTP_REQUEST",
            "details": "GET /index.html"
        },
        {
            "service": "SSH",
            "event_type": "CONNECTION",
            "details": "SSH connection established"
        },
        {
            "service": "HTTP",
            "event_type": "HTTP_REQUEST",
            "details": "GET /login"
        },
        {
            "service": "SSH",
            "event_type": "LOGIN_SUCCESS",
            "details": "Successful authentication"
        }
    ]

    event = random.choice(events)
    source_ip = random.choice(SIMULATED_IPS)

    return create_event(
        source_ip=source_ip,
        service=event["service"],
        event_type=event["event_type"],
        details=event["details"]
    )


def generate_brute_force_attack():
    """
    Generates a simulated SSH brute-force pattern.
    """

    source_ip = random.choice(SIMULATED_IPS)

    generated_events = []

    for attempt in range(6):
        event = create_event(
            source_ip=source_ip,
            service="SSH",
            event_type="LOGIN_FAILED",
            details=f"Failed login attempt #{attempt + 1}"
        )

        generated_events.append(event)

        # Small delay so the events have different timestamps
        time.sleep(0.2)

    return generated_events


def generate_port_scan():
    """
    Generates a simulated port-scanning pattern.
    """

    source_ip = random.choice(SIMULATED_IPS)

    ports = [21, 22, 23, 80, 443, 8080]

    generated_events = []

    for port in ports:
        event = create_event(
            source_ip=source_ip,
            service=f"PORT_{port}",
            event_type="PORT_PROBE",
            details=f"Connection attempt to port {port}"
        )

        generated_events.append(event)

        time.sleep(0.2)

    return generated_events


def generate_suspicious_access():
    """
    Generates a simulated suspicious-access pattern.
    """

    source_ip = random.choice(SIMULATED_IPS)

    generated_events = []

    login_event = create_event(
        source_ip=source_ip,
        service="SSH",
        event_type="LOGIN_SUCCESS",
        details="Successful authentication"
    )

    generated_events.append(login_event)

    time.sleep(0.2)

    command_event = create_event(
        source_ip=source_ip,
        service="SSH",
        event_type="SUSPICIOUS_COMMAND",
        details="Suspicious command detected"
    )

    generated_events.append(command_event)

    return generated_events


def generate_abnormal_traffic():
    """
    Generates a simulated high-frequency traffic pattern.
    """

    source_ip = random.choice(SIMULATED_IPS)

    generated_events = []

    for request in range(10):
        event = create_event(
            source_ip=source_ip,
            service="HTTP",
            event_type="HIGH_FREQUENCY_REQUEST",
            details=f"HTTP request #{request + 1}"
        )

        generated_events.append(event)

        time.sleep(0.1)

    return generated_events


def run_simulation():
    """
    Runs a complete demonstration containing
    normal and suspicious activity.
    """

    print("\n=== HoneyWatch Simulation Started ===\n")

    print("Generating normal activity...")
    generate_normal_activity()

    time.sleep(1)

    print("Generating brute-force attack...")
    generate_brute_force_attack()

    time.sleep(1)

    print("Generating port scan...")
    generate_port_scan()

    time.sleep(1)

    print("Generating suspicious access...")
    generate_suspicious_access()

    time.sleep(1)

    print("Generating abnormal traffic...")
    generate_abnormal_traffic()

    print("\n=== HoneyWatch Simulation Completed ===")


if __name__ == "__main__":
    run_simulation()