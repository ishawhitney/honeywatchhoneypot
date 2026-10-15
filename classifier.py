from backend.detector import run_detection


def classify_attacks():
    """
    Converts detection results into
    structured attack classifications.
    """

    detections = run_detection()

    incidents = []

    for result in detections["brute_force"]:
        incidents.append({
            "source_ip": result["source_ip"],
            "attack_type": "BRUTE_FORCE",
            "evidence": f'{result["attempts"]} failed SSH login attempts'
        })

    for result in detections["port_scan"]:
        incidents.append({
            "source_ip": result["source_ip"],
            "attack_type": "PORT_SCAN",
            "evidence": f'{result["ports_probed"]} different ports probed'
        })

    for result in detections["suspicious_access"]:
        incidents.append({
            "source_ip": result["source_ip"],
            "attack_type": "SUSPICIOUS_ACCESS",
            "evidence": f'{result["suspicious_events"]} suspicious command(s) detected'
        })

    for result in detections["abnormal_traffic"]:
        incidents.append({
            "source_ip": result["source_ip"],
            "attack_type": "ABNORMAL_TRAFFIC",
            "evidence": f'{result["request_count"]} high-frequency HTTP requests'
        })

    return incidents


if __name__ == "__main__":

    print("\n=== HoneyWatch Attack Classifier ===\n")

    incidents = classify_attacks()

    if not incidents:
        print("No attacks classified.")

    else:
        for incident in incidents:
            print(f"Source IP   : {incident['source_ip']}")
            print(f"Attack Type : {incident['attack_type']}")
            print(f"Evidence    : {incident['evidence']}")
            print("-" * 45)