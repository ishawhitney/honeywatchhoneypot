from backend.classifier import classify_attacks


# Base threat scores for different attack types
THREAT_SCORES = {
    "SUSPICIOUS_ACCESS": 40,
    "ABNORMAL_TRAFFIC": 50,
    "PORT_SCAN": 60,
    "BRUTE_FORCE": 70
}


def calculate_threat_score(attack_type):
    """
    Returns the base threat score for an attack type.
    """

    return THREAT_SCORES.get(attack_type, 20)


def determine_severity(score):
    """
    Converts a numerical threat score
    into a severity level.
    """

    if score >= 80:
        return "CRITICAL"

    elif score >= 60:
        return "HIGH"

    elif score >= 40:
        return "MEDIUM"

    else:
        return "LOW"


def score_incidents():
    """
    Assigns threat scores and severity levels
    to classified incidents.
    """

    classified_incidents = classify_attacks()

    scored_incidents = []

    for incident in classified_incidents:

        score = calculate_threat_score(
            incident["attack_type"]
        )

        severity = determine_severity(score)

        scored_incidents.append({
            "source_ip": incident["source_ip"],
            "attack_type": incident["attack_type"],
            "evidence": incident["evidence"],
            "threat_score": score,
            "severity": severity
        })

    return scored_incidents


if __name__ == "__main__":

    print("\n=== HoneyWatch Threat Scoring Engine ===\n")

    incidents = score_incidents()

    if not incidents:
        print("No incidents to score.")

    else:

        for incident in incidents:

            print(f"Source IP    : {incident['source_ip']}")
            print(f"Attack Type  : {incident['attack_type']}")
            print(f"Threat Score : {incident['threat_score']}")
            print(f"Severity     : {incident['severity']}")
            print(f"Evidence     : {incident['evidence']}")
            print("-" * 50)
            