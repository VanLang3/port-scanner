import os

import requests

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
FLAGGED_SCORE_THRESHOLD = 25


def check_abuseipdb(ip, api_key=None, max_age_days=90):
    """
    Query AbuseIPDB for IP reputation.
    Returns a normalized dict, or None if lookup failed or no API key is set.
    """
    api_key = api_key or os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        print("Warning: ABUSEIPDB_API_KEY not set — skipping threat intel lookup")
        print("Set it with: export ABUSEIPDB_API_KEY='your_key_here'\n")
        return None

    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": max_age_days,
    }

    try:
        response = requests.get(
            ABUSEIPDB_URL, headers=headers, params=params, timeout=10
        )
        response.raise_for_status()
        data = response.json()["data"]
    except requests.exceptions.RequestException as e:
        print(f"Threat intel lookup failed: {e}\n")
        return None

    score = data.get("abuseConfidenceScore", 0)
    return {
        "source": "abuseipdb",
        "abuse_confidence_score": score,
        "total_reports": data.get("totalReports", 0),
        "num_distinct_users": data.get("numDistinctUsers", 0),
        "country_code": data.get("countryCode"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "usage_type": data.get("usageType"),
        "flagged": score >= FLAGGED_SCORE_THRESHOLD,
    }


def print_threat_report(intel):
    """Print a human-readable summary from check_abuseipdb() output."""
    score = intel["abuse_confidence_score"]
    print(f"  Abuse confidence: {score}/100")
    print(f"  Total reports:    {intel['total_reports']}")
    print(f"  Distinct users:   {intel['num_distinct_users']}")
    print(f"  Country:          {intel['country_code']}")
    print(f"  ISP:              {intel['isp']}")

    if intel["flagged"]:
        print("\n  WARNING: IP has been reported — proceed with caution.")
    else:
        print("\n  No strong malicious signals in AbuseIPDB.")
