import requests
from pathlib import Path
import json

URL = "http://localhost:9001/api/emails/analyze"
FIXTURE = Path("backend/tests/fixtures/sample_bec_investigation.eml")

with open(FIXTURE, "rb") as f:
    files = {"file": ("sample_bec_investigation.eml", f, "message/rfc822")}
    print(f"Posting {FIXTURE} to {URL}...")
    resp = requests.post(URL, files=files, timeout=120)
    print("Status code:", resp.status_code)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
    data = resp.json()

    # 1. Probable origin relay infrastructure
    probable_ip = data.get("relay_analysis", {}).get("probable_source_infrastructure", {}).get("address")
    print("Probable source IP:", probable_ip)
    assert probable_ip == "198.199.90.42", f"Expected 198.199.90.42, got {probable_ip}"

    # 2. Check threat intelligence observations for geolocation
    observations = data.get("threat_intelligence", {}).get("observations", [])
    geo_obs = next((obs for obs in observations if obs.get("kind") == "geolocation" and obs.get("entity") == "198.199.90.42"), None)
    print("Geo observation found:", geo_obs is not None)
    assert geo_obs is not None, "Missing geolocation observation for 198.199.90.42"
    
    geo_data = geo_obs.get("data", {})
    country = geo_data.get("country_name") or geo_data.get("country")
    country_code = geo_data.get("country_code")
    region = geo_data.get("state_prov") or geo_data.get("region")
    city = geo_data.get("city")
    lat = geo_data.get("latitude")
    lon = geo_data.get("longitude")
    org = geo_data.get("organization")
    asn = geo_data.get("asn")

    print(f"  Country: {country} ({country_code})")
    print(f"  Region: {region}")
    print(f"  City: {city}")
    print(f"  Coordinates: Lat={lat}, Lon={lon}")
    print(f"  Org: {org}")
    print(f"  ASN: {asn}")

    assert country == "United States", f"Expected United States, got {country}"
    assert country_code == "US", f"Expected US, got {country_code}"
    assert region == "New Jersey", f"Expected New Jersey, got {region}"
    assert city == "North Bergen", f"Expected North Bergen, got {city}"
    assert lat is not None and lon is not None, "Coordinates missing"
    assert -90 <= lat <= 90 and -180 <= lon <= 180, f"Invalid coordinates {lat}, {lon}"

    # 3. Check case persistence source_ip
    case_id = data.get("caseId") or data.get("case_id")
    print("Case ID:", case_id)

    # 4. Check risk score
    score = data.get("risk_assessment", {}).get("score")
    classification = data.get("risk_assessment", {}).get("classification")
    print("Risk score:", score)
    print("Classification:", classification)

    print("\n>>> LIVE POST /api/emails/analyze TEST PASSED WITH VERIFIED GEOLOCATION! <<<")
