import requests
from pathlib import Path

URL = "http://localhost:9001/api/emails/analyze"
FIXTURE = Path("backend/tests/fixtures/sample.eml")

with open(FIXTURE, "rb") as f:
    files = {"file": ("sample.eml", f, "message/rfc822")}
    print(f"Posting {FIXTURE} to {URL}...")
    resp = requests.post(URL, files=files, timeout=120)
    print("Status code:", resp.status_code)
    data = resp.json()

    probable_ip = data.get("relay_analysis", {}).get("probable_source_infrastructure", {}).get("address")
    print("Probable source IP:", probable_ip)
    assert probable_ip is None, f"Expected None, got {probable_ip}"

    observations = data.get("threat_intelligence", {}).get("observations", [])
    geo_obs = [obs for obs in observations if obs.get("kind") == "geolocation"]
    print("Geo observations count:", len(geo_obs))
    assert len(geo_obs) == 0, f"Expected 0 geolocation observations, got {len(geo_obs)}"

    print("\n>>> PRIVATE/RESERVED EMAIL TEST PASSED (NO VERIFIED GEOLOCATION AS EXPECTED)! <<<")
