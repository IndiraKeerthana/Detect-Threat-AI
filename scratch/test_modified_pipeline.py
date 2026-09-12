import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app.services.email_parser import parse_email
from app.services.relay_analyzer import analyze_received_headers
from app.services.security_analysis import analyze_security
from app.services.threat_intelligence import analyze_threat_intelligence
from app.services.investigation import analyze_investigation

raw_eml = (Path(__file__).resolve().parent.parent / "backend/tests/fixtures/sample_bec_investigation.eml").read_bytes()

parsed_email = parse_email(raw_eml)
relay_analysis = analyze_received_headers(parsed_email.received)
security_analysis = analyze_security(parsed_email)
threat_intelligence = analyze_threat_intelligence(parsed_email, relay_analysis, security_analysis)
investigation = analyze_investigation(parsed_email, security_analysis, threat_intelligence)

print("=== RELAY ANALYSIS ===")
print("Probable source address:", relay_analysis.probable_source_infrastructure.address)
print("Confidence:", relay_analysis.probable_source_infrastructure.confidence)
print("Reason:", relay_analysis.probable_source_infrastructure.reason)

print("\n=== THREAT INTELLIGENCE OBSERVATIONS ===")
geo_obs = None
for obs in threat_intelligence.observations:
    if obs.entity_type == "ip":
        print(f"IP: {obs.entity} | kind: {obs.kind} | provider: {obs.provider} | status: {obs.status}")
        if obs.kind == "geolocation":
            geo_obs = obs
            print("  Geo Data:", obs.data)

print("\n=== RISK ASSESSMENT ===")
print("Score:", investigation.risk_assessment.score)
print("Level:", investigation.risk_assessment.level)
print("Classification:", investigation.risk_assessment.classification)
print("Factors:", [f.code for f in investigation.risk_assessment.factors])

assert relay_analysis.probable_source_infrastructure.address == "198.199.90.42", "Failed: Probable source address is not 198.199.90.42"
assert geo_obs is not None, "Failed: Geolocation observation is missing"
assert geo_obs.data.get("country_code") == "US", "Failed: Country code is not US"
assert geo_obs.data.get("latitude") is not None, "Failed: Latitude is missing"
assert geo_obs.data.get("longitude") is not None, "Failed: Longitude is missing"
print("\n>>> ALL ASSERTIONS PASSED! <<<")
