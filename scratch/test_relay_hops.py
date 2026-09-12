import sys
from pathlib import Path

sys.path.insert(0, str(Path("backend").resolve()))

from app.services.email_parser import parse_email
from app.services.relay_analyzer import analyze_received_headers

eml = Path("backend/tests/fixtures/sample_bec_investigation.eml").read_bytes()
p = parse_email(eml)
r = analyze_received_headers(p.received)

print("probable_source_infrastructure:")
print("  address:", r.probable_source_infrastructure.address)
print("  confidence:", r.probable_source_infrastructure.confidence)
print("  reason:", r.probable_source_infrastructure.reason)

print("\nRelay Hops (oldest to newest):")
for hop in r.relay_hops:
    print(f"Hop {hop.hop_number}:")
    print(f"  header: {hop.original_header[:70]}...")
    for ip in hop.extracted_ips:
        print(f"    IP: {ip.address} | class: {ip.classification} | candidate: {ip.is_public_source_candidate}")
