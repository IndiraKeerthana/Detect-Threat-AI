import sys
from pathlib import Path

sys.path.insert(0, str(Path("backend").resolve()))

from app.config import get_settings
from app.services.intelligence.providers import IPGeolocationProvider

settings = get_settings()
geo_provider = IPGeolocationProvider(settings.ip_geolocation_api_key)

# We want an IP that:
# 1. Is genuinely public and routable
# 2. Is NOT Google (8.8.8.8), Cloudflare (1.1.1.1), Microsoft, Amazon
# 3. Resolves cleanly via IPGeolocationProvider with Country, Region/City, and Coordinates
# 4. Represents realistic external ISP or hosting provider infrastructure

test_ips = [
    # Let's test a few public IPs from various typical European / North American / Asian commercial ISPs or universities
    "195.130.217.42",   # European ISP/university or commercial
    "185.220.101.5",    # Common hosting/relay
    "93.184.216.34",    # Example.com (EDGECAST / Verizon Digital)
    "194.169.175.42",   # European network
    "146.112.61.106",   # OpenDNS
    "199.232.41.10",    # Fastly
    "45.33.32.156",     # Linode
    "104.244.42.1",     # Twitter / X
    "142.250.190.46",   # (Google)
    "151.101.65.140",   # Fastly
    "192.30.255.113",   # GitHub
    "205.251.192.0",    # AWS DNS
]

print(f"Testing {len(test_ips)} candidate IPs against IPGeolocationProvider...")
for ip in test_ips:
    try:
        res = geo_provider.lookup("ip", ip)
        if res:
            obs, rels = res
            data = obs.data
            print(f"\nIP: {ip}")
            print(f"  Country: {data.get('country_name')} ({data.get('country_code')})")
            print(f"  Region: {data.get('state_prov')}")
            print(f"  City: {data.get('city')}")
            print(f"  Coords: Lat={data.get('latitude')}, Lon={data.get('longitude')}")
            print(f"  ISP: {data.get('isp')}")
            print(f"  Org: {data.get('organization')}")
            print(f"  ASN: {data.get('asn')}")
    except Exception as e:
        print(f"IP {ip} failed: {e}")
