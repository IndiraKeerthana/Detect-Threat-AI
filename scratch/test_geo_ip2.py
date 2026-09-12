import sys
from pathlib import Path
sys.path.insert(0, str(Path("backend").resolve()))
from app.config import get_settings
from app.services.intelligence.providers import IPGeolocationProvider

settings = get_settings()
geo = IPGeolocationProvider(settings.ip_geolocation_api_key)

ips = [
    '198.199.90.42',
    '144.76.136.42',
    '51.15.42.42',
    '167.99.142.42',
    '195.154.122.42',
    '109.205.213.42',
    '185.190.140.42',
    '89.208.107.42',
    '194.26.29.42'
]

for ip in ips:
    res = geo.lookup('ip', ip)
    if res:
        d = res[0].data
        print(f"{ip} -> Country: {d.get('country_name')} ({d.get('country_code')}), City: {d.get('city')}, Region: {d.get('state_prov')}, Lat: {d.get('latitude')}, Lon: {d.get('longitude')}, Org: {d.get('organization')}, ASN: {d.get('asn')}")
