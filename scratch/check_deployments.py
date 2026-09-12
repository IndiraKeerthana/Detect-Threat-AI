import urllib.request
import re
import json

def check_vercel():
    url = 'https://detect-threat-ai.vercel.app'
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req) as resp:
        headers = dict(resp.headers)
        html = resp.read().decode('utf-8')
        print("Vercel Headers:")
        for k, v in headers.items():
            if 'vercel' in k.lower() or 'date' in k.lower() or 'etag' in k.lower() or 'commit' in k.lower():
                print(f"  {k}: {v}")
        js_files = re.findall(r'src=["\']([^"\']+\.js)["\']', html)
        print("JS files:", js_files)
        for js in js_files:
            js_url = url + js if js.startswith('/') else js
            with urllib.request.urlopen(urllib.request.Request(js_url, headers={'User-Agent': 'Mozilla/5.0'})) as js_resp:
                js_content = js_resp.read().decode('utf-8')
                print(f"  {js} size: {len(js_content)}")
                matches = set(re.findall(r'sample_bec_investigation|apex-innovations|sample\.eml', js_content))
                print(f"  Keywords in {js}: {matches}")
                # check commit sha if present
                shas = re.findall(r'[0-9a-f]{40}|[0-9a-f]{7}', js_content)
                # print git commit info if embedded
                for line in js_content.split(';'):
                    if 'git' in line.lower() or 'commit' in line.lower() or 'version' in line.lower():
                        if len(line) < 200:
                            print("  Snippet:", line)

if __name__ == '__main__':
    check_vercel()
