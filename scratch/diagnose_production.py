import urllib.request
import json
import re

print("--- 1. Checking Vercel Frontend Deployments ---")
for vercel_url in ["https://detect-threat-ai.vercel.app", "https://detect-threat-ai2.vercel.app"]:
    try:
        req = urllib.request.Request(vercel_url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            html = resp.read().decode("utf-8", errors="ignore")
            # Find script bundles
            scripts = re.findall(r'src="(/assets/[^"]+\.js)"', html)
            print(f"\nURL: {vercel_url} (HTTP {resp.status})")
            print(f"  Scripts found: {scripts}")
            if scripts:
                bundle_url = vercel_url.rstrip("/") + scripts[0]
                b_req = urllib.request.Request(bundle_url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(b_req, timeout=15) as b_resp:
                    bundle_text = b_resp.read().decode("utf-8", errors="ignore")
                    print(f"  Bundle {scripts[0]} size: {len(bundle_text)} bytes")
                    # Check for specimen indicators
                    has_sample_bec = "sample_bec_investigation.eml" in bundle_text
                    has_security_signals = "security_signals.eml" in bundle_text
                    has_apex = "apex-innovations" in bundle_text
                    has_streamlined_ui = "WHAT THE AI FOUND FISHY" in bundle_text or "What The AI Found Fishy" in bundle_text
                    has_old_sections = "AI Analyst Rationale & Synthesis" in bundle_text or "AI ANALYST RATIONALE" in bundle_text
                    print(f"  Contains sample_bec_investigation.eml: {has_sample_bec}")
                    print(f"  Contains security_signals.eml: {has_security_signals}")
                    print(f"  Contains apex-innovations (new specimen): {has_apex}")
                    print(f"  Contains 'What The AI Found Fishy': {has_streamlined_ui}")
                    print(f"  Contains 'AI Analyst Rationale & Synthesis' (removed section): {has_old_sections}")
    except Exception as e:
        print(f"URL: {vercel_url} -> Error: {e}")

print("\n--- 3. Inspecting Vercel Bundle Environment & API Endpoint ---")
try:
    req = urllib.request.Request("https://detect-threat-ai.vercel.app/assets/index-BH7S1EfD.js", headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        text = resp.read().decode("utf-8")
        idx = text.find("/api/emails/analyze")
        if idx != -1:
            snippet = text[max(0, idx - 150):min(len(text), idx + 150)]
            print("Snippet around /api/emails/analyze:")
            print(snippet)
        else:
            print("/api/emails/analyze not found in bundle!")
        
        # Check for VITE_API_URL or onrender
        render_mentions = re.findall(r'https://[a-zA-Z0-9\.\-_]*render\.com[^\s"\'`]*', text)
        print("Render URLs in bundle:", set(render_mentions))
        
        # Check where AI ANALYSIS UNAVAILABLE appears in the bundle
        ai_unavail = text.find("AI ANALYSIS UNAVAILABLE")
        if ai_unavail != -1:
            print("\nSnippet around AI ANALYSIS UNAVAILABLE in bundle:")
            print(text[max(0, ai_unavail - 100):min(len(text), ai_unavail + 200)])
except Exception as e:
    print(f"Error inspecting bundle: {e}")

print("\n--- 2. Checking Render Backend Health ---")
render_health_url = "https://detect-threat-ai.onrender.com/api/health"
try:
    req = urllib.request.Request(render_health_url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        print(f"Render Health Status: {resp.status}")
        h_data = json.loads(resp.read().decode("utf-8"))
        print(json.dumps(h_data, indent=2))
except Exception as e:
    print(f"Render Health Error: {e}")
