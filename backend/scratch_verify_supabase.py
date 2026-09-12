import json
import urllib.request
import psycopg2
from pathlib import Path
from app.config import get_settings

def run_test():
    sample_eml = (Path(__file__).parent / "tests" / "fixtures" / "sample.eml").read_bytes()
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="sample.eml"\r\n'
        "Content-Type: message/rfc822\r\n\r\n"
    ).encode("utf-8") + sample_eml + f"\r\n--{boundary}--\r\n".encode("utf-8")

    req = urllib.request.Request(
        "http://127.0.0.1:8000/api/emails/analyze",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}
    )

    print("[1] Sending POST /api/emails/analyze...", flush=True)
    with urllib.request.urlopen(req) as resp:
        res_data = json.loads(resp.read().decode("utf-8"))

    case_id = res_data.get("case_id") or res_data.get("caseId")
    print(f"[2] Response received. Case ID generated: {case_id}", flush=True)
    assert case_id, "No case ID returned!"

    # 2. Directly verify in Supabase PostgreSQL
    db_url = get_settings().database_url
    conn = psycopg2.connect(db_url)
    cur = conn.cursor()
    cur.execute("SELECT id, title, classification, risk_score, created_at, investigation_data FROM completed_cases WHERE LOWER(id) = LOWER(%s);", (case_id,))
    row = cur.fetchone()
    conn.close()

    assert row, f"Case {case_id} not found in Supabase PostgreSQL!"
    print("[3] Direct Supabase PG check: SUCCESS! Row found:")
    print("    DB ID:", row[0])
    print("    DB Title:", row[1])
    print("    DB Classification:", row[2])
    print("    DB Risk Score:", row[3])
    print("    DB Created At:", row[4])
    inv = json.loads(row[5]) if isinstance(row[5], str) else row[5]
    print("    Stored AI Source:", inv.get("ai_investigation", {}).get("source"))
    print("    Stored AI Classification:", inv.get("ai_investigation", {}).get("classification"))

    # 3. Retrieve via GET API endpoint
    res_get = urllib.request.urlopen(f"http://127.0.0.1:8000/api/cases/{case_id}")
    get_data = json.loads(res_get.read().decode("utf-8"))
    print(f"[4] GET /api/cases/{case_id}: SUCCESS! ID: {get_data['id']}")
    print("    Retrieved title:", get_data["title"])
    print("    Retrieved subject:", get_data["subject"])
    print("    Retrieved sender:", get_data["sender"])

    print("--- DATA SURVIVAL & SUPABASE PERSISTENCE TEST PASSED 100% ---")

if __name__ == "__main__":
    run_test()
