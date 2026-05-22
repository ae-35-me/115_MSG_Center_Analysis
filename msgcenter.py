#!/usr/bin/env python3
"""
M365 Message Center → Ollama security analysis PoC
Runs fully locally — no cloud API costs.
"""

import os
import sys
import json
import re
import csv
import io
import base64
import socket
import argparse
import time
import gzip
from collections import Counter
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timedelta
from dotenv import load_dotenv
import psycopg2
from psycopg2.extras import RealDictCursor

load_dotenv(override=True)

TENANT_ID     = os.getenv("TENANT_ID")
CLIENT_ID     = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
OLLAMA_HOST   = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL  = os.getenv("OLLAMA_MODEL", "llama3.2")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "14400"))
OLLAMA_RELEVANCE_TIMEOUT = int(os.getenv("OLLAMA_RELEVANCE_TIMEOUT", "14400"))
TENANT_SERVICES_HINT = os.getenv("TENANT_SERVICES_HINT", "")
AZURE_RESOURCE_SCAN_LIMIT = int(os.getenv("AZURE_RESOURCE_SCAN_LIMIT", "5000"))
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "output.txt")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID", "")
LAST_RUN_TIME_STR  = os.getenv("LAST_RUN_TIME", "")
DATABASE_URL       = os.getenv("DATABASE_URL")
LOCAL_DATABASE_URL = os.getenv("LOCAL_DATABASE_URL")
FORCED_TENANT_SERVICES = ["Microsoft 365 Copilot", "Microsoft 365 Copilot Chat"]


# ── Database ──────────────────────────────────────────────────────────────────

def get_db_connection(url=None):
    db_url = url or DATABASE_URL
    if not db_url:
        return None
    try:
        conn = psycopg2.connect(db_url)
        return conn
    except Exception as e:
        # We don't print full error here to keep logs clean when Neon is down
        return None


def init_db():
    """Create the analysis table if it does not exist on both databases."""
    for name, url in [("Neon", DATABASE_URL), ("Local", LOCAL_DATABASE_URL)]:
        if not url:
            continue
        conn = get_db_connection(url)
        if not conn:
            print(f"  ⚠  {name} database connection failed during initialization.")
            continue
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS message_analysis (
                        id TEXT PRIMARY KEY,
                        title TEXT,
                        services TEXT[],
                        published_at TIMESTAMP WITH TIME ZONE,
                        last_modified TIMESTAMP WITH TIME ZONE,
                        analysis_json JSONB,
                        risk_rating TEXT,
                        model_used TEXT,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE INDEX IF NOT EXISTS idx_risk_rating ON message_analysis(risk_rating);
                    CREATE INDEX IF NOT EXISTS idx_published_at ON message_analysis(published_at);
                """)
                conn.commit()
                print(f"✅  {name} database initialized (table: message_analysis)")
        except Exception as e:
            print(f"  ⚠  {name} database initialization failed: {e}")
        finally:
            conn.close()


def sync_databases():
    """Sync missing records from Local DB to Neon DB."""
    if not DATABASE_URL or not LOCAL_DATABASE_URL:
        return

    print("🔄  Checking for data sync between Local and Neon...")
    local_conn = get_db_connection(LOCAL_DATABASE_URL)
    if not local_conn:
        print("  ⚠  Local DB unavailable for sync.")
        return

    neon_conn = get_db_connection(DATABASE_URL)
    if not neon_conn:
        print("  ℹ️  Neon DB still constrained/unavailable. Skipping sync for now.")
        local_conn.close()
        return

    try:
        with local_conn.cursor() as lcur, neon_conn.cursor() as ncur:
            # Get IDs from both
            lcur.execute("SELECT id FROM message_analysis")
            local_ids = {row[0] for row in lcur.fetchall()}
            
            ncur.execute("SELECT id FROM message_analysis")
            neon_ids = {row[0] for row in ncur.fetchall()}
            
            missing_ids = local_ids - neon_ids
            if not missing_ids:
                print("✅  Neon database is up to date.")
                return

            print(f"📦  Syncing {len(missing_ids)} records to Neon...")
            for msg_id in missing_ids:
                lcur.execute("""
                    SELECT id, title, services, published_at, last_modified, analysis_json, risk_rating, model_used, created_at 
                    FROM message_analysis WHERE id = %s
                """, (msg_id,))
                record = list(lcur.fetchone())
                
                # Ensure analysis_json is a string for the sync insert
                if isinstance(record[5], (dict, list)):
                    record[5] = json.dumps(record[5])
                
                ncur.execute("""
                    INSERT INTO message_analysis (id, title, services, published_at, last_modified, analysis_json, risk_rating, model_used, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (id) DO UPDATE SET
                        title = EXCLUDED.title,
                        services = EXCLUDED.services,
                        published_at = EXCLUDED.published_at,
                        last_modified = EXCLUDED.last_modified,
                        analysis_json = EXCLUDED.analysis_json,
                        risk_rating = EXCLUDED.risk_rating,
                        model_used = EXCLUDED.model_used,
                        created_at = EXCLUDED.created_at;
                """, tuple(record))
            neon_conn.commit()
            print(f"✅  Sync complete: {len(missing_ids)} records moved to Neon.")
    except Exception as e:
        print(f"  ⚠  Sync failed: {e}")
    finally:
        local_conn.close()
        neon_conn.close()


def check_analysis_exists(msg_id: str) -> bool:
    """Check if analysis exists in the Local DB (primary reference)."""
    conn = get_db_connection(LOCAL_DATABASE_URL) or get_db_connection(DATABASE_URL)
    if not conn:
        return False
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM message_analysis WHERE id = %s", (msg_id,))
            return cur.fetchone() is not None
    except Exception:
        return False
    finally:
        conn.close()


def save_analysis(msg_id, title, services, published_at, last_modified, analysis_json, risk_rating, model_used):
    """Save the analysis results to both Local and Neon databases."""
    # Normalize types for PG
    if isinstance(analysis_json, str):
        try:
            json.loads(analysis_json)
            json_data = analysis_json
        except Exception:
            json_data = json.dumps({"raw_output": analysis_json})
    elif isinstance(analysis_json, dict):
        json_data = json.dumps(analysis_json)
    else:
        json_data = json.dumps({"output": str(analysis_json)})

    pub_at_dt = parse_graph_datetime(published_at) if isinstance(published_at, str) else published_at
    last_mod_dt = parse_graph_datetime(last_modified) if isinstance(last_modified, str) else last_modified

    # Save to Local first (most reliable)
    local_saved = _perform_save(LOCAL_DATABASE_URL, "Local", msg_id, title, services, pub_at_dt, last_mod_dt, json_data, risk_rating, model_used)
    
    # Try to save to Neon
    neon_saved = _perform_save(DATABASE_URL, "Neon", msg_id, title, services, pub_at_dt, last_mod_dt, json_data, risk_rating, model_used)
    
    if local_saved:
        print(f"    💾  Analysis saved to Local DB (ID: {msg_id})")
    if neon_saved:
        print(f"    💾  Analysis saved to Neon DB (ID: {msg_id})")
    elif DATABASE_URL:
        print(f"    ⚠️  Neon DB save skipped/failed (ID: {msg_id})")


def _perform_save(url, name, msg_id, title, services, pub_at, last_mod, json_data, risk_rating, model_used):
    if not url:
        return False
    conn = get_db_connection(url)
    if not conn:
        return False
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO message_analysis (id, title, services, published_at, last_modified, analysis_json, risk_rating, model_used)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    title = EXCLUDED.title,
                    services = EXCLUDED.services,
                    published_at = EXCLUDED.published_at,
                    last_modified = EXCLUDED.last_modified,
                    analysis_json = EXCLUDED.analysis_json,
                    risk_rating = EXCLUDED.risk_rating,
                    model_used = EXCLUDED.model_used,
                    created_at = CURRENT_TIMESTAMP;
            """, (msg_id, title, list(services) if isinstance(services, (list, set)) else [services], 
                  pub_at, last_mod, json_data, risk_rating, model_used))
            conn.commit()
            return True
    except Exception as e:
        # print(f"  ⚠  Failed to save to {name}: {e}")
        return False
    finally:
        conn.close()


# ── Helpers ───────────────────────────────────────────────────────────────────

def http_post(url, data: dict, headers: dict = None, timeout: int = 60) -> dict:
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def http_get(url, headers: dict = None, timeout: int = 60) -> dict:
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def strip_html(html: str) -> str:
    text = re.sub(r"<[^>]+>", " ", html or "")
    text = text.replace("&nbsp;", " ").replace("&amp;", "&") \
               .replace("&lt;", "<").replace("&gt;", ">")
    return re.sub(r" {2,}", " ", text).strip()


def format_duration(seconds: float) -> str:
    minutes, secs = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def parse_graph_datetime(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def decode_jwt_claims(token: str) -> dict:
    """Decode JWT payload without signature verification (diagnostics only)."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        payload = parts[1]
        pad = "=" * (-len(payload) % 4)
        decoded = base64.urlsafe_b64decode(payload + pad).decode("utf-8")
        return json.loads(decoded)
    except Exception:
        return {}


def parse_services_hint(raw: str) -> list[str]:
    """Parse comma-separated service hints into normalized names."""
    if not raw:
        return []
    items = [s.strip() for s in raw.split(",")]
    return [s for s in items if s]


def update_env_value(key: str, value: str) -> None:
    """Update or append a key=value pair in the .env file."""
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    key_found = False
    new_lines = []
    for line in lines:
        if re.match(rf"^{re.escape(key)}\s*=", line):
            new_lines.append(f"{key}={value}\n")
            key_found = True
        else:
            new_lines.append(line)
    if not key_found:
        new_lines.append(f"{key}={value}\n")
    with open(env_path, "w", encoding="utf-8") as f:
        f.writelines(new_lines)


def send_telegram_message(text: str) -> None:
    """Send a plain-text message via Telegram Bot API. Skips silently if not configured."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = json.dumps({"chat_id": TELEGRAM_CHAT_ID, "text": text}).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            resp.read()
    except urllib.error.HTTPError as e:
        body = b""
        try:
            body = e.read()
        except Exception:
            pass
        print(f"  ⚠  Telegram send failed (HTTP {e.code}): {body.decode()[:200]}")
    except Exception as e:
        print(f"  ⚠  Telegram send failed: {e}")


def send_dependency_alert(component: str, reason: str, model: str = "") -> None:
    """Send a dependency-failure alert to Telegram."""
    lines = [
        "❌ M365 Message Center dependency issue",
        "",
        f"Component: {component}",
        f"Reason: {reason}",
    ]
    if model:
        lines.append(f"Model: {model}")
    send_telegram_message("\n".join(lines))


def find_key_recursive(data, target_key):
    """Recursively search for a key in a nested dict/list."""
    if isinstance(data, dict):
        if target_key in data:
            return data[target_key]
        for v in data.values():
            result = find_key_recursive(v, target_key)
            if result is not None:
                return result
    elif isinstance(data, list):
        for item in data:
            result = find_key_recursive(item, target_key)
            if result is not None:
                return result
    return None


def has_security_implications(analysis_raw: str) -> bool:
    """Return True if the analysis contains meaningful security implications."""
    if not analysis_raw or not analysis_raw.strip():
        print("    ⚠  Analysis output is empty.")
        return False

    parsed = None
    try:
        parsed = json.loads(analysis_raw)
    except Exception:
        # Try to extract JSON from markdown or text
        match = re.search(r"\{.*\}", analysis_raw, flags=re.DOTALL)
        if match:
            try:
                parsed = json.loads(match.group(0))
            except Exception:
                parsed = None

    if not isinstance(parsed, dict):
        # Fallback to keyword search if JSON parsing fails
        lowered = analysis_raw.lower()
        found = any(term in lowered for term in ["high", "medium", "security implication"])
        if found:
            print("    ℹ️  JSON parse failed, but keywords suggest security implications.")
        return found

    # Flexible risk check
    risk = find_key_recursive(parsed, "risk_rating")
    if risk is None:
        risk = find_key_recursive(parsed, "overall_risk_level")
    
    if risk:
        risk_str = str(risk).lower()
        print(f"    🔍  Detected risk level: {risk_str}")
        if any(level in risk_str for level in ["medium", "high", "critical"]):
            return True

    # Check for non-empty implications list
    imps = find_key_recursive(parsed, "security_implications")
    if isinstance(imps, list) and len(imps) > 0:
        print(f"    🔍  Detected {len(imps)} security implications.")
        return True

    return False


def build_telegram_message(msg: dict, analysis_raw: str) -> str:
    """Build a plain-text Telegram notification for a message with security implications."""
    title    = msg.get("title", "Untitled")
    services = ", ".join(msg.get("services", [])) or "Unknown"
    updated  = msg.get("lastModifiedDateTime", "")
    msg_id   = msg.get("id", "")

    parsed = None
    try:
        parsed = json.loads(analysis_raw)
    except Exception:
        match = re.search(r"\{.*\}", analysis_raw, flags=re.DOTALL)
        if match:
            try:
                parsed = json.loads(match.group(0))
            except Exception:
                parsed = None

    if isinstance(parsed, dict):
        risk = parsed.get("risk_rating", "Unknown")
        summary = parsed.get("plain_english_summary", "")
        implications = parsed.get("security_implications", [])
        sec_text = ""
        for imp in implications:
            theme = imp.get("theme", "other")
            impact = imp.get("impact", "")
            sec_text += f"• [{theme}] {impact}\n"
    else:
        # Fallback to simple extraction
        risk_match = re.search(r"\*\*Risk Rating\*\*\s*:\s*(.+?)(?:\n|$)", analysis_raw, re.IGNORECASE)
        risk = risk_match.group(1).strip() if risk_match else "Unknown"
        sec_text = "See full analysis for details."
        summary = ""

    if len(sec_text) > 600:
        sec_text = sec_text[:597] + "..."

    admin_url = (
        "https://admin.microsoft.com/Adminportal/Home"
        f"#/MessageCenter/:/messages/{msg_id}"
    )

    parts = [
        "🚨 M365 Security Alert",
        "",
        f"Title:   {title}",
        f"Service: {services}",
        f"Updated: {updated[:10] if updated else 'Unknown'}",
        f"Risk:    {risk}",
    ]
    if summary:
        parts += ["", "Summary:", summary]
    if sec_text:
        parts += ["", "Security Implications:", sec_text.strip()]
    parts += ["", admin_url]
    return "\n".join(parts)


class TeeStream:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, data):
        for stream in self.streams:
            stream.write(data)
        return len(data)

    def flush(self):
        for stream in self.streams:
            stream.flush()

    def isatty(self):
        return any(getattr(stream, "isatty", lambda: False)() for stream in self.streams)


# ── Graph API ─────────────────────────────────────────────────────────────────

def get_token_from_cli(scope: str) -> str:
    """Attempt to get an access token using the Azure CLI."""
    resource_map = {
        "https://graph.microsoft.com/.default": "ms-graph",
        "https://management.azure.com/.default": "arm"
    }
    resource_type = resource_map.get(scope, "arm")
    cmd = ["az", "account", "get-access-token", "--resource-type", resource_type, "--output", "json"]
    try:
        # We use a short timeout and check for az existence
        import subprocess
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=15)
        data = json.loads(result.stdout)
        token = data.get("accessToken")
        if token:
            print(f"    (Acquired {resource_type} token via Azure CLI)")
            return token
    except (subprocess.SubprocessError, FileNotFoundError, json.JSONDecodeError, KeyError):
        pass
    return ""


def get_graph_token() -> str:
    # 1. Try Client Credentials first for Graph (usually has better/specific permissions for M365)
    if CLIENT_ID and CLIENT_SECRET:
        url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
        data = {
            "client_id":     CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "scope":         "https://graph.microsoft.com/.default",
            "grant_type":    "client_credentials",
        }
        try:
            resp = http_post(url, data, {"Content-Type": "application/x-www-form-urlencoded"})
            if "access_token" in resp:
                return resp["access_token"]
        except Exception as e:
            print(f"    (Graph SP token fetch failed: {e})")

    # 2. Fall back to Azure CLI
    cli_token = get_token_from_cli("https://graph.microsoft.com/.default")
    if cli_token:
        return cli_token

    raise RuntimeError("Could not acquire Graph API token (SP or CLI)")


def get_messages(token: str, days: int = 90, since: datetime | None = None) -> list:
    fields = "id,title,services,category,severity,tags,isMajorChange,startDateTime,lastModifiedDateTime,actionRequiredByDateTime,body"
    # Use top=1000 to get more data per request
    url = (
        "https://graph.microsoft.com/v1.0/admin/serviceAnnouncement/messages"
        f"?$top=1000&$orderby=lastModifiedDateTime%20desc&$select={fields}"
    )
    headers = {"Authorization": f"Bearer {token}"}
    cutoff = datetime.now().astimezone() - timedelta(days=days)
    # For a 'complete' run, we can ignore the 'since' (last_run) parameter if the user wants to re-validate history
    # but the 'cutoff' (days) still applies.
    messages: list[dict] = []

    print(f"    (Fetching messages since {cutoff.strftime('%Y-%m-%d')}...)")

    while url:
        try:
            resp = http_get(url, headers)
        except urllib.error.HTTPError as e:
            error_body = json.loads(e.read().decode())
            raise RuntimeError(f"Graph API error: {error_body}")

        if "value" not in resp:
            raise RuntimeError(f"Graph API error: {resp}")

        page_messages = resp["value"]
        for message in page_messages:
            updated = parse_graph_datetime(message.get("lastModifiedDateTime", ""))
            if updated and updated < cutoff:
                # We stop if we hit the time cutoff
                continue
            messages.append(message)

        # Get next page link
        url = resp.get("@odata.nextLink")

    return messages


def get_organization(token: str) -> list[dict]:
    url = "https://graph.microsoft.com/v1.0/organization?$select=id,displayName,verifiedDomains"
    try:
        resp = http_get(url, {"Authorization": f"Bearer {token}"})
        return resp.get("value", [])
    except Exception:
        return []


# ── Azure ARM API ────────────────────────────────────────────────────────────

def get_arm_token() -> str:
    # 1. Try Azure CLI first (user request)
    cli_token = get_token_from_cli("https://management.azure.com/.default")
    if cli_token:
        return cli_token

    # 2. Fall back to Client Credentials
    url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    data = {
        "client_id":     CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope":         "https://management.azure.com/.default",
        "grant_type":    "client_credentials",
    }
    resp = http_post(url, data, {"Content-Type": "application/x-www-form-urlencoded"})
    if "access_token" not in resp:
        raise RuntimeError(f"ARM token fetch failed: {resp}")
    return resp["access_token"]


def arm_get(url: str, token: str) -> dict:
    return http_get(url, {"Authorization": f"Bearer {token}"}, timeout=60)


def get_azure_resource_context() -> tuple[list[str], list[str]]:
    """Summarize Azure subscriptions/resources and return (lines, provider_list)."""
    print("☁️  Fetching Azure resource context...")
    providers = []
    try:
        arm_token = get_arm_token()
    except Exception as e:
        print(f"  ⚠  Could not get ARM token: {e}")
        return [], []

    try:
        subs_resp = arm_get(
            "https://management.azure.com/subscriptions?api-version=2020-01-01",
            arm_token,
        )
        subscriptions = subs_resp.get("value", [])
    except Exception as e:
        print(f"  ⚠  Could not list Azure subscriptions: {e}")
        return [], []

    enabled_subs = [s for s in subscriptions if s.get("state") == "Enabled"]
    if not enabled_subs:
        return [], []

    total_resources = 0
    provider_counts: Counter[str] = Counter()
    type_counts: Counter[str] = Counter()

    for sub in enabled_subs:
        sub_id = sub.get("subscriptionId")
        if not sub_id:
            continue

        url = (
            f"https://management.azure.com/subscriptions/{sub_id}/resources"
            "?api-version=2021-04-01"
        )

        while url and total_resources < AZURE_RESOURCE_SCAN_LIMIT:
            try:
                data = arm_get(url, arm_token)
            except Exception:
                break

            for resource in data.get("value", []):
                rtype = resource.get("type", "Unknown")
                type_counts[rtype] += 1
                provider = rtype.split("/")[0] if "/" in rtype else rtype
                provider_counts[provider] += 1
                total_resources += 1
                if total_resources >= AZURE_RESOURCE_SCAN_LIMIT:
                    break
            url = data.get("nextLink")

    sub_names = [s.get("displayName", s.get("subscriptionId", "unknown")) for s in enabled_subs]
    top_providers = ", ".join(
        f"{name} ({count})" for name, count in provider_counts.most_common(12)
    )
    top_types = ", ".join(
        f"{name} ({count})" for name, count in type_counts.most_common(20)
    )

    providers = sorted(list(provider_counts.keys()))
    print(f"    Providers      : {len(providers)} discovered ({', '.join(providers[:10])}{'...' if len(providers) > 10 else ''})")
    
    lines = [
        f"Azure Subscriptions: {', '.join(sub_names[:10])}",
        f"Azure Resources Discovered: {total_resources}",
        f"Azure Resource Providers In Use: {top_providers}",
        f"Azure Resource Types In Use: {top_types}",
    ]
    return lines, providers


def get_azure_updates_rss(providers_in_use: list[str], days: int = 30) -> list[dict]:
    """Fetch Azure Updates RSS feed and filter by resource providers in use."""
    print("📰  Fetching Azure product updates (RSS)...")
    
    # Priority-ordered feed URLs
    urls = [
        "https://azurefeeds.com/feed",
        "https://www.microsoft.com/releasecommunications/api/v2/azure/rss",
        "https://azurecomcdn.azureedge.net/en-us/updates/feed/"
    ]
    
    updates = []
    content = ""
    for url in urls:
        try:
            print(f"    (Trying {url}...)")
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
                "Accept": "application/rss+xml, application/xml, text/xml, */*",
                "Accept-Encoding": "gzip, deflate"
            })
            with urllib.request.urlopen(req, timeout=20) as resp:
                content_bytes = resp.read()
                encoding = resp.info().get('Content-Encoding', '').lower()
                if 'gzip' in encoding:
                    try:
                        content_bytes = gzip.decompress(content_bytes)
                    except Exception as e:
                        print(f"      ⚠  Gzip decompression failed: {e}")
                
                try:
                    content = content_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    content = content_bytes.decode("latin-1", errors="ignore")
                
                if "<item>" in content:
                    print(f"    ✅ Successfully fetched from {url}")
                    break
        except Exception as e:
            print(f"    ⚠  Failed to fetch from {url}: {e}")
            continue

    if not content:
        print("    ⚠  Could not fetch any RSS content from available sources.")
        return []

    try:
        # Simple regex-based RSS parsing to avoid external dependencies
        items = re.findall(r"<item>(.*?)</item>", content, re.DOTALL)
        print(f"    (Found {len(items)} total RSS items in feed)")
        cutoff = datetime.now().astimezone() - timedelta(days=days)
        
        lower_providers = [p.lower() for p in providers_in_use]
        # Common providers to always include if they appear
        critical_providers = ['security', 'identity', 'entra', 'governance', 'compliance']
        
        for item in items:
            title_match = re.search(r"<title>(.*?)</title>", item)
            link_match = re.search(r"<link>(.*?)</link>", item)
            pub_date_match = re.search(r"<pubDate>(.*?)</pubDate>", item)
            desc_match = re.search(r"<description>(.*?)</description>", item, re.DOTALL)
            
            title_text = strip_html(title_match.group(1)) if title_match else "Untitled"
            desc_text = strip_html(desc_match.group(1)) if desc_match else ""
            
            # Simple date parsing for RSS format (e.g., "Fri, 17 May 2024 12:00:00 Z")
            pub_at = None
            if pub_date_match:
                date_str = pub_date_match.group(1)
                try:
                    # Support multiple formats
                    # Format 1: "Fri, 17 May 2024 12:00:00 Z"
                    dmatch = re.search(r"(\d{1,2})\s+([A-Za-z]{3})\s+(\d{4})", date_str)
                    if dmatch:
                        day, month, year = dmatch.groups()
                        month_map = {"Jan":1,"Feb":2,"Mar":3,"Apr":4,"May":5,"Jun":6,"Jul":7,"Aug":8,"Sep":9,"Oct":10,"Nov":11,"Dec":12}
                        pub_at = datetime(int(year), month_map[month], int(day)).astimezone()
                except Exception:
                    pass

            if pub_at and pub_at < cutoff:
                continue

            # Check if title or description mentions any of our providers
            # or if it's a general/security announcement
            combined = (title_text + " " + desc_text).lower()
            is_relevant = False
            
            # 1. Check in-use providers
            for p in lower_providers:
                short_p = p.split('.')[-1].lower()
                if len(short_p) > 2 and short_p in combined:
                    is_relevant = True
                    break
            
            # 2. Check critical security/identity themes
            if not is_relevant:
                for cp in critical_providers:
                    if cp in combined:
                        is_relevant = True
                        break
            
            # 3. If no providers discovered yet, include all recent updates
            if not lower_providers:
                is_relevant = True
            
            if is_relevant:
                updates.append({
                    "id": link_match.group(1) if link_match else f"rss-{hash(title_text)}",
                    "title": title_text,
                    "services": ["Azure Updates"],
                    "category": "Product Update",
                    "lastModifiedDateTime": pub_at.isoformat() if pub_at else datetime.now().isoformat(),
                    "startDateTime": pub_at.isoformat() if pub_at else datetime.now().isoformat(),
                    "body": {"content": desc_text},
                    "is_azure_rss": True
                })
    except Exception as e:
        print(f"    ⚠  Failed to parse Azure Updates RSS: {e}")
        
    print(f"    (Found {len(updates)} relevant updates from RSS)")
    return updates


def get_azure_advisor_recommendations(token: str, sub_id: str, days: int = 30) -> list[dict]:
    """Fetch Azure Advisor Security recommendations for a subscription."""
    url = f"https://management.azure.com/subscriptions/{sub_id}/providers/Microsoft.Advisor/recommendations?api-version=2023-01-01&$filter=Category eq 'Security'"
    recommendations = []
    try:
        data = arm_get(url, token)
        for rec in data.get("value", []):
            props = rec.get("properties", {})
            impact = props.get("impact", "Low")
            if impact not in ["High", "Medium"]:
                continue
            
            # Advisor recommendations don't always have a 'published' date, 
            # so we check lastUpdated or metadata
            updated_str = props.get("lastUpdated")
            updated_at = parse_graph_datetime(updated_str) if updated_str else None
            
            cutoff = datetime.now().astimezone() - timedelta(days=days)
            if updated_at and updated_at < cutoff:
                continue

            mapped = {
                "id": rec.get("name"),
                "title": f"Advisor: {props.get('shortDescription', {}).get('problem', 'Security Recommendation')}",
                "services": [props.get("resourceMetadata", {}).get("resourceId", "Azure").split('/')[-1] if '/' in props.get("resourceMetadata", {}).get("resourceId", "") else "Azure"],
                "category": f"Advisor {impact} Security",
                "lastModifiedDateTime": updated_str or datetime.now().isoformat(),
                "startDateTime": updated_str or datetime.now().isoformat(),
                "body": {
                    "content": f"Impact: {impact}\nRecommendation: {props.get('shortDescription', {}).get('solution', 'N/A')}\nDescription: {props.get('extendedProperties', {}).get('description', 'No details available')}"
                },
                "is_azure_advisor": True,
                "subscription_id": sub_id
            }
            recommendations.append(mapped)
    except Exception as e:
        # We don't log every 403 here to avoid noise, as Advisor might not be enabled on all subs
        pass
    return recommendations


def get_azure_service_health_events(token: str, sub_id: str = None, days: int = 90) -> list[dict]:
    """Fetch Azure Service Health events (Security, Maintenance, Informational)."""
    if sub_id:
        url = f"https://management.azure.com/subscriptions/{sub_id}/providers/Microsoft.ResourceHealth/events?api-version=2022-10-01"
    else:
        url = "https://management.azure.com/providers/Microsoft.ResourceHealth/events?api-version=2022-10-01"
    
    events = []
    try:
        data = arm_get(url, token)
        raw_list = data.get("value", [])
            
        for event in raw_list:
            props = event.get("properties", {})
            event_type = props.get("eventType")
            
            if event_type not in ["Security", "Maintenance", "Informational", "Incident", "ActionRequired"]:
                continue

            start_time = parse_graph_datetime(props.get("startTime", ""))
            cutoff = datetime.now().astimezone() - timedelta(days=days)
            if start_time and start_time < cutoff:
                continue
            
            mapped = {
                "id": event.get("name"), 
                "title": props.get("title", "Untitled Azure Event"),
                "services": [props.get("service", "Azure")],
                "category": props.get("eventType", "Unknown"),
                "lastModifiedDateTime": props.get("lastUpdateTime", props.get("startTime")),
                "startDateTime": props.get("startTime"),
                "body": {
                    "content": f"Summary: {props.get('summary', 'No summary provided')}\n\nDetails: {props.get('description', 'No detailed description')}"
                },
                "is_azure": True,
                "subscription_id": sub_id
            }
            events.append(mapped)
    except urllib.error.HTTPError as e:
        if e.code == 403:
            scope = f"sub {sub_id}" if sub_id else "tenant level"
            print(f"    ⚠  403 Forbidden for Service Health at {scope}. Fix: Grant 'Reader' at this scope.")
        else:
            print(f"    ⚠  Failed to fetch events: {e}")
    except Exception as e:
        print(f"    ⚠  Failed to fetch events for sub {sub_id}: {e}")
        
    return events


# ── Tenant Context ────────────────────────────────────────────────────────────

def get_subscribed_skus(token: str) -> list[dict]:
    """Fetch licensed SKUs for the tenant."""
    url = "https://graph.microsoft.com/v1.0/subscribedSkus"
    try:
        resp = http_get(url, {"Authorization": f"Bearer {token}"})
        return resp.get("value", [])
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode()
        except Exception:
            pass
        print(f"  ⚠  Could not fetch subscribed SKUs: HTTP {e.code}")
        if body:
            print(f"     Response: {body[:500]}")
        if e.code == 403:
            print("     Needs Organization.Read.All (Application) with admin consent.")
            print("     In Entra → App registrations → your app → API permissions:")
            print("       1. Add permission → Microsoft Graph → Application → Organization.Read.All")
            print("       2. Click 'Grant admin consent for <tenant>'")
        return []
    except Exception as e:
        print(f"  ⚠  Could not fetch subscribed SKUs: {e}")
        return []


def get_service_usage(token: str) -> dict[str, int]:
    """Fetch active-user counts per service (last 30 days). Returns {service: count}."""
    url = "https://graph.microsoft.com/v1.0/reports/getOffice365ServicesUserCounts(period='D30')"
    # Build a no-redirect opener so we can follow the 302 manually
    opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler)
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        resp = opener.open(req, timeout=30)
        # If we got a redirect, the final URL is a pre-authenticated download
        content = resp.read().decode("utf-8-sig")
        # If Graph returned JSON instead of CSV, it's an error or unexpected
        if content.lstrip().startswith("{"):
            data = json.loads(content)
            print(f"  ⚠  Service usage returned JSON instead of CSV: {json.dumps(data)[:300]}")
            return {}
        reader = csv.DictReader(io.StringIO(content))
        rows = list(reader)
        if not rows:
            return {}
        latest = rows[-1]
        active: dict[str, int] = {}
        for key, val in latest.items():
            if key.endswith(" Active"):
                service = key.replace(" Active", "")
                try:
                    active[service] = int(val)
                except (ValueError, TypeError):
                    pass
        return active
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode()
        except Exception:
            pass
        print(f"  ⚠  Could not fetch service usage: HTTP {e.code}")
        if body:
            print(f"     Response: {body[:500]}")
        if e.code == 403:
            print("     Needs Reports.Read.All (Application) with admin consent.")
            print("     In Entra → App registrations → your app → API permissions:")
            print("       1. Add permission → Microsoft Graph → Application → Reports.Read.All")
            print("       2. Click 'Grant admin consent for <tenant>'")
        elif e.code == 404:
            print("     The reports endpoint was not found. Possible causes:")
            print("     - Reports.Read.All permission not granted or not admin-consented")
            print("     - Reporting is disabled in your tenant (Admin → Settings → Reports)")
            if "UnknownTenantId" in body:
                print("     - Token tenant appears unknown to M365 reports backend")
                print("       Check TENANT_ID in .env and confirm this tenant has M365 reporting enabled")
        return {}
    except Exception as e:
        print(f"  ⚠  Could not fetch service usage: {e}")
        return {}


def build_tenant_context(token: str, services_hint: list[str]) -> tuple[str, list[str]]:
    """Build concise tenant context for the LLM prompt. Returns (context_str, azure_providers)."""
    lines: list[str] = []
    azure_providers: list[str] = []

    print("📋  Fetching tenant context...")

    skus = get_subscribed_skus(token)
    if skus:
        enabled = [s["skuPartNumber"] for s in skus if s.get("capabilityStatus") == "Enabled"]
        if enabled:
            lines.append(f"Subscribed SKUs: {', '.join(sorted(enabled))}")
            print(f"    SKUs           : {len(enabled)} enabled")
        # Collect unique enabled service plan names
        plans: set[str] = set()
        for s in skus:
            if s.get("capabilityStatus") != "Enabled":
                continue
            for sp in s.get("servicePlans", []):
                if sp.get("provisioningStatus") == "Success":
                    plans.add(sp["servicePlanName"])
        if plans:
            lines.append(f"Enabled Service Plans: {', '.join(sorted(plans))}")
            print(f"    Service plans  : {len(plans)} enabled")
        else:
            print("    SKUs           : fetched, but none enabled")
    else:
        print("    SKUs           : unavailable or empty")

    usage = get_service_usage(token)
    if usage:
        in_use = [f"{svc} ({n})" for svc, n in sorted(usage.items()) if n > 0]
        not_in_use = [svc for svc, n in sorted(usage.items()) if n == 0]
        if in_use:
            lines.append(f"Services with Active Users (30 days): {', '.join(in_use)}")
            print(f"    Active services: {len(in_use)}")
        if not_in_use:
            lines.append(f"Services with No Active Users: {', '.join(not_in_use)}")
            print(f"    Inactive svcs  : {len(not_in_use)}")
    else:
        print("    Usage reports  : unavailable")

    azure_lines, azure_providers = get_azure_resource_context()
    if azure_lines:
        lines.extend(azure_lines)
    else:
        print("    Azure context  : unavailable")

    if services_hint:
        lines.append(f"Tenant Service Hints: {', '.join(sorted(services_hint))}")
        print(f"    Service hints  : {len(services_hint)} provided")

    if not lines:
        print("    Tenant context : none available (relevance filtering disabled)")
        return "", []

    return "\n".join(lines), azure_providers


def print_graph_tenant_diagnostics(token: str) -> None:
    claims = decode_jwt_claims(token)
    token_tid = claims.get("tid")
    token_iss = claims.get("iss")
    print("🧾  Graph tenant diagnostics...")
    print(f"    Config TENANT_ID: {TENANT_ID}")
    print(f"    Token tid       : {token_tid or 'unavailable'}")
    if token_iss:
        print(f"    Token issuer    : {token_iss}")

    orgs = get_organization(token)
    if orgs:
        org = orgs[0]
        print(f"    Graph org id    : {org.get('id', 'unavailable')}")
        print(f"    Graph org name  : {org.get('displayName', 'unavailable')}")
    else:
        print("    Graph org info  : unavailable")


# ── Ollama ────────────────────────────────────────────────────────────────────

def list_ollama_models() -> list[str]:
    try:
        resp = http_get(f"{OLLAMA_HOST}/api/tags")
        return [m["name"] for m in resp.get("models", [])]
    except Exception:
        return []


def get_ollama_version() -> str | None:
    try:
        resp = http_get(f"{OLLAMA_HOST}/api/version")
        return resp.get("version")
    except Exception:
        return None


def print_ollama_diagnostics(model: str) -> None:
    print("🔎  Ollama diagnostics...")
    print(f"    Host           : {OLLAMA_HOST}")
    version = get_ollama_version()
    if version:
        print(f"    API version    : {version}")
    else:
        print("    API version    : unavailable")

    models = list_ollama_models()
    if models:
        print(f"    Models visible : {len(models)}")
        if model in models:
            print(f"    Requested model: {model} (found)")
        else:
            print(f"    Requested model: {model} (not found in /api/tags)")
            print(f"    First models   : {', '.join(models[:5])}")
    else:
        print("    Models visible : none")


def verify_ollama_runtime(model: str, timeout: int) -> tuple[bool, str]:
    """Ensure Ollama is reachable, model exists, and a trivial prompt can complete."""
    # First, a quick check of the API and version
    version = get_ollama_version()
    if not version:
        # Retry once with a slight delay in case Ollama is just waking up
        time.sleep(2)
        version = get_ollama_version()
        if not version:
            return False, "Ollama API unavailable"

    models = list_ollama_models()
    if not models:
        return False, "No models visible from Ollama"
    if model not in models:
        return False, f"Model '{model}' not found in /api/tags"

    # The probe triggers the model load. On CPU-only hardware, loading 
    # large models (like Gemma 26B) into RAM can take several minutes.
    probe_prompt = "Reply with exactly: OK"
    
    # We use a generous timeout for the initial probe (at least 10 minutes)
    # and retry a couple of times to be safe.
    probe_timeout = max(timeout, 600)
    max_attempts = 3
    
    for attempt in range(1, max_attempts + 1):
        try:
            if attempt > 1:
                print(f"    (Probe attempt {attempt}/{max_attempts}...)")
            else:
                print(f"    (Sending probe to load model '{model}' — this may take several minutes on CPU...)")
                
            probe = ollama_generate(probe_prompt, model, probe_timeout).strip()
            if probe:
                return True, f"Ollama OK (v{version}, model={model}, probe='{probe[:40]}')"
            else:
                print(f"    ⚠ Probe attempt {attempt} returned empty output.")
        except Exception as e:
            print(f"    ⚠ Probe attempt {attempt} failed: {e}")
            if attempt < max_attempts:
                wait_time = 10 * attempt
                print(f"    Retrying in {wait_time}s...")
                time.sleep(wait_time)
            else:
                return False, f"Probe generation failed after {max_attempts} attempts: {type(e).__name__}: {e}"

    return False, "Probe generation failed (no valid response)"


def ollama_generate(prompt: str, model: str, timeout: int) -> str:
    url = f"{OLLAMA_HOST}/api/generate"
    payload = json.dumps({
        "model":  model,
        "prompt": prompt,
        "stream": True,
        "keep_alive": "30m",
    }).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
    )

    started = time.monotonic()
    chunks = 0
    response_parts = []

    print(f"    Ollama request : POST {url}")
    print(f"    Prompt size    : {len(prompt):,} chars")
    print(f"    Started at     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("    Stream status  : waiting for first token...")

    with urllib.request.urlopen(req, timeout=timeout) as resp:
        while True:
            line = resp.readline()
            if not line:
                break

            decoded = line.decode("utf-8").strip()
            if not decoded:
                continue

            data = json.loads(decoded)
            chunk = data.get("response", "")
            if chunk:
                response_parts.append(chunk)
                chunks += 1

            if data.get("done"):
                break

    return "".join(response_parts).strip()


# ── Analysis ──────────────────────────────────────────────────────────────────

DEFAULT_RISK_RUBRIC = """
High:
- New or expanded cross-boundary data access (e.g., new sources Copilot/agents can ingest; new connectors; new default sharing paths)
- Bypass/weakening of existing controls (labels/DLP/IB/CA) or reduced ability to enforce them
- Material identity/permission model changes (new admin roles, broader default scopes)
- Compliance impact with short timelines (action required soon)

Medium:
- New capability that increases attack surface, but mitigations exist or are configurable
- Control changes are optional / off by default, but likely to be adopted
- Logging/visibility changes that require uplift

Low:
- UI/UX change, non-security feature, or security improvement with no action required
- Changes confined to out-of-scope services
"""


def load_guidance() -> tuple[dict, str]:
    """Load security seed pack and rubric from guidance.json or return a default."""
    guidance_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "guidance.json")
    seed_pack = {
        "org_security_hotspots": [
            {
                "theme": "general_security",
                "description": "General security best practices for M365 and Azure.",
                "escalation": "review"
            }
        ]
    }
    rubric = DEFAULT_RISK_RUBRIC

    if os.path.exists(guidance_path):
        try:
            with open(guidance_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if "org_security_hotspots" in data:
                    seed_pack = {"org_security_hotspots": data["org_security_hotspots"]}
                if "risk_rating_rubric" in data:
                    rubric = data["risk_rating_rubric"]
        except Exception as e:
            print(f"  ⚠  Failed to load guidance.json: {e}")
    
    return seed_pack, rubric


SECURITY_SEED_PACK, RISK_RATING_RUBRIC = load_guidance()

RELEVANCE_ONLY_TEMPLATE = """SYSTEM: 
You are a Senior Information Security Architect specializing in Microsoft 365 and Azure. 
Your task is to **triage** a Microsoft 365 Message Center or Azure Service Update to decide if it has **any** security or compliance implications for the tenant. 
Focus exclusively on security posture changes: if an update is only UI/UX or performance with no effect on data access, user permissions, compliance, or controls, it is **not security relevant**. 
Consider indirect impacts (e.g., new default sharing, cross-tenant connections) and the tenant’s context below. 
Return ONLY valid JSON, no markdown or extra text. Match this schema exactly: 
{{ 
  "relevant": true|false, 
  "security_relevant": true|false, 
  "confidence": 0.0-1.0, 
  "why": "brief reason", 
  "urgency": "ignore|monitor|review|escalate" 
}} 
 
INPUT: 
TITLE: {title} 
SERVICE(S): {services} 
CATEGORY: {category} 
BODY (TRUNCATED): {body} 
 
TENANT_CONTEXT: 
{tenant_context_block} 
"""

PROMPT_TEMPLATE = """SYSTEM:
You are a Senior Information Security Architect and Cyber Security Expert with deep technical knowledge of the Microsoft Cloud security stack (M365, Azure, Purview, Defender, Entra ID).
Analyze the provided Microsoft 365 or Azure update for potential security risks, configuration drifts, or compliance implications.
Consider the provided TENANT_CONTEXT to determine if this change specifically impacts the services and resources currently in use.
Think critically about threat vectors, such as unauthorized data access, privilege escalation, or weakening of existing security controls.
Before providing the final JSON, perform an internal **Adversarial Reasoning** pass:
1. Simulate a **Red Team Attacker**: How would I exploit this change to bypass controls, exfiltrate data, or escalate privileges?
2. Simulate a **Blue Team Defender**: What specific configuration, policy, or monitoring control will mitigate this threat?
Summarize the key takeaway from this debate in the `adversarial_analysis` field below.

**Industry Framework Mapping**: 
For every security implication, identify the most relevant:
- **MITRE ATT&CK Technique**: (e.g., T1078 - Valid Accounts, T1567 - Exfiltration Over Web Service).
- **NIST CSF Control**: (e.g., PR.AC-4 - Information flow is controlled, ID.RA-1 - Asset vulnerabilities are identified).
Include these in the `framework_mapping` section of each implication.

If the update **does not introduce any notable risk**
 (no new data access, no control/policy changes), you must still produce a valid JSON output, but keep `security_implications` minimal (e.g. one entry noting "No significant security changes") and set `risk_rating`: "Low". It’s better to clearly indicate a trivial impact than to overstate risks or leave required fields empty.
**Important**: Apply the RISK_RATING_RUBRIC strictly when choosing `risk_rating`. Never label an update as "High" unless it clearly matches the **High** criteria (e.g., new cross-boundary access or major control bypass). Routine or cosmetic changes must be "Low". If a change **improves security** (e.g., stricter auth), it should also be "Low" (with a positive rationale). Avoid exaggerating minor changes as major risks.
Ensure all strings in the JSON are correctly escaped (e.g., use double quotes and escape internal quotes).
Return ONLY valid JSON. No markdown.

{seed_pack}

{risk_rubric}

Return JSON exactly matching this schema:
{{
  "meta": {{
    "message_id": "{message_id}",
    "title": "{title}"
  }},
  "plain_english_summary": "2-3 sentences",
  "what_changed": ["bullet strings"],
  "adversarial_analysis": "Summary of Red/Blue team reasoning debate",
  "security_implications": [
    {{
      "theme": "data_access_change|copilot_agentic|dlp_labeling|dlp_labeling_control_plane|data_persistence|identity_permissions|external_sharing|audit_logging|compliance_retention|other",
      "impact": "what could happen",
      "evidence": "quote snippet",
      "framework_mapping": {{
        "mitre_attack": ["ID and Name"],
        "nist_csf": ["Control ID and Name"]
      }}
    }}
  ],
  "recommended_actions": [
    {{
      "action": "imperative verb phrase",
      "owner": "team",
      "when": "now|monitor",
      "effort": "S|M|L"
    }}
  ],
  "risk_rating": "Low|Medium|High",
  "risk_rationale": "one sentence tied to rubric"
}}

INPUT:
TITLE: {title}
SERVICE(S): {services}
UPDATE_CONTENT:
{body}

TENANT_CONTEXT:
{tenant_context_block}
"""


def assess_relevance(message: dict, model: str, ollama_timeout: int,
                     tenant_context: str = "") -> tuple[bool, str]:
    body = strip_html(message.get("body", {}).get("content", ""))
    if len(body) > 1200:
        body = body[:1200] + "... [truncated]"

    ctx_block = f"TENANT CONTEXT:\n{tenant_context}" if tenant_context else "No tenant context available."
    prompt = RELEVANCE_ONLY_TEMPLATE.format(
        seed_pack=json.dumps(SECURITY_SEED_PACK, indent=2),
        risk_rubric=RISK_RATING_RUBRIC,
        title=message.get("title", "Unknown"),
        services=", ".join(message.get("services", [])) or "Unknown",
        category=message.get("category", "Unknown"),
        tenant_context_block=ctx_block,
        body=body,
    )

    raw = ollama_generate(prompt, model, ollama_timeout)

    # Try strict JSON first, then fallback to extracting first JSON object.
    parsed = None
    try:
        parsed = json.loads(raw)
    except Exception:
        match = re.search(r"\{.*\}", raw, flags=re.DOTALL)
        if match:
            try:
                parsed = json.loads(match.group(0))
            except Exception:
                parsed = None

    if isinstance(parsed, dict):
        # Use 'relevant' or 'security_relevant' as the decision.
        relevant = bool(parsed.get("relevant") or parsed.get("security_relevant"))
        # 'why' is the new field for reasoning.
        reason = str(parsed.get("why") or parsed.get("reason", "")).strip() or "No reason provided"
        return relevant, reason

    lowered = raw.lower()
    if "not relevant" in lowered:
        return False, "Model indicated not relevant"
    if "relevant" in lowered:
        return True, "Model indicated relevant"
    return True, "Could not parse relevance output; defaulting to relevant"


def analyze_message(message: dict, model: str, ollama_timeout: int,
                    tenant_context: str = "") -> str:
    body = strip_html(message.get("body", {}).get("content", ""))
    original_body_length = len(body)
    # Trim body to avoid blowing out context window on smaller models
    if len(body) > 3000:
        body = body[:3000] + "... [truncated]"

    ctx_block = f"TENANT CONTEXT:\n{tenant_context}" if tenant_context else "No tenant context available."

    prompt = PROMPT_TEMPLATE.format(
        seed_pack=json.dumps(SECURITY_SEED_PACK, indent=2),
        risk_rubric=RISK_RATING_RUBRIC,
        title=message.get("title", "Unknown"),
        message_id=message.get("id", "Unknown"),
        services=", ".join(message.get("services", [])) or "Unknown",
        tenant_context_block=ctx_block,
        body=body,
    )
    print(f"    Body size      : {original_body_length:,} chars ({len(body):,} sent to model)")
    return ollama_generate(prompt, model, ollama_timeout)


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Analyse M365 Message Center posts for security implications using Ollama."
    )
    parser.add_argument(
        "-n", "--count", type=int, default=5,
        help="Number of latest messages to analyse after date/filtering (default: 5, use 0 for all)"
    )
    parser.add_argument(
        "-m", "--model", type=str, default=None,
        help=f"Ollama model to use (default: {OLLAMA_MODEL} from .env, or auto-detect)"
    )
    parser.add_argument(
        "--list-models", action="store_true",
        help="List available Ollama models and exit"
    )
    parser.add_argument(
        "--filter", type=str, default=None,
        help="Only analyse messages whose title contains this string (case-insensitive)"
    )
    parser.add_argument(
        "--days", type=int, default=90,
        help="Only analyse messages updated in the last N days (default: 90)"
    )
    parser.add_argument(
        "--ollama-timeout", type=int, default=OLLAMA_TIMEOUT,
        help=(
            "Seconds to wait for each Ollama response "
            f"(default: {OLLAMA_TIMEOUT}; env: OLLAMA_TIMEOUT)"
        )
    )
    parser.add_argument(
        "--relevance-timeout", type=int, default=OLLAMA_RELEVANCE_TIMEOUT,
        help=(
            "Seconds to wait for the short relevance pass "
            f"(default: {OLLAMA_RELEVANCE_TIMEOUT}; env: OLLAMA_RELEVANCE_TIMEOUT)"
        )
    )
    parser.add_argument(
        "--services-hint", type=str, default=TENANT_SERVICES_HINT,
        help=(
            "Comma-separated list of services you actually use (fallback when Graph "
            "SKU/usage APIs are unavailable), e.g. 'Exchange,Teams,SharePoint'"
        )
    )
    parser.add_argument(
        "--output", type=str, default=OUTPUT_FILE,
        help=f"Write console output to a text file as well (default: {OUTPUT_FILE})"
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Force analysis even if it already exists in the database (overwrites existing)"
    )
    return parser.parse_args()


def pick_model(requested: str) -> str:
    """Use requested model, fall back to .env, then auto-detect from Ollama."""
    if requested:
        return requested
    if OLLAMA_MODEL:
        return OLLAMA_MODEL
    models = list_ollama_models()
    if not models:
        raise RuntimeError(
            "No Ollama models found. Pull one first, e.g.: ollama pull llama3.2"
        )
    print(f"  Auto-detected Ollama model: {models[0]}")
    return models[0]


def separator():
    print("\n" + "═" * 72)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()
    original_stdout = sys.stdout
    original_stderr = sys.stderr
    log_handle = None

    if args.output:
        log_handle = open(args.output, "w", encoding="utf-8", buffering=1)
        sys.stdout = TeeStream(original_stdout, log_handle)
        sys.stderr = TeeStream(original_stderr, log_handle)

    try:
        # List models mode
        if args.list_models:
            models = list_ollama_models()
            if models:
                print("Available Ollama models:")
                for m in models:
                    print(f"  • {m}")
            else:
                print("No models found — is Ollama running?")
            sys.exit(0)

        # Validate config
        missing = [k for k in ("TENANT_ID", "CLIENT_ID", "CLIENT_SECRET") if not os.getenv(k)]
        if missing:
            print(f"❌  Missing env vars: {', '.join(missing)}")
            print("    Copy .env.example to .env and fill in your values.")
            sys.exit(1)

        model = pick_model(args.model)

        print(f"🤖  Model  : {model}  ({OLLAMA_HOST})")
        print(f"⏱️  Timeout: {args.ollama_timeout}s per message")
        print(f"⚡  Relevance pass timeout: {args.relevance_timeout}s")
        count_text = "all" if args.count <= 0 else str(args.count)
        print(f"📊  Count  : {count_text} messages")
        print(f"🗓️  Window : last {args.days} days")
        print(f"📝  Output : {args.output}")
        if args.filter:
            print(f"🔎  Filter : \"{args.filter}\"")
        if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
            print(f"📨  Telegram: enabled (chat {TELEGRAM_CHAT_ID})")
        elif TELEGRAM_BOT_TOKEN:
            print("📨  Telegram: token set but TELEGRAM_CHAT_ID missing — notifications disabled")
        else:
            print("📨  Telegram: not configured")
        if LAST_RUN_TIME_STR:
            print(f"🕐  Last run : {LAST_RUN_TIME_STR}")
        else:
            print("🕐  Last run : first run (no LAST_RUN_TIME set)")
        print_ollama_diagnostics(model)
        
        if DATABASE_URL or LOCAL_DATABASE_URL:
            init_db()
            sync_databases()
        
        print("🧪  Checking LLM dependency...")
        llm_ok, llm_status = verify_ollama_runtime(model, args.relevance_timeout)
        if llm_ok:
            print(f"    {llm_status}")
        else:
            print(f"  ❌  LLM dependency check failed: {llm_status}")
            send_dependency_alert("Ollama", f"{llm_status}; host={OLLAMA_HOST}", model=model)
            sys.exit(1)

        print("\n🔐  Getting Graph API token...")
        try:
            token = get_graph_token()
        except Exception as e:
            send_dependency_alert("Microsoft Graph", f"Token fetch failed: {type(e).__name__}: {e}")
            raise
        print_graph_tenant_diagnostics(token)

        services_hint = parse_services_hint(args.services_hint)
        # Always treat Microsoft 365 Copilot as in use, even if SKU/usage APIs are incomplete.
        forced_seen = {s.casefold() for s in services_hint}
        for forced_service in FORCED_TENANT_SERVICES:
            if forced_service.casefold() not in forced_seen:
                services_hint.append(forced_service)
                forced_seen.add(forced_service.casefold())
        tenant_context, azure_providers = build_tenant_context(token, services_hint)

        last_run_dt: datetime | None = None
        if LAST_RUN_TIME_STR:
            try:
                last_run_dt = datetime.fromisoformat(LAST_RUN_TIME_STR)
            except ValueError:
                print(f"  ⚠  Could not parse LAST_RUN_TIME '{LAST_RUN_TIME_STR}', ignoring")
        run_started_at = datetime.now().astimezone()
        ollama_alert_sent = False

        print("📬  Fetching Message Center messages...")
        try:
            m365_messages = get_messages(token, days=args.days, since=last_run_dt)
        except Exception as e:
            send_dependency_alert("Microsoft Graph", f"Message fetch failed: {type(e).__name__}: {e}")
            raise

        print("☁️  Fetching Azure Service Health & Advisor events...")
        azure_messages = []
        try:
            arm_token = get_arm_token()
            # Try tenant-level first (global advisories)
            tenant_events = get_azure_service_health_events(arm_token, days=args.days)
            azure_messages.extend(tenant_events)
            
            subs_resp = arm_get("https://management.azure.com/subscriptions?api-version=2020-01-01", arm_token)
            enabled_subs = [s for s in subs_resp.get("value", []) if s.get("state") == "Enabled"]
            for sub in enabled_subs:
                sub_id = sub.get("subscriptionId")
                sub_name = sub.get("displayName", sub_id)
                print(f"    Sub: {sub_name}...")
                sub_events = get_azure_service_health_events(arm_token, sub_id, days=args.days)
                azure_messages.extend(sub_events)
                
                # Fetch Advisor Security recommendations
                advisor_recs = get_azure_advisor_recommendations(arm_token, sub_id, days=args.days)
                if advisor_recs:
                    print(f"      (Found {len(advisor_recs)} Advisor security recommendations)")
                    azure_messages.extend(advisor_recs)
        except Exception as e:
            print(f"  ⚠  Azure event fetch failed: {e}")

        # Fetch Azure Updates RSS
        rss_updates = get_azure_updates_rss(azure_providers, days=args.days)
        azure_messages.extend(rss_updates)

        all_messages = m365_messages + azure_messages
        # Sort by updated time descending
        all_messages.sort(key=lambda x: x.get("lastModifiedDateTime", ""), reverse=True)

        if args.filter:
            all_messages = [m for m in all_messages if args.filter.lower() in m.get("title", "").lower()]
            print(f"    {len(all_messages)} messages match filter.")

        batch = all_messages if args.count <= 0 else all_messages[: args.count]
        print(f"    Analysing {len(batch)} of {len(all_messages)} fetched ({len(m365_messages)} M365, {len(azure_messages)} Azure/RSS).\n")

        if not batch:
            no_new_note = "\n".join([
                "✅ M365 Message Center check complete",
                "",
                "Result: no new entries found.",
                f"Window: last {args.days} days",
                f"Since: {LAST_RUN_TIME_STR or 'first run baseline'}",
                f"LLM: {llm_status}",
            ])
            send_telegram_message(no_new_note)
            print("📨  Telegram heartbeat sent (no new items).")

        separator()
        skipped = 0

        for i, msg in enumerate(batch, 1):
            title    = msg.get("title", "Untitled")
            services = ", ".join(msg.get("services", [])) or "Unknown"
            updated  = msg.get("lastModifiedDateTime", "")
            msg_id   = msg.get("id", "")

            print(f"\n[{i}/{len(batch)}] {title}")
            print(f"  Service : {services}")
            print(f"  Updated : {updated}")
            print(f"  ID      : {msg_id}\n")

            if DATABASE_URL and check_analysis_exists(msg_id) and not args.force:
                print(f"    ⏭  Skipping (already analyzed in database)")
                skipped += 1
                separator()
                continue

            print("⚡  Relevance check...\n")

            try:
                is_relevant, relevance_reason = assess_relevance(
                    msg,
                    model,
                    min(args.relevance_timeout, args.ollama_timeout),
                    tenant_context,
                )
            except Exception as e:
                is_relevant, relevance_reason = True, f"Relevance check failed ({e}); defaulting to relevant"

            if not is_relevant:
                print(f"ℹ️  Relevance says not relevant: {relevance_reason}")
                print("   Skipping detailed analysis.")
                if DATABASE_URL:
                    triage_json = json.dumps({
                        "meta": {
                            "message_id": msg_id,
                            "title": title
                        },
                        "plain_english_summary": f"Triage filtered this message: {relevance_reason}",
                        "status": "Skipped (Not Relevant)",
                        "risk_rating": "Informational",
                        "risk_rationale": "Filtered out during initial relevance triage."
                    })
                    save_analysis(msg_id, title, msg.get("services", []), msg.get("startDateTime"), updated, triage_json, "Informational", model)
                separator()
                continue
            else:
                print(f"✅  Relevant: {relevance_reason}")
            print("🔍  Analysing...\n")

            started = time.monotonic()
            try:
                analysis = analyze_message(msg, model, args.ollama_timeout, tenant_context)
                print(analysis)
                print(f"\n    Analysis time  : {format_duration(time.monotonic() - started)}")

                # Extract risk rating for DB
                risk_rating = "Unknown"
                try:
                    parsed = json.loads(analysis)
                    risk_rating = parsed.get("risk_rating", "Unknown")
                except Exception:
                    # Fallback to keyword search
                    match = re.search(r"\"risk_rating\":\s*\"(.*?)\"", analysis)
                    if match:
                        risk_rating = match.group(1)

                if DATABASE_URL:
                    save_analysis(msg_id, title, msg.get("services", []), msg.get("startDateTime"), updated, analysis, risk_rating, model)

                if has_security_implications(analysis):
                    tg_text = build_telegram_message(msg, analysis)
                    send_telegram_message(tg_text)
                    print("  📨  Telegram notification sent.")
                else:
                    print("  ℹ️  No Telegram notification (no material security implications detected).")
            except KeyboardInterrupt:
                print("\n  ⏹  Cancelled by user.")
                break
            except (TimeoutError, socket.timeout) as e:
                elapsed = format_duration(time.monotonic() - started)
                print(f"  ⚠  Ollama socket timeout after {elapsed}: {e}")
                print(f"     Host={OLLAMA_HOST} Model={model} Timeout={args.ollama_timeout}s")
                print("     If no chunks were logged, the model likely did not produce any bytes before the socket timeout.")
                if not ollama_alert_sent:
                    send_dependency_alert(
                        "Ollama",
                        f"Socket timeout after {elapsed}; host={OLLAMA_HOST}; timeout={args.ollama_timeout}s",
                        model=model,
                    )
                    ollama_alert_sent = True
            except urllib.error.URLError as e:
                elapsed = format_duration(time.monotonic() - started)
                print(f"  ⚠  Ollama connection error after {elapsed}: {e.reason}")
                print(f"     Is Ollama running? Try: ollama serve")
                if not ollama_alert_sent:
                    send_dependency_alert(
                        "Ollama",
                        f"Connection error after {elapsed}: {e.reason}; host={OLLAMA_HOST}",
                        model=model,
                    )
                    ollama_alert_sent = True
            except Exception as e:
                elapsed = format_duration(time.monotonic() - started)
                error_msg = f"Analysis failed after {elapsed}: {type(e).__name__}: {e}"
                print(f"  ⚠  {error_msg}")
                if DATABASE_URL:
                    error_json = json.dumps({
                        "meta": {"message_id": msg_id, "title": title},
                        "status": "Error",
                        "error_details": error_msg,
                        "risk_rating": "Error"
                    })
                    save_analysis(msg_id, title, msg.get("services", []), msg.get("startDateTime"), updated, error_json, "Error", model)
                if not ollama_alert_sent:
                    send_dependency_alert(
                        "Ollama",
                        f"Analysis failure after {elapsed}: {type(e).__name__}: {e}",
                        model=model,
                    )
                    ollama_alert_sent = True

            separator()

        analysed = len(batch) - skipped
        print(f"\n✅  Done — {analysed} analysed, {skipped} skipped (from {len(batch)}).")
        update_env_value("LAST_RUN_TIME", run_started_at.isoformat())
        print(f"🕐  LAST_RUN_TIME updated in .env")
    finally:
        sys.stdout = original_stdout
        sys.stderr = original_stderr
        if log_handle is not None:
            log_handle.close()


if __name__ == "__main__":
    main()
