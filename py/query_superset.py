#!/usr/bin/env python3
"""
Query Superset - SQL query tool with schema discovery, caching, and multi-format output.

Usage:
    python py/query_superset.py --sql "SELECT * FROM table LIMIT 10"
    python py/query_superset.py --sql "SELECT * FROM table" --output-file result.csv
    python py/query_superset.py --list-datasource
    python py/query_superset.py --list-databases --datasource-id 4
    python py/query_superset.py --list-tables --datasource-id 4 --database warehouse
    python py/query_superset.py --describe table_name
    python py/query_superset.py --show-create table_name
    python py/query_superset.py --history

Build (package to dist/ and skills/query-superset/):
    ./py/build.sh

Configuration Priority:
    1. Command line args: --username / --password
    2. Environment vars: SUPERSET_USERNAME / SUPERSET_PASSWORD
    3. OS keychain (Credential Manager / Keychain / libsecret)
    4. Config file (Fernet-encrypted fallback):
       - Linux: ~/.config/superset-cli/config.json
       - Windows: %APPDATA%/superset-cli/config.json
    5. Interactive prompt (first-time setup: login test + datasource selection)
"""

import argparse
import csv
import getpass
import hashlib
import json
import os
import re
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

try:
    import requests
except ImportError:
    print("Error: requests library not installed")
    print("Run: pip install requests")
    sys.exit(1)

try:
    from cryptography.fernet import Fernet
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    import keyring as _keyring_mod
    HAS_KEYRING = True
except ImportError:
    HAS_KEYRING = False

FERNET_PREFIX = "$fernet_v1$"

DEFAULT_SUPERSET_URL = "http://43.138.226.32:8787"

def get_superset_url():
    cfg = load_config()
    url = cfg.get("superset_url")
    if url:
        return url.rstrip("/")
    return (os.getenv("SUPERSET_URL") or DEFAULT_SUPERSET_URL).rstrip("/")
DEFAULT_TIMEOUT = 180
DEFAULT_PAGE_SIZE = 1000
HISTORY_MAX = 50

_config_datasource_id = None

# 元数据查询时排除的数据库名称（不返回这些库的表/结构信息）
EXCLUDED_DATABASES = {"bigdata", "bigdata_test", "ods", "warehouse", "warehouse_test"}
MAX_SETUP_ATTEMPTS = 3


class SupersetError(Exception):
    """Base error for Superset CLI."""


class NetworkError(SupersetError):
    """Network/connectivity failure."""


class AuthError(SupersetError):
    """Invalid username or password."""


class AccessDeniedError(SupersetError):
    """Authenticated but lacking permission for the requested resource."""


def get_config_dir():
    if sys.platform == "win32":
        return Path(os.environ.get("APPDATA", "~")) / "superset-cli"
    return Path.home() / ".config" / "superset-cli"


def get_config_file():
    return get_config_dir() / "config.json"


_FERNET_KEY = b"EwJ_JKzzZ4vs4pwWBmuLhvDtR919AfKAU--rd7v91S8="

def encrypt_password(plain):
    if not HAS_CRYPTO:
        print("Warning: cryptography not installed, password stored in plaintext", file=sys.stderr)
        return plain
    try:
        f = Fernet(_FERNET_KEY)
        token = f.encrypt(plain.encode())
        return FERNET_PREFIX + token.decode()
    except Exception as e:
        print(f"Warning: encryption failed ({e}), password stored in plaintext", file=sys.stderr)
        return plain

def decrypt_password(encrypted):
    if not encrypted or not encrypted.startswith(FERNET_PREFIX):
        return encrypted
    if not HAS_CRYPTO:
        print("Error: cryptography not installed – cannot decrypt password", file=sys.stderr)
        print("Run: pip install cryptography", file=sys.stderr)
        return None
    try:
        token = encrypted[len(FERNET_PREFIX):]
        f = Fernet(_FERNET_KEY)
        return f.decrypt(token.encode()).decode()
    except Exception as e:
        print(f"Error: failed to decrypt password ({e})", file=sys.stderr)
        return None

def _keyring_set(service, username, password):
    if not HAS_KEYRING:
        return False
    try:
        _keyring_mod.set_password(service, username, password)
        return True
    except Exception as e:
        print(f"Warning: OS keychain write failed ({e}), falling back to file encryption", file=sys.stderr)
        return False

def _keyring_get(service, username):
    if not HAS_KEYRING:
        return None
    try:
        return _keyring_mod.get_password(service, username)
    except Exception as e:
        print(f"Warning: OS keychain read failed ({e}), trying config file", file=sys.stderr)
        return None

def _keyring_delete(service, username):
    if not HAS_KEYRING:
        return
    try:
        _keyring_mod.delete_password(service, username)
    except Exception:
        pass

KEYRING_SERVICE = "superset-cli"

def load_config():
    config_file = get_config_file()
    if config_file.exists():
        try:
            with open(config_file) as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    return {}


def get_default_datasource_id():
    global _config_datasource_id
    if _config_datasource_id is None:
        cfg = load_config()
        _config_datasource_id = cfg.get("datasource_id") or int(
            os.getenv("SUPERSET_DATASOURCE_ID", "4")
        )
    return _config_datasource_id


def _write_secure_json(path, data):
    """Write JSON with 600 permission (owner read/write only)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    try:
        path.chmod(0o600)
    except Exception:
        pass

def save_config(username=None, password=None, datasource_id=None, superset_url=None):
    config_file = get_config_dir() / "config.json"
    cfg = load_config()

    # If username changed, clean old keyring entry (if any)
    old_user = cfg.get("username")
    if password is not None and username is not None and username != old_user:
        _keyring_delete(KEYRING_SERVICE, old_user)

    if username is not None:
        cfg["username"] = username

    if password is not None:
        if username is not None and _keyring_set(KEYRING_SERVICE, username, password):
            # success: remove any legacy file-encrypted password
            cfg.pop("password", None)
        else:
            # fallback: Fernet encryption in config.json
            cfg["password"] = encrypt_password(password)

    if datasource_id is not None:
        cfg["datasource_id"] = datasource_id

    if superset_url is not None:
        cfg["superset_url"] = superset_url.rstrip("/")

    _write_secure_json(config_file, cfg)
    print(f"Configuration saved to: {config_file}")


def setup_wizard():
    print("=" * 50)
    print("Superset CLI - First Time Setup")
    print("=" * 50)

    for attempt in range(1, MAX_SETUP_ATTEMPTS + 1):
        if attempt > 1:
            print(f"\n--- 第 {attempt}/{MAX_SETUP_ATTEMPTS} 次尝试 ---")

        username = input("Superset username: ").strip()
        password = getpass.getpass("Superset password: ").strip()
        if not username or not password:
            print("Error: 用户名和密码不能为空")
            continue

        session = requests.Session()
        try:
            print("\n正在验证账号并获取可用数据源...")
            login(session, username, password)
            datasources = fetch_datasources(session, DEFAULT_TIMEOUT)
            if not datasources:
                print("Error: 账号验证成功，但未找到可用数据源，请检查 Superset 权限")
                sys.exit(1)

            datasource_id = prompt_datasource_choice(datasources)
            save_config(username, password, datasource_id)
            save_cookies(session)

            global _config_datasource_id
            _config_datasource_id = datasource_id

            selected = next(ds for ds in datasources if ds["id"] == datasource_id)
            print(
                f"\nSetup complete. Default datasource: ID={datasource_id} "
                f"({selected['name']}, {selected['backend']})"
            )
            return username, password
        except AuthError as e:
            print(f"Error: {e}")
            if attempt >= MAX_SETUP_ATTEMPTS:
                print(f"已达到最大尝试次数（{MAX_SETUP_ATTEMPTS} 次），退出")
                sys.exit(1)
            print("请重新输入账号和密码")
        except NetworkError as e:
            print(f"Error: 网络错误 - {e}")
            sys.exit(1)
        except AccessDeniedError as e:
            print(f"Error: {e}")
            sys.exit(1)
        finally:
            session.close()

    print(f"已达到最大尝试次数（{MAX_SETUP_ATTEMPTS} 次），退出")
    sys.exit(1)


def reauth_wizard():
    """Prompt for new credentials when auth fails. Returns (username, password)."""
    print("\n===== 认证失败，请重新输入账号和密码 =====")
    for attempt in range(1, MAX_SETUP_ATTEMPTS + 1):
        if attempt > 1:
            print(f"\n--- 第 {attempt}/{MAX_SETUP_ATTEMPTS} 次尝试 ---")

        username = input("Superset username: ").strip()
        password = getpass.getpass("Superset password: ").strip()
        if not username or not password:
            print("用户名和密码不能为空")
            continue

        session = requests.Session()
        try:
            login(session, username, password)
            save_config(username, password)
            session.close()
            print("认证成功，凭据已保存")
            return username, password
        except AuthError as e:
            print(f"Error: {e}")
        except NetworkError as e:
            print(f"Error: 网络错误 - {e}")
            sys.exit(1)
        finally:
            session.close()

    print(f"已达到最大尝试次数（{MAX_SETUP_ATTEMPTS} 次），退出")
    sys.exit(1)


def get_credentials(args):
    username = args.username or os.getenv("SUPERSET_USERNAME")
    password = args.password or os.getenv("SUPERSET_PASSWORD")
    if username and password:
        return username, password

    config = load_config()
    username = username or config.get("username")

    # Try OS keychain first
    if not password and username:
        password = _keyring_get(KEYRING_SERVICE, username)

    # Fallback: config file (Fernet-encrypted or legacy plaintext)
    if not password:
        p = config.get("password")
        if p:
            password = decrypt_password(p)

    if username and password:
        return username, password
    return setup_wizard()


def get_csrf_token(session):
    try:
        resp = session.get(f"{get_superset_url()}/login/", timeout=DEFAULT_TIMEOUT)
    except requests.RequestException as e:
        raise NetworkError(f"无法连接 Superset（{get_superset_url()}）: {e}") from e

    if resp.status_code != 200:
        raise NetworkError(f"无法访问登录页，HTTP {resp.status_code}")

    match = re.search(r'id="csrf_token"[^>]*value="([^"]+)"', resp.text)
    if match:
        return match.group(1)
    match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', resp.text)
    if match:
        return match.group(1)
    raise NetworkError("无法从登录页获取 CSRF token，请检查 Superset 服务状态")


def get_csrf_token_sqllab(session):
    resp = session.get(f"{get_superset_url()}/sqllab/")
    if resp.status_code == 200:
        match = re.search(r'id="csrf_token"[^>]*value="([^"]+)"', resp.text)
        if match:
            return match.group(1)
    return None


def login(session, username, password):
    csrf_token = get_csrf_token(session)

    login_data = {"username": username, "password": password}
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-CSRF-Token": csrf_token,
        "Referer": f"{get_superset_url()}/login/",
    }
    try:
        resp = session.post(
            f"{get_superset_url()}/login/",
            data=login_data,
            headers=headers,
            allow_redirects=False,
            timeout=DEFAULT_TIMEOUT,
        )
    except requests.RequestException as e:
        raise NetworkError(f"登录请求失败: {e}") from e

    if resp.status_code == 401:
        raise AuthError("账号或密码错误")
    if resp.status_code not in (200, 302):
        raise NetworkError(f"登录请求异常，HTTP {resp.status_code}")

    if not session_valid(session):
        raise AuthError("账号或密码错误")
    return session


def save_cookies(session):
    cookies = requests.utils.dict_from_cookiejar(session.cookies)
    _write_secure_json(get_config_dir() / "cookies.json", cookies)


def load_cookies(session):
    cookie_file = get_config_dir() / "cookies.json"
    try:
        with open(cookie_file) as f:
            cookies = json.load(f)
        session.cookies = requests.utils.cookiejar_from_dict(cookies)
        return True
    except (FileNotFoundError, json.JSONDecodeError):
        return False


def session_valid(session):
    try:
        resp = session.get(f"{get_superset_url()}/api/v1/database/", timeout=10)
        return resp.status_code == 200
    except requests.RequestException:
        return False


def request_json(session, method, url, **kwargs):
    """HTTP helper that maps request failures to typed errors."""
    try:
        resp = session.request(method, url, **kwargs)
    except requests.RequestException as e:
        raise NetworkError(f"请求失败: {e}") from e
    return resp


def ensure_login(session, username, password, force=False):
    if not force and load_cookies(session) and session_valid(session):
        print("Using cached session")
        return
    print("Logging in to Superset...")
    login(session, username, password)
    save_cookies(session)
    print("Session saved")


# ── Schema Discovery ──────────────────────────────────────────────────────────

def fetch_datasources(session, timeout, show_excluded=False):
    """Fetch datasource metadata from Superset. Returns a list of dicts."""
    resp = request_json(
        session,
        "GET",
        f"{get_superset_url()}/api/v1/database/",
        headers={"Referer": f"{get_superset_url()}/sqllab/"},
        timeout=timeout,
    )
    if resp.status_code in (401, 403):
        raise AccessDeniedError("账号已验证，但无权获取数据源列表")
    if resp.status_code != 200:
        raise NetworkError(f"获取数据源列表失败，HTTP {resp.status_code}")

    ids = resp.json().get("ids", [])
    if not ids:
        return []

    datasources = []
    for db_id in ids:
        r = request_json(
            session,
            "GET",
            f"{get_superset_url()}/api/v1/database/{db_id}",
            headers={"Referer": f"{get_superset_url()}/sqllab/"},
            timeout=timeout,
        )
        if r.status_code in (401, 403):
            raise AccessDeniedError(f"账号已验证，但无权读取数据源 ID={db_id}")
        if r.status_code != 200:
            continue
        info = r.json().get("result", {})
        name = info.get("database_name", "?")
        backend = info.get("backend", "?")
        excluded = name.lower() in EXCLUDED_DATABASES
        if excluded and not show_excluded:
            continue
        datasources.append(
            {"id": db_id, "name": name, "backend": backend, "excluded": excluded}
        )

    datasources.sort(key=lambda ds: ds["id"])
    return datasources


def print_datasources(datasources, title="可用数据源"):
    if not datasources:
        print("No data sources found")
        return
    print(f"\n{title}")
    print("-" * 50)
    for i, ds in enumerate(datasources, 1):
        flag = " [excluded]" if ds.get("excluded") else ""
        print(f"  [{i}] ID={ds['id']}: {ds['name']} ({ds['backend']}){flag}")
    print(f"\n数据源 IDs: {[ds['id'] for ds in datasources]}")


def prompt_datasource_choice(datasources):
    """Interactive prompt to pick a default datasource ID."""
    print_datasources(datasources, title="可用数据源（请选择默认数据源）")

    env_default = os.getenv("SUPERSET_DATASOURCE_ID")
    default_id = None
    if env_default and str(env_default).isdigit():
        env_default = int(env_default)
        if any(ds["id"] == env_default for ds in datasources):
            default_id = env_default
    if default_id is None:
        default_id = datasources[0]["id"]

    id_set = {ds["id"] for ds in datasources}
    while True:
        prompt = (
            f"\n选择默认数据源 [1-{len(datasources)}]，"
            f"或直接输入 ID（回车默认 ID={default_id}）: "
        )
        choice = input(prompt).strip()
        if not choice:
            return default_id
        if choice.isdigit():
            value = int(choice)
            if value in id_set:
                return value
            if 1 <= value <= len(datasources):
                return datasources[value - 1]["id"]
        print("无效选择，请重试")


def list_databases(session, timeout, show_excluded=False):
    datasources = fetch_datasources(session, timeout, show_excluded=show_excluded)
    print_datasources(datasources)
    sys.exit(0)


def list_tables(session, datasource_id, timeout, database_name=None, output_format="md"):
    """List tables using SQL SHOW TABLES command."""
    sql = "SHOW TABLES" if not database_name else f"SHOW TABLES IN {database_name}"
    result = execute_sql(session, sql, datasource_id, timeout)
    columns, rows = parse_results(result)
    if not rows:
        print("No tables found")
        return
    # Extract table names from rows
    table_rows = []
    for row in rows:
        if isinstance(row, dict):
            val = list(row.values())[0] if row else ""
        else:
            val = str(row) if row else ""
        table_rows.append({"table": val})
    table_rows.sort(key=lambda r: r["table"])
    print_table(table_rows, columns=["table"], fmt=output_format, title=f"Tables (datasource={datasource_id}, database={database_name or 'default'})")


def describe_table(session, table_name, database_id, timeout, output_format="md"):
    # Parse table name: catalog.db.table, db.table, or bare table
    parts = table_name.split(".")
    if len(parts) == 3:
        catalog, schema, tbl = parts
    elif len(parts) == 2:
        schema, tbl = parts
        catalog = None
    else:
        tbl = parts[0]
        catalog = schema = None

    # Build WHERE from parsed name parts
    filters = []
    if tbl:
        filters.append(f"TABLE_NAME = '{tbl}'")
    if schema:
        filters.append(f"TABLE_SCHEMA = '{schema}'")
    if catalog:
        filters.append(f"TABLE_CATALOG = '{catalog}'")
    where_clause = " AND ".join(filters) if filters else "1=1"

    info_sql = (
        f"SELECT COLUMN_NAME AS `Field`, COLUMN_TYPE AS `Type`, "
        f"IS_NULLABLE AS `Null`, COLUMN_COMMENT AS `Comment` "
        f"FROM information_schema.COLUMNS WHERE {where_clause} "
        f"ORDER BY ORDINAL_POSITION"
    )

    try:
        result = execute_sql(session, info_sql, database_id, timeout, fetch_all=True)
        columns, rows = parse_results(result)
        if rows:
            print_table(rows, columns=columns, fmt=output_format, title=f"Structure: {table_name}")
            return
    except Exception:
        pass

    # Fallback: try DESC directly
    try:
        result = execute_sql(session, f"DESC {table_name}", database_id, timeout, fetch_all=True)
        columns, rows = parse_results(result)
        if rows:
            print_table(rows, columns=columns, fmt=output_format, title=f"Structure: {table_name}")
            return
    except Exception:
        pass

    print(f"No metadata found for table: {table_name}")


def show_create_table(session, table_name, database_id, timeout):
    sql = f"SHOW CREATE TABLE {table_name}"
    result = execute_sql(session, sql, database_id, timeout, fetch_all=True)
    columns, rows = parse_results(result)
    if not rows:
        print(f"No DDL found for table: {table_name}")
        return
    for row in rows:
        if isinstance(row, dict):
            for v in row.values():
                print(v)
        else:
            print(row)


# ── Query Execution ────────────────────────────────────────────────────────────

def execute_sql(session, sql, database_id, timeout, fetch_all=False, page_size=DEFAULT_PAGE_SIZE):
    csrf_token = get_csrf_token_sqllab(session)
    payload = {"database_id": database_id, "sql": sql}
    headers = {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrf_token or "",
        "Referer": f"{get_superset_url()}/sqllab/",
    }
    resp = session.post(
        f"{get_superset_url()}/api/v1/sqllab/execute/",
        json=payload,
        headers=headers,
        timeout=timeout,
    )
    if resp.status_code != 200:
        if resp.status_code == 401:
            raise Exception("Session expired. Please re-login with --force-login")
        if resp.status_code == 500:
            raise Exception("Server error. Please try again later")
        try:
            error_msg = resp.json().get("message", resp.text[:200])
        except Exception:
            error_msg = resp.text[:200]
        raise Exception(f"SQL execution failed ({resp.status_code}): {error_msg}")
    return resp.json()


def execute_sql_paginated(session, sql, database_id, timeout, page_size, max_rows=None):
    all_columns = []
    all_rows = []
    offset = 0
    while True:
        paginated_sql = f"{sql} LIMIT {page_size} OFFSET {offset}"
        result = execute_sql(session, paginated_sql, database_id, timeout, fetch_all=True)
        columns, rows = parse_results(result)
        if not all_columns and columns:
            all_columns = columns
        if not rows:
            break
        all_rows.extend(rows)
        if max_rows and len(all_rows) >= max_rows:
            all_rows = all_rows[:max_rows]
            break
        if len(rows) < page_size:
            break
        offset += page_size
        print(f"  Fetched {len(all_rows)} rows...", file=sys.stderr)
    return all_columns, all_rows


# ── Result Parsing & Output ────────────────────────────────────────────────────

def parse_results(data):
    def normalize_columns(columns):
        if not columns:
            return []
        if isinstance(columns[0], dict):
            return [c.get("name") or c.get("column_name") or str(c) for c in columns]
        return columns

    if "data" in data:
        rows = data.get("data", [])
        if rows and isinstance(rows[0], list):
            columns = normalize_columns(data.get("columns", []))
            return columns, [dict(zip(columns, row)) for row in rows]
        return [], rows
    if "result" in data:
        result = data.get("result", {})
        rows = result.get("data", [])
        if rows and isinstance(rows[0], list):
            columns = normalize_columns(result.get("columns", []))
            return columns, [dict(zip(columns, row)) for row in rows]
        return [], rows
    return [], []


def write_csv(columns, rows, output_path):
    if not rows:
        print("No data to write")
        return
    keys = columns if columns else list(rows[0].keys())
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(rows)
    print(f"CSV saved to: {output_path}")


def write_json(rows, output_path):
    if not rows:
        print("No data to write")
        return
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2, default=str)
    print(f"JSON saved to: {output_path}")


def print_table(rows, columns=None, fmt="md", title=None):
    if not rows:
        print("(no results)")
        return

    keys = columns if columns else list(rows[0].keys())
    if not keys:
        print("(empty)")
        return

    if title:
        print(f"\n{title}")
        print("=" * len(title))

    if fmt == "json":
        print(json.dumps(rows, ensure_ascii=False, indent=2, default=str))
        return

    if fmt == "csv":
        writer = csv.DictWriter(sys.stdout, fieldnames=keys, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            if isinstance(row, dict):
                writer.writerow(row)
            else:
                writer.writerow(dict(zip(keys, row)))
        return

    # Markdown format (default)
    col_widths = [len(k) for k in keys]
    display_rows = []
    for row in rows:
        display_row = {}
        for i, k in enumerate(keys):
            val = row.get(k, "") if isinstance(row, dict) else ""
            sval = str(val) if val is not None else ""
            display_row[k] = sval
            col_widths[i] = max(col_widths[i], len(sval))
        display_rows.append(display_row)

    header = "| " + " | ".join(k.ljust(col_widths[i]) for i, k in enumerate(keys)) + " |"
    sep = "|" + "|".join("-" * (col_widths[i] + 2) for i, k in enumerate(keys)) + "|"
    print(header)
    print(sep)
    for dr in display_rows:
        line = "| " + " | ".join(dr[k].ljust(col_widths[i]) for i, k in enumerate(keys)) + " |"
        print(line)
    print(f"\n({len(rows)} rows)")


# ── Cache ──────────────────────────────────────────────────────────────────────

def get_cache_dir():
    d = get_config_dir() / "cache"
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_cache_key(sql, database_id):
    raw = f"{database_id}:{sql.strip()}"
    return hashlib.md5(raw.encode()).hexdigest()


def get_cached(sql, database_id):
    cache_file = get_cache_dir() / f"{get_cache_key(sql, database_id)}.json"
    if cache_file.exists():
        try:
            with open(cache_file) as f:
                data = json.load(f)
            print(f"Cache hit for query (key={get_cache_key(sql, database_id)[:8]})")
            return data
        except (json.JSONDecodeError, IOError):
            return None
    return None


def set_cache(sql, database_id, result):
    cache_file = get_cache_dir() / f"{get_cache_key(sql, database_id)}.json"
    with open(cache_file, "w") as f:
        json.dump(result, f, ensure_ascii=False, default=str)


# ── Query History ──────────────────────────────────────────────────────────────

def get_history_file():
    return get_config_dir() / "history.jsonl"


def save_to_history(sql, database_id, row_count, output_file=None):
    entry = {
        "timestamp": datetime.now().isoformat(),
        "sql": sql,
        "database_id": database_id,
        "row_count": row_count,
        "output_file": output_file,
    }
    history_file = get_history_file()
    with open(history_file, "a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def clear_cache():
    cache_dir = get_cache_dir()
    if not cache_dir.exists():
        print("Cache directory not found")
        return
    count = 0
    for f in cache_dir.iterdir():
        if f.suffix == ".json":
            f.unlink()
            count += 1
    print(f"Cleared {count} cache file(s)")


def clear_history():
    history_file = get_history_file()
    if not history_file.exists():
        print("No history file found")
        return
    history_file.unlink()
    print("History file deleted")


def show_history(max_count=HISTORY_MAX):
    history_file = get_history_file()
    if not history_file.exists():
        print("No query history found")
        return
    lines = history_file.read_text().strip().split("\n")
    entries = []
    for line in lines[-max_count:]:
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    if not entries:
        print("No query history found")
        return

    print(f"\nQuery History (last {len(entries)} entries)")
    print("=" * 60)
    for i, e in enumerate(entries, 1):
        ts = e.get("timestamp", "?")[:19]
        sql_preview = e.get("sql", "")[:60]
        rows = e.get("row_count", "?")
        db = e.get("database_id", "?")
        print(f"  {i:3d}. [{ts}] db={db} rows={rows}")
        print(f"       {sql_preview}")
    print()


def list_databases_in_datasource(session, datasource_id, timeout, output_format="md"):
    """List databases in a data source, excluding internal ones."""
    result = execute_sql(session, "SHOW DATABASES", datasource_id, timeout)
    columns, rows = parse_results(result)
    # Filter out excluded databases
    filtered = []
    for row in rows:
        name = list(row.values())[0] if isinstance(row, dict) and row else str(row)
        if name.lower() not in EXCLUDED_DATABASES:
            filtered.append({"database": name})
    filtered.sort(key=lambda r: r["database"])
    print_table(filtered, columns=["database"], fmt=output_format, title=f"Databases (datasource={datasource_id})")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Superset SQL 查询工具")
    parser.add_argument("--sql", help="要执行的 SQL 语句")
    parser.add_argument("--sql-file", help="从 SQL 文件读取语句")
    parser.add_argument("--list-datasource", action="store_true", help="列出所有可用数据源")
    parser.add_argument("--list-databases", action="store_true", help="列出数据源下的数据库")
    parser.add_argument("--list-tables", action="store_true", help="列出数据库里的表")
    parser.add_argument("--describe", metavar="TABLE", help="查看表结构")
    parser.add_argument("--show-create", metavar="TABLE", help="查看建表语句")
    parser.add_argument("--history", action="store_true", help="显示查询历史")
    parser.add_argument("--clear-cache", action="store_true", help="清空查询缓存")
    parser.add_argument("--clear-history", action="store_true", help="清空查询历史")
    parser.add_argument("--datasource-id", type=int, default=get_default_datasource_id(), help=f"数据源 ID（默认: {get_default_datasource_id()}）")
    parser.add_argument("--set-default-datasource", type=int, metavar="ID", help="设置默认数据源 ID 并退出")
    parser.add_argument("--database", default=None, help="数据库名称（配合 --list-tables 使用）")
    parser.add_argument("--output-dir", default="./", help="输出目录")
    parser.add_argument("--output-file", default=None, help="保存到文件（根据扩展名自动检测格式）")
    parser.add_argument("--format", choices=["csv", "json", "md"], default="md", help="输出格式（默认: md）")
    parser.add_argument("--page-size", type=int, default=DEFAULT_PAGE_SIZE, help=f"分页大小（默认: {DEFAULT_PAGE_SIZE}）")
    parser.add_argument("--all-pages", action="store_true", help="自动获取所有分页")
    parser.add_argument("--cache", action="store_true", help="缓存相同查询结果")
    parser.add_argument("--no-cache", action="store_true", help="禁用缓存和历史记录")
    parser.add_argument("--username", default=None, help="Superset 用户名")
    parser.add_argument("--password", default=None, help="Superset 密码")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help=f"查询超时秒数（默认: {DEFAULT_TIMEOUT}）")
    parser.add_argument("--set-superset-url", metavar="URL", help="设置默认 Superset 地址并退出")
    parser.add_argument("--force-login", action="store_true", help="强制重新登录")

    args = parser.parse_args()

    needs_auth = any([args.sql, args.sql_file, args.list_tables, args.describe, args.show_create])
    if args.clear_cache:
        clear_cache()
        sys.exit(0)
    if args.clear_history:
        clear_history()
        sys.exit(0)

    if args.set_default_datasource is not None:
        save_config(datasource_id=args.set_default_datasource)
        sys.exit(0)

    if args.set_superset_url is not None:
        save_config(superset_url=args.set_superset_url)
        sys.exit(0)

    if not needs_auth and not args.list_datasource and not args.list_databases and not args.history:
        parser.error("one of --sql, --sql-file, --list-datasource, --list-databases, --list-tables, --describe, --show-create, --history is required")

    if args.history:
        show_history()
        sys.exit(0)

    username, password = get_credentials(args)
    session = requests.Session()
    try:
        ensure_login(session, username, password, force=args.force_login)
    except AuthError:
        username, password = reauth_wizard()
        session = requests.Session()
        try:
            ensure_login(session, username, password, force=True)
        except (AuthError, NetworkError) as e:
            print(f"Error: 重新认证失败 - {e}")
            sys.exit(1)

    try:
        if args.list_datasource:
            list_databases(session, args.timeout)

        if args.list_databases:
            list_databases_in_datasource(session, args.datasource_id, args.timeout, output_format=args.format)
            sys.exit(0)

        if args.list_tables:
            list_tables(session, args.datasource_id, args.timeout, database_name=args.database, output_format=args.format)
            sys.exit(0)

        if args.describe:
            describe_table(session, args.describe, args.datasource_id, args.timeout, output_format=args.format)
            sys.exit(0)

        if args.show_create:
            show_create_table(session, args.show_create, args.datasource_id, args.timeout)
            sys.exit(0)

        # Resolve SQL from inline or file
        if args.sql_file:
            sql_path = Path(args.sql_file)
            if not sql_path.exists():
                parser.error(f"SQL file not found: {args.sql_file}")
            sql = sql_path.read_text().strip()
            if args.sql:
                print("Warning: --sql ignored because --sql-file is provided", file=sys.stderr)
        elif args.sql:
            sql = args.sql
        else:
            parser.error("--sql or --sql-file is required for query execution")

        # Check cache
        if args.cache and not args.no_cache:
            cached = get_cached(sql, args.datasource_id)
            if cached:
                columns, rows = parse_results(cached)
                print(f"Retrieved {len(rows)} rows (cached)")
                if args.output_file:
                    _output_results(columns, rows, args)
                else:
                    print_table(rows, columns=columns, fmt=args.format)
                sys.exit(0)

        with Spinner("查询中"):
            if args.all_pages:
                columns, rows = execute_sql_paginated(
                    session, sql, args.datasource_id, args.timeout, args.page_size
                )
            else:
                result = execute_sql(session, sql, args.datasource_id, args.timeout)
                columns, rows = parse_results(result)

        print(f"Retrieved {len(rows)} rows")

        # Cache results
        if args.cache and not args.no_cache:
            if args.all_pages:
                set_cache(sql, args.datasource_id, {"data": [list(r.values()) for r in rows], "columns": columns})
            else:
                set_cache(sql, args.datasource_id, result)

        # Save to history
        if not args.no_cache:
            save_to_history(sql, args.datasource_id, len(rows), args.output_file)

        # Output
        if args.output_file:
            _output_results(columns, rows, args)
        else:
            print_table(rows, columns=columns, fmt=args.format)

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
    finally:
        session.close()


class Spinner:
    """Simple spinner with elapsed time for long-running operations."""
    def __init__(self, message="Executing SQL"):
        self.message = message
        self._running = False
        self._thread = None

    def __enter__(self):
        self._running = True
        self._t0 = time.time()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *args):
        self._running = False
        if self._thread:
            self._thread.join(0.5)
        elapsed = time.time() - self._t0
        print(f"\r{self.message}... done ({elapsed:.1f}s)  ")

    def _spin(self):
        chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        i = 0
        while self._running:
            elapsed = time.time() - self._t0
            sys.stdout.write(f"\r{self.message}... {chars[i % len(chars)]} {elapsed:.0f}s")
            sys.stdout.flush()
            time.sleep(0.15)
            i += 1


def _output_results(columns, rows, args):
    output_path = Path(args.output_file)
    if not output_path.is_absolute():
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / output_path
    else:
        output_path.parent.mkdir(parents=True, exist_ok=True)

    ext = output_path.suffix.lower()
    if ext == ".csv" or (not ext and args.format == "csv"):
        write_csv(columns, rows, output_path)
    elif ext == ".json" or (not ext and args.format == "json"):
        write_json(rows, output_path)
    else:
        # Default to CSV for file output
        write_csv(columns, rows, output_path)


if __name__ == "__main__":
    main()
