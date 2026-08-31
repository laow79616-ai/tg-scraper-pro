#!/usr/bin/env python3
"""
TG 采集工具 Pro 版 - Web 面板
功能：
1. 多账号管理（5个水军号）
2. 关键词搜索群组
3. 24小时实时监听新用户
4. 消息采集模式（抓取发言者）
5. 自动去重保存文档

安全与稳定性改进：
- 账号密码 / secret_key 支持环境变量覆盖
- FloodWait 正确等待后继续，不再静默吞掉
- 监听事件处理器正确注册与移除
- 基础日志、代理支持、更严格的异常处理
"""
import os
import json
import time
import asyncio
import threading
import csv
import logging
import secrets
from datetime import datetime
from flask import Flask, jsonify, request, send_from_directory, send_file, session, redirect

from telethon import TelegramClient, events
from telethon.tl.functions.contacts import SearchRequest
from telethon.tl.functions.channels import GetParticipantsRequest
from telethon.tl.functions.messages import GetHistoryRequest, SearchGlobalRequest
from telethon.tl.types import (
    ChannelParticipantsSearch,
    InputPeerEmpty,
    Channel,
    Chat,
    User,
)
from telethon.errors import (
    FloodWaitError,
    SessionPasswordNeededError,
    ChatAdminRequiredError,
    ChannelPrivateError,
)

# ============ 日志 ============
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("tg-scraper-pro")

app = Flask(__name__, static_folder="static", static_url_path="")
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# ============ 登录认证（优先读环境变量） ============
ADMIN_USERNAME = os.environ.get("TG_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("TG_ADMIN_PASS", "Ab123456987")
_secret = os.environ.get("TG_SECRET_KEY")
if not _secret:
    _secret = secrets.token_hex(24)
    logger.warning("未设置 TG_SECRET_KEY，已使用随机密钥（重启后 session 会失效）")
app.secret_key = _secret

if ADMIN_PASSWORD == "Ab123456987":
    logger.warning("正在使用默认管理员密码，请尽快通过环境变量 TG_ADMIN_PASS 修改！")


@app.before_request
def require_login():
    """所有请求需要登录认证"""
    allowed_paths = ['/api/login', '/api/auth/status', '/login.html']
    if request.path in allowed_paths:
        return None
    if request.path.startswith('/static/'):
        return None
    if not session.get('logged_in'):
        if request.path.startswith('/api/'):
            return jsonify({'status': 'error', 'message': '未登录'}), 401
        return redirect('/login.html')
    return None


@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json or {}
    username = data.get('username', '')
    password = data.get('password', '')
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        session['logged_in'] = True
        session['username'] = username
        return jsonify({'status': 'ok', 'message': '登录成功'})
    return jsonify({'status': 'error', 'message': '用户名或密码错误'}), 403


@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'status': 'ok', 'message': '已退出登录'})


@app.route('/api/auth/status', methods=['GET'])
def auth_status():
    if session.get('logged_in'):
        return jsonify({'logged_in': True, 'username': session.get('username')})
    return jsonify({'logged_in': False})


@app.route('/login.html')
def login_page():
    return send_from_directory('static', 'login.html')


@app.after_request
def after_request(response):
    # 同源面板不需要宽松 CORS；避免 Access-Control-Allow-Origin: * 配合 Cookie 的安全风险
    response.headers.add('Cache-Control', 'no-cache, no-store, must-revalidate')
    response.headers.add('X-Content-Type-Options', 'nosniff')
    response.headers.add('X-Frame-Options', 'SAMEORIGIN')
    return response


# ============ 全局配置 ============
DATA_DIR = "data"
OUTPUT_DIR = "output"
ACCOUNTS_FILE = os.path.join(DATA_DIR, "accounts.json")
GROUPS_FILE = os.path.join(DATA_DIR, "groups.json")
USERS_FILE = os.path.join(DATA_DIR, "users.json")
TASKS_FILE = os.path.join(DATA_DIR, "tasks.json")
MONITOR_FILE = os.path.join(DATA_DIR, "monitor.json")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

# 全局状态
clients = {}  # account_id -> TelegramClient
client_status = {}  # account_id -> {status, username, phone, ...}
monitor_running = False
monitor_thread = None
collected_users = set()  # 全局去重用户集合
# 保存已注册的事件处理器，便于正确移除：acc_id -> list of (event_type, callback)
_monitor_handlers = {}

# 异步事件循环 - 使用独立线程
loop = asyncio.new_event_loop()


def start_loop():
    asyncio.set_event_loop(loop)
    loop.run_forever()


async_thread = threading.Thread(target=start_loop, daemon=True)
async_thread.start()
time.sleep(0.5)


def run_async(coro, timeout=120):
    """安全地在异步循环中执行协程"""
    future = asyncio.run_coroutine_threadsafe(coro, loop)
    return future.result(timeout=timeout)


def _parse_proxy(proxy_str):
    """解析代理字符串，支持 socks5://user:pass@host:port 或 host:port"""
    if not proxy_str:
        return None
    try:
        from urllib.parse import urlparse
        s = proxy_str.strip()
        if "://" not in s:
            s = "socks5://" + s
        u = urlparse(s)
        host = u.hostname
        port = u.port or 1080
        username = u.username
        password = u.password
        # Telethon: (proxy_type, host, port, rdns, username, password)
        # 1=SOCKS5, 2=SOCKS4, 3=HTTP
        ptype = 1
        if u.scheme in ("http", "https"):
            ptype = 3
        elif u.scheme in ("socks4",):
            ptype = 2
        return (ptype, host, port, True, username, password)
    except Exception as e:
        logger.warning("代理解析失败 %s: %s", proxy_str, e)
        return None


# ============ 数据持久化 ============
def load_json(filepath, default=None):
    if default is None:
        default = []
    if os.path.exists(filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning("读取 JSON 失败 %s: %s", filepath, e)
            return default
    return default


def save_json(filepath, data):
    # 使用临时文件写入防止损坏
    tmp_path = filepath + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, filepath)
    except Exception as e:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise e


def load_accounts():
    return load_json(ACCOUNTS_FILE, [])


def save_accounts(accounts):
    save_json(ACCOUNTS_FILE, accounts)


def load_groups():
    return load_json(GROUPS_FILE, [])


def save_groups(groups):
    save_json(GROUPS_FILE, groups)


# Users data cache (avoid re-reading on every request)
_users_cache = None
_users_mtime = 0


def load_users_data():
    global _users_cache, _users_mtime
    try:
        if not os.path.exists(USERS_FILE):
            return []
        mtime = os.path.getmtime(USERS_FILE)
        if _users_cache is not None and mtime == _users_mtime:
            return _users_cache
        _users_cache = load_json(USERS_FILE, [])
        _users_mtime = mtime
        return _users_cache
    except:
        return load_json(USERS_FILE, [])


def save_users_data(users):
    global _users_cache, _users_mtime
    save_json(USERS_FILE, users)
    _users_cache = users
    _users_mtime = os.path.getmtime(USERS_FILE)


# Tasks data cache - 只缓存任务计数，不加载完整数据
_tasks_count_cache = 0
_tasks_count_mtime = 0


def get_tasks_count():
    """只获取任务计数，不加载完整文件"""
    global _tasks_count_cache, _tasks_count_mtime
    try:
        if not os.path.exists(TASKS_FILE):
            return 0
        mtime = os.path.getmtime(TASKS_FILE)
        if mtime == _tasks_count_mtime:
            return _tasks_count_cache
        tasks = load_json(TASKS_FILE, [])
        _tasks_count_cache = len(tasks)
        _tasks_count_mtime = mtime
        return _tasks_count_cache
    except:
        return _tasks_count_cache


def load_tasks():
    return load_json(TASKS_FILE, [])


def save_tasks(tasks):
    global _tasks_count_cache, _tasks_count_mtime
    # 只保留最近50条任务，防止文件无限增长
    if len(tasks) > 50:
        tasks = tasks[-50:]
    save_json(TASKS_FILE, tasks)
    _tasks_count_cache = len(tasks)
    _tasks_count_mtime = os.path.getmtime(TASKS_FILE)


def load_monitor_config():
    return load_json(MONITOR_FILE, {"enabled": False, "accounts": [], "groups": []})


def save_monitor_config(config):
    save_json(MONITOR_FILE, config)


# ============ 账号管理 ============
async def _connect_account(account):
    """连接单个账号（支持可选 proxy 字段）"""
    acc_id = account["id"]
    api_id = int(account["api_id"])
    api_hash = account["api_hash"]
    phone = account["phone"]
    session_file = os.path.join(DATA_DIR, f"session_{acc_id}")
    proxy = _parse_proxy(account.get("proxy") or "")

    # 如果已有客户端且已连接，先断开
    if acc_id in clients:
        old_client = clients[acc_id]
        try:
            if old_client.is_connected():
                await old_client.disconnect()
        except Exception:
            pass

    client = TelegramClient(
        session_file,
        api_id,
        api_hash,
        proxy=proxy,
        connection_retries=5,
        retry_delay=3,
        auto_reconnect=True,
        request_retries=3,
    )
    await client.connect()

    if not await client.is_user_authorized():
        await client.send_code_request(phone)
        clients[acc_id] = client
        return {"status": "need_code", "account_id": acc_id}

    me = await client.get_me()
    clients[acc_id] = client
    client_status[acc_id] = {
        "status": "online",
        "username": me.username or "",
        "first_name": me.first_name or "",
        "phone": phone,
        "connected_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "proxy": bool(proxy),
    }
    logger.info("账号已连接: %s (@%s)", phone, me.username or me.first_name)
    return {"status": "connected", "account_id": acc_id, "username": me.username or me.first_name}


async def _submit_code(acc_id, code, password=None):
    """提交验证码"""
    client = clients.get(acc_id)
    if not client:
        return {"status": "error", "message": "客户端未找到"}

    accounts = load_accounts()
    account = next((a for a in accounts if a["id"] == acc_id), None)
    if not account:
        return {"status": "error", "message": "账号配置未找到"}

    try:
        await client.sign_in(account["phone"], code)
    except SessionPasswordNeededError:
        if password:
            await client.sign_in(password=password)
        else:
            return {"status": "need_password", "account_id": acc_id}

    me = await client.get_me()
    client_status[acc_id] = {
        "status": "online",
        "username": me.username or "",
        "first_name": me.first_name or "",
        "phone": account["phone"],
        "connected_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    return {"status": "connected", "account_id": acc_id, "username": me.username or me.first_name}


async def _disconnect_account(acc_id):
    """断开账号"""
    client = clients.get(acc_id)
    if client:
        try:
            await client.disconnect()
        except:
            pass
        del clients[acc_id]
    if acc_id in client_status:
        client_status[acc_id]["status"] = "offline"
    return {"status": "ok"}


async def _check_account_status(acc_id):
    """检查账号状态 - 轻量级检查"""
    client = clients.get(acc_id)
    if not client:
        return {"status": "offline", "message": "未连接"}
    try:
        if not client.is_connected():
            # 尝试重连
            await client.connect()
            if not await client.is_user_authorized():
                return {"status": "offline", "message": "需要重新授权"}
        me = await client.get_me()
        if me:
            client_status[acc_id] = {
                "status": "online",
                "username": me.username or "",
                "first_name": me.first_name or "",
                "phone": client_status.get(acc_id, {}).get("phone", ""),
                "connected_at": client_status.get(acc_id, {}).get("connected_at", ""),
            }
            return {"status": "online", "username": me.username or me.first_name}
        else:
            return {"status": "restricted", "message": "账号可能被限制"}
    except Exception as e:
        if acc_id in client_status:
            client_status[acc_id]["status"] = "offline"
        return {"status": "error", "message": str(e)}


# ============ 关键词搜索群组 ============

# ============ 通过链接/用户名精确添加 ============
import re as _re_link
from urllib.parse import unquote as _unquote_link

def parse_tg_link(raw: str):
    s = _unquote_link((raw or "").strip())
    if not s:
        return None
    if s.startswith("@") and _re_link.fullmatch(r"@[A-Za-z0-9_]{4,}", s):
        return {"kind": "username", "username": s[1:]}
    m = _re_link.match(r"^(?:https?://)?(?:www\.)?(?:t\.me|telegram\.me|telegram\.dog)/(.+)$", s, _re_link.I)
    if m:
        path = m.group(1).strip().strip("/")
        parts = path.split("/")
        head = parts[0]
        if head == "joinchat" and len(parts) > 1:
            return {"kind": "invite", "hash": parts[1].split("?")[0]}
        if head.startswith("+"):
            return {"kind": "invite", "hash": head[1:].split("?")[0]}
        if _re_link.fullmatch(r"[A-Za-z0-9_]{4,}", head):
            return {"kind": "username", "username": head}
    if _re_link.fullmatch(r"[A-Za-z0-9_]{4,}", s):
        return {"kind": "username", "username": s}
    return None


def _first_online_client():
    for name in ("clients", "online_clients", "account_clients", "telethon_clients"):
        obj = globals().get(name)
        if isinstance(obj, dict):
            for cid, cli in obj.items():
                if cli:
                    return cid, cli
    accs = globals().get("accounts") or globals().get("ACCOUNTS")
    if isinstance(accs, dict):
        for cid, acc in accs.items():
            cli = acc.get("client") if isinstance(acc, dict) else None
            if cli:
                return cid, cli
    if isinstance(accs, list):
        for acc in accs:
            if isinstance(acc, dict) and acc.get("client"):
                return acc.get("id") or acc.get("phone"), acc.get("client")
    return None, None


def _discovered_store():
    for name in ("discovered_groups", "found_groups", "groups", "GROUP_LIST", "search_results"):
        obj = globals().get(name)
        if isinstance(obj, list):
            return name, obj
    return None, None


@app.route("/api/groups/from-link", methods=["POST"])
def api_groups_from_link():
    data = request.get_json(silent=True) or {}
    raw = (data.get("link") or "").strip()
    do_listen = bool(data.get("listen"))
    parsed = parse_tg_link(raw)
    if not parsed:
        return jsonify({"status": "error", "message": "无法识别的链接或用户名"})

    acc_id, client = _first_online_client()
    if not client:
        return jsonify({"status": "error", "message": "没有在线账号，请先在账号管理里连接"})

    async def _resolve():
        if parsed["kind"] == "username":
            return await client.get_entity(parsed["username"])
        from telethon.tl.functions.messages import CheckChatInviteRequest, ImportChatInviteRequest
        from telethon.tl.types import ChatInviteAlready
        inv = await client(CheckChatInviteRequest(parsed["hash"]))
        if isinstance(inv, ChatInviteAlready):
            return inv.chat
        updates = await client(ImportChatInviteRequest(parsed["hash"]))
        chats = getattr(updates, "chats", None) or []
        return chats[0] if chats else updates

    def _telethon_run(cli, coro, timeout=30):
        import asyncio
        # 必须用该 client 连接时的 loop，禁止在 Flask 线程新建 loop
        loop = getattr(cli, "loop", None)
        if loop is None:
            raise RuntimeError("client 没有 loop，账号可能未真正连接")
        if loop.is_running():
            return asyncio.run_coroutine_threadsafe(coro, loop).result(timeout=timeout)
        # loop 存在但没在跑：仍在该 loop 上执行，不切换
        return loop.run_until_complete(coro)

    try:
        entity = run_async(_resolve(), timeout=30)

        title = getattr(entity, "title", None) or getattr(entity, "first_name", "") or raw
        username = getattr(entity, "username", None) or parsed.get("username") or ""
        uid = getattr(entity, "id", None)
        is_channel = bool(getattr(entity, "broadcast", False))
        is_megagroup = bool(getattr(entity, "megagroup", False))
        gtype = "频道" if is_channel and not is_megagroup else "群组"
        members = getattr(entity, "participants_count", 0) or 0
        async def _full_count(ent):
            from telethon.tl.types import Channel, Chat
            from telethon.tl.functions.channels import GetFullChannelRequest
            from telethon.tl.functions.messages import GetFullChatRequest
            if isinstance(ent, Channel):
                full = await client(GetFullChannelRequest(ent))
                return getattr(full.full_chat, "participants_count", 0) or 0
            if isinstance(ent, Chat):
                full = await client(GetFullChatRequest(ent.id))
                return getattr(full.full_chat, "participants_count", 0) or 0
            return 0
        try:
            members = run_async(_full_count(entity), timeout=20) or members
        except Exception:
            pass

        from datetime import datetime
        item = {
            "id": str(uid),
            "title": title,
            "username": username,
            "participants_count": int(members or 0),
            "type": "channel" if (gtype == "频道") else "group",
            "keyword": "链接添加",
            "link": raw,
            "source": "link",
            "listen": do_listen,
            "found_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

        groups = load_groups()
        exists = False
        for g in groups:
            if str(g.get("id")) == str(uid) or (username and g.get("username") == username):
                g.update(item)
                exists = True
                break
        if not exists:
            groups.append(item)
        save_groups(groups)

        listen_msg = ""
        if do_listen:
            try:
                account_ids = [aid for aid, st in client_status.items() if st.get("status") == "online"]
                if not account_ids:
                    listen_msg = "已添加，但没有在线账号，监听未启动"
                else:
                    def _g_link(g):
                        if g.get("username"):
                            return "https://t.me/" + g["username"]
                        return g.get("link") or ""
                    all_links = [x for x in (_g_link(g) for g in load_groups()) if x]
                    mon = run_async(_start_monitor(account_ids, all_links), timeout=60)
                    listen_msg = "已添加并启动监听" if mon.get("status") in ("ok", "success", None) else ("已添加，监听: " + str(mon))
            except Exception as e:
                listen_msg = "已添加但监听启动失败: %s" % e

        return jsonify({"status": "ok", "group": item, "message": listen_msg or "已添加"})
    except Exception as e:
        return jsonify({"status": "error", "message": "解析失败: %s" % e})


async def _get_working_client(acc_id=None):
    """获取一个可用的客户端，如果断开则自动重连"""
    if acc_id and acc_id in clients:
        client = clients[acc_id]
        try:
            if not client.is_connected():
                await client.connect()
            await client.get_me()
            return client
        except Exception:
            try:
                await client.connect()
                if await client.is_user_authorized():
                    return client
            except Exception:
                pass
    # 遍历所有客户端找一个可用的
    for cid, c in list(clients.items()):
        try:
            if not c.is_connected():
                await c.connect()
            me = await c.get_me()
            if me:
                return c
        except Exception:
            try:
                await c.connect()
                if await c.is_user_authorized():
                    return c
            except Exception:
                if cid in client_status:
                    client_status[cid]["status"] = "offline"
                continue
    return None


async def _search_groups(keyword, acc_id=None):
    """通过关键词全局搜索群组/频道"""
    keyword = (keyword or "").strip()
    if not keyword:
        return {"status": "error", "message": "关键词为空"}
    client = await _get_working_client(acc_id)
    if not client:
        return {"status": "error", "message": "没有可用的在线账号，请尝试重新连接"}
    results = []
    try:
        from telethon.tl.functions.contacts import SearchRequest
        from telethon.tl.types import Channel, Chat
        resp = await client(SearchRequest(q=keyword, limit=50))
        chats = list(getattr(resp, "chats", []) or [])
        peers = list(getattr(resp, "results", []) or [])
        logger.info("关键词[%s] chats=%s results=%s", keyword, len(chats), len(peers))
        seen = set()
        entities = []
        for ch in chats:
            entities.append(ch)
        for peer in peers:
            try:
                ent = await client.get_entity(peer)
                entities.append(ent)
            except Exception as e:
                logger.warning("解析搜索结果失败: %s", e)
        for ch in entities:
            cid = getattr(ch, "id", None)
            if cid is None or cid in seen:
                continue
            seen.add(cid)
            if not isinstance(ch, (Channel, Chat)):
                continue
            is_channel = bool(getattr(ch, "broadcast", False)) and not bool(getattr(ch, "megagroup", False))
            members = getattr(ch, "participants_count", 0) or 0
            try:
                if isinstance(ch, Channel):
                    from telethon.tl.functions.channels import GetFullChannelRequest
                    full = await client(GetFullChannelRequest(ch))
                    members = getattr(full.full_chat, "participants_count", members) or members
            except Exception:
                pass
            results.append({
                "id": str(ch.id),
                "title": getattr(ch, "title", "") or "",
                "username": getattr(ch, "username", None) or "",
                "participants_count": int(members or 0),
                "type": "channel" if is_channel else "group",
                "found_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "keyword": keyword,
            })
    except FloodWaitError as e:
        return {"status": "error", "message": "被限流，需等待 %s 秒" % e.seconds}
    except Exception as e:
        logger.exception("搜索失败")
        return {"status": "error", "message": str(e)}
    if results:
        existing_groups = load_groups()
        existing_ids = {str(g.get("id")) for g in existing_groups}
        new_groups = [g for g in results if str(g.get("id")) not in existing_ids and (g.get("participants_count") or 0) >= 100]
        existing_groups.extend(new_groups)
        save_groups(existing_groups)
        logger.info("关键词[%s] 新增 %s 个，当前总数 %s", keyword, len(new_groups), len(existing_groups))
    return {"status": "ok", "count": len(results), "groups": results}

# ============ 成员采集 ============
async def _scrape_members(group_link, acc_id=None):
    """采集群组成员列表"""
    client = await _get_working_client(acc_id)
    if not client:
        return {"status": "error", "message": "没有可用的在线账号"}

    try:
        entity = await client.get_entity(group_link)
    except ChannelPrivateError:
        return {"status": "error", "message": "频道/群组为私有，无法访问"}
    except Exception as e:
        return {"status": "error", "message": f"无法获取群组: {str(e)}"}

    members = []
    flood_hits = 0
    try:
        seen = set()
        async for user in client.iter_participants(entity):
            if getattr(user, "bot", False) or getattr(user, "deleted", False):
                continue
            uid = str(user.id)
            if uid in seen:
                continue
            seen.add(uid)
            members.append({
                "user_id": uid,
                "username": user.username or "",
                "first_name": user.first_name or "",
                "last_name": user.last_name or "",
                "phone": getattr(user, "phone", "") or "",
                "is_bot": False,
                "source": group_link,
                "source_type": "member",
                "collected_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })
            if len(members) % 200 == 0:
                logger.info("成员采集中 %s: %s", group_link, len(members))
                await asyncio.sleep(0.3)
    except ChatAdminRequiredError:
        return {"status": "error", "message": "需要管理员权限才能获取成员列表"}
    except Exception as e:
        if not members:
            return {"status": "error", "message": str(e)}
        logger.warning("成员采集部分失败: %s", e)

    # 保存用户数据
    added = _save_collected_users(members)
    return {"status": "ok", "count": len(members), "added": added, "flood_hits": flood_hits}


# ============ 消息采集模式 ============
async def _scrape_messages(group_link, limit=1000, acc_id=None):
    """通过历史消息采集发言用户"""
    client = await _get_working_client(acc_id)
    if not client:
        return {"status": "error", "message": "没有可用的在线账号"}

    try:
        entity = await client.get_entity(group_link)
    except Exception as e:
        return {"status": "error", "message": f"无法获取群组: {str(e)}"}

    users_found = {}
    try:
        async for message in client.iter_messages(entity, limit=limit):
            try:
                if message.sender and isinstance(message.sender, User):
                    user = message.sender
                    if user.bot:
                        continue
                    uid = str(user.id)
                    if uid not in users_found:
                        users_found[uid] = {
                            "user_id": uid,
                            "username": user.username or "",
                            "first_name": user.first_name or "",
                            "last_name": user.last_name or "",
                            "phone": user.phone or "",
                            "is_bot": False,
                            "source": group_link,
                            "source_type": "message",
                            "collected_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        }
            except FloodWaitError as e:
                wait_s = min(int(e.seconds) + 1, 120)
                logger.warning("消息采集触发限流，等待 %s 秒", wait_s)
                await asyncio.sleep(wait_s)
            await asyncio.sleep(0.08)

    except FloodWaitError as e:
        wait_s = min(int(e.seconds) + 1, 120)
        logger.warning("消息采集整体限流，等待 %s 秒后返回已采集数据", wait_s)
        await asyncio.sleep(wait_s)
    except Exception as e:
        if not users_found:
            return {"status": "error", "message": str(e)}
        logger.warning("消息采集部分失败: %s", e)

    members = list(users_found.values())
    added = _save_collected_users(members)
    return {"status": "ok", "count": len(members), "added": added}


# ============ 24小时实时监听 ============

def _chat_id_set(raw_ids):
    s = set()
    for i in raw_ids or []:
        if i is None or i == "":
            continue
        s.add(i)
        s.add(str(i))
        try:
            n = int(str(i).replace("-100", "").lstrip("-"))
        except Exception:
            continue
        s.add(n)
        s.add(-n)
        s.add(int("-100%d" % n))
        s.add("-100%d" % n)
        s.add(str(n))
    return s

def _chat_allowed(chat_id, allowed):
    if not allowed:
        return True
    if chat_id in allowed:
        return True
    if str(chat_id) in allowed:
        return True
    try:
        n = int(str(chat_id).replace("-100", "").lstrip("-"))
        return n in allowed or str(n) in allowed or int("-100%d" % n) in allowed
    except Exception:
        return False

def _make_join_handler(allowed_chat_ids):
    """工厂函数：避免循环内闭包捕获错误，并支持按群过滤"""
    async def handler(event):
        if allowed_chat_ids and not _chat_allowed(getattr(event, 'chat_id', None), allowed_chat_ids):
            return
        if not (event.user_joined or event.user_added):
            return
        try:
            user = await event.get_user()
            if not user or getattr(user, "bot", False):
                return
            user_info = {
                "user_id": str(user.id),
                "username": user.username or "",
                "first_name": user.first_name or "",
                "last_name": user.last_name or "",
                "phone": user.phone or "",
                "is_bot": False,
                "source": str(event.chat_id),
                "source_type": "monitor_join",
                "collected_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            _save_collected_users([user_info])
        except Exception as e:
            logger.debug("join handler error: %s", e)
    return handler


def _make_msg_handler(allowed_chat_ids):
    async def msg_handler(event):
        chat_id = getattr(event, "chat_id", None)
        try:
            if allowed_chat_ids and not _chat_allowed(chat_id, allowed_chat_ids):
                return
            sender = event.sender
            if sender is None:
                sender = await event.get_sender()
            if not sender or not isinstance(sender, User) or getattr(sender, "bot", False):
                return
            user_info = {
                "user_id": str(sender.id),
                "username": sender.username or "",
                "first_name": sender.first_name or "",
                "last_name": sender.last_name or "",
                "phone": sender.phone or "",
                "is_bot": False,
                "source": str(event.chat_id),
                "source_type": "monitor_message",
                "collected_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            _save_collected_users([user_info])
        except Exception as e:
            logger.debug("msg handler error: %s", e)
    return msg_handler


async def _resolve_chat_ids(client, group_links):
    """把 @username / 链接 / 数字 id 解析成 chat_id 集合，失败的跳过"""
    ids = set()
    if not group_links:
        return ids
    for link in group_links:
        try:
            entity = await client.get_entity(link)
            ids.add(entity.id)
        except Exception as e:
            logger.warning("无法解析监听群组 %s: %s", link, e)
    return ids



async def _resolve_and_join(client, group_links):
    """把 t.me/@ 转成真实 chat_id，并尝试加入。"""
    ids = []
    from telethon.tl.functions.channels import JoinChannelRequest
    from telethon.tl.functions.messages import ImportChatInviteRequest
    for raw in group_links or []:
        raw = (raw or "").strip()
        if not raw:
            continue
        try:
            parsed = parse_tg_link(raw) if "parse_tg_link" in globals() else None
            entity = None
            if parsed and parsed.get("kind") == "invite":
                try:
                    entity = await client.get_entity(raw)
                except Exception:
                    try:
                        upd = await client(ImportChatInviteRequest(parsed["hash"]))
                        chats = getattr(upd, "chats", None) or []
                        entity = chats[0] if chats else None
                    except Exception as e:
                        logger.warning("邀请链接加入失败 %s: %s", raw, e)
            else:
                username = None
                if parsed and parsed.get("username"):
                    username = parsed["username"]
                elif raw.startswith("@"):
                    username = raw[1:]
                else:
                    username = raw.replace("https://t.me/", "").replace("http://t.me/", "").strip("/")
                if username:
                    try:
                        entity = await client.get_entity(username)
                    except Exception as e:
                        logger.warning("解析群失败 %s: %s", raw, e)
                if entity is not None:
                    try:
                        await client(JoinChannelRequest(entity))
                    except Exception:
                        pass
            if entity is not None:
                cid = getattr(entity, "id", None)
                if cid is not None:
                    ids.append(cid)
                    ids.append(int("-100%d" % abs(int(cid))))
        except Exception as e:
            logger.warning("resolve/join %s: %s", raw, e)
    return ids

async def _start_monitor(account_ids, group_links):
    """启动实时监听（正确注册/记录 handler，支持按群过滤）"""
    global monitor_running

    # 先清理旧 handler，避免重复注册
    await _stop_monitor()

    registered = 0
    for acc_id in account_ids:
        client = clients.get(acc_id)
        if not client:
            continue
        try:
            allowed = await _resolve_chat_ids(client, group_links)
            join_h = _make_join_handler(allowed)
            msg_h = _make_msg_handler(allowed)
            client.add_event_handler(join_h, events.ChatAction)
            client.add_event_handler(msg_h, events.NewMessage)
            _monitor_handlers[acc_id] = [
                (events.ChatAction, join_h),
                (events.NewMessage, msg_h),
            ]
            registered += 1
            logger.info("监听已挂到账号 %s，过滤群数=%s", acc_id, len(allowed) if allowed else "全部")
        except Exception as e:
            logger.error("账号 %s 注册监听失败: %s", acc_id, e)

    if registered == 0:
        return {"status": "error", "message": "没有可用账号注册监听"}

    monitor_running = True
    save_monitor_config({
        "enabled": True,
        "accounts": account_ids,
        "groups": group_links,
        "started_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })
    return {"status": "ok", "message": f"监听已启动（{registered} 个账号）"}


async def _stop_monitor():
    """停止监听（按已记录的 callback 正确移除）"""
    global monitor_running
    monitor_running = False

    for acc_id, handlers in list(_monitor_handlers.items()):
        client = clients.get(acc_id)
        if not client:
            continue
        for event_type, callback in handlers:
            try:
                client.remove_event_handler(callback, event_type)
            except Exception as e:
                logger.debug("移除 handler 失败 %s: %s", acc_id, e)
        _monitor_handlers.pop(acc_id, None)

    # 兼容：尝试清理可能残留的 handler
    for acc_id, client in list(clients.items()):
        try:
            client.list_event_handlers()  # 存在即可，不强制清空
        except Exception:
            pass

    save_monitor_config({"enabled": False, "accounts": [], "groups": []})
    return {"status": "ok", "message": "监听已停止"}


# ============ 用户数据管理 ============
_save_lock = threading.Lock()


def _save_collected_users(new_users):
    """保存采集到的用户（按 user_id 去重）- 线程安全

    默认保存所有非 bot 用户（即使没有 username）。
    可通过环境变量 TG_REQUIRE_USERNAME=1 恢复「仅保存有用户名」的旧行为。
    """
    global collected_users
    require_username = os.environ.get("TG_REQUIRE_USERNAME", "0") == "1"
    with _save_lock:
        existing = load_users_data()
        existing_ids = {u["user_id"] for u in existing}
        collected_users = existing_ids.copy()

        added = 0
        for user in new_users:
            uid = str(user.get("user_id") or "")
            if not uid or uid in existing_ids:
                continue
            if user.get("is_bot"):
                continue
            if require_username and not user.get("username"):
                continue
            existing.append(user)
            existing_ids.add(uid)
            collected_users.add(uid)
            added += 1

        if added > 0:
            save_users_data(existing)
            logger.info("新增用户 %s 条，当前总量 %s", added, len(existing))
        return added


def export_users_csv():
    """导出用户到 CSV"""
    users = load_users_data()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"users_export_{timestamp}.csv"
    filepath = os.path.join(OUTPUT_DIR, filename)

    with open(filepath, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["用户ID", "用户名", "名字", "姓氏", "手机号", "是否Bot", "来源", "采集方式", "采集时间"])
        for user in users:
            writer.writerow([
                user.get("user_id", ""),
                f"@{user['username']}" if user.get("username") else "",
                user.get("first_name", ""),
                user.get("last_name", ""),
                user.get("phone", ""),
                user.get("is_bot", False),
                user.get("source", ""),
                user.get("source_type", "member"),
                user.get("collected_at", ""),
            ])
    return filepath, filename


def export_users_txt():
    """导出用户名到 TXT"""
    users = load_users_data()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"usernames_{timestamp}.txt"
    filepath = os.path.join(OUTPUT_DIR, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        for user in users:
            if user.get("username"):
                f.write(f"@{user['username']}\n")
    return filepath, filename


# ============ API 路由 ============

@app.route("/")
def index():
    return send_from_directory("static", "index.html")


# --- 账号管理 ---
@app.route("/api/accounts", methods=["GET"])
def get_accounts():
    accounts = load_accounts()
    # 附加在线状态 - 快速返回缓存状态，不做实际连接检查
    for acc in accounts:
        status = client_status.get(acc["id"], {"status": "offline"})
        acc["online_status"] = status.get("status", "offline")
        acc["connected_username"] = status.get("username", "")
    return jsonify(accounts)


@app.route("/api/accounts", methods=["POST"])
def add_account():
    data = request.json or {}
    accounts = load_accounts()
    acc_id = f"acc_{int(time.time() * 1000)}"
    account = {
        "id": acc_id,
        "name": data.get("name", f"账号{len(accounts)+1}"),
        "api_id": str(data.get("api_id", "")).strip(),
        "api_hash": str(data.get("api_hash", "")).strip(),
        "phone": str(data.get("phone", "")).strip(),
        "proxy": str(data.get("proxy", "")).strip(),  # 可选 socks5://host:port
        "added_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    if not account["api_id"] or not account["api_hash"] or not account["phone"]:
        return jsonify({"status": "error", "message": "api_id / api_hash / phone 均为必填"}), 400
    accounts.append(account)
    save_accounts(accounts)
    return jsonify({"status": "ok", "account": account})


@app.route("/api/accounts/<acc_id>", methods=["DELETE"])
def delete_account(acc_id):
    accounts = load_accounts()
    accounts = [a for a in accounts if a["id"] != acc_id]
    save_accounts(accounts)
    # 断开连接
    if acc_id in clients:
        try:
            run_async(_disconnect_account(acc_id), timeout=10)
        except:
            pass
    return jsonify({"status": "ok"})


@app.route("/api/accounts/<acc_id>/connect", methods=["POST"])
def connect_account(acc_id):
    accounts = load_accounts()
    account = next((a for a in accounts if a["id"] == acc_id), None)
    if not account:
        return jsonify({"status": "error", "message": "账号不存在"})
    try:
        result = run_async(_connect_account(account), timeout=120)
        return jsonify(result)
    except asyncio.TimeoutError:
        return jsonify({"status": "error", "message": "连接超时，请检查网络"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route("/api/accounts/<acc_id>/disconnect", methods=["POST"])
def disconnect_account(acc_id):
    try:
        result = run_async(_disconnect_account(acc_id), timeout=10)
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route("/api/accounts/<acc_id>/submit_code", methods=["POST"])
def submit_code(acc_id):
    data = request.json
    code = data.get("code", "")
    password = data.get("password", "")
    try:
        result = run_async(_submit_code(acc_id, code, password), timeout=60)
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route("/api/accounts/<acc_id>/check", methods=["GET"])
def check_account(acc_id):
    """一键自检账号状态"""
    try:
        result = run_async(_check_account_status(acc_id), timeout=30)
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route("/api/accounts/connect_all", methods=["POST"])
def connect_all_accounts():
    """一键连接所有账号"""
    accounts = load_accounts()
    results = []
    for account in accounts:
        try:
            result = run_async(_connect_account(account), timeout=60)
            results.append({"id": account["id"], "result": result})
        except Exception as e:
            results.append({"id": account["id"], "result": {"status": "error", "message": str(e)}})
        time.sleep(0.5)  # 每个账号间隔0.5秒，减轻压力
    return jsonify({"status": "ok", "results": results})


# --- 关键词搜索群组 ---
@app.route("/api/search_groups", methods=["POST"])
def search_groups():
    data = request.json
    keyword = data.get("keyword", "")
    if not keyword:
        return jsonify({"status": "error", "message": "请输入关键词"})
    try:
        result = run_async(_search_groups(keyword), timeout=60)
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route("/api/groups", methods=["GET"])
def get_groups():
    groups = load_groups()
    return jsonify(groups)


@app.route("/api/groups/<group_id>", methods=["DELETE"])
def delete_group(group_id):
    groups = load_groups()
    groups = [g for g in groups if str(g.get("id")) != str(group_id)]
    save_groups(groups)
    return jsonify({"status": "ok"})


# --- 采集任务 ---
@app.route("/api/scrape/all", methods=["POST"])
def scrape_all_groups():
    """一键采集所有已发现的群组"""
    data = request.json or {}
    mode = data.get("mode", "members")
    groups = load_groups()
    if not groups:
        return jsonify({"status": "error", "message": "没有已发现的群组"})
    results = []
    for g in groups:
        link = "@" + g["username"] if g.get("username") else str(g.get("id", ""))
        if not link or link == "@":
            results.append({"link": str(g.get("title", "unknown")), "result": {"status": "error", "message": "无有效链接"}})
            continue
        try:
            if mode == "messages":
                result = run_async(_scrape_messages(link, limit=1000), timeout=300)
            else:
                result = run_async(_scrape_members(link), timeout=300)
            results.append({"link": link, "result": result})
        except Exception as e:
            results.append({"link": link, "result": {"status": "error", "message": str(e)}})
    # 记录任务（不保存members详情，只保存计数）
    tasks = load_tasks()
    task = {
        "id": f"task_{int(time.time())}",
        "type": f"all_{mode}",
        "links": [r["link"] for r in results],
        "results": results,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    tasks.append(task)
    save_tasks(tasks)
    return jsonify({"status": "ok", "results": results})


@app.route("/api/scrape/members", methods=["POST"])
def scrape_members():
    data = request.json
    links = data.get("links", [])
    if isinstance(links, str):
        links = [l.strip() for l in links.split("\n") if l.strip()]

    results = []
    for link in links:
        try:
            result = run_async(_scrape_members(link), timeout=300)
            results.append({"link": link, "result": result})
        except Exception as e:
            results.append({"link": link, "result": {"status": "error", "message": str(e)}})

    # 记录任务
    tasks = load_tasks()
    task = {
        "id": f"task_{int(time.time())}",
        "type": "members",
        "links": links,
        "results": results,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    tasks.append(task)
    save_tasks(tasks)

    return jsonify({"status": "ok", "results": results})


@app.route("/api/scrape/messages", methods=["POST"])
def scrape_messages():
    data = request.json
    links = data.get("links", [])
    limit = data.get("limit", 1000)
    if isinstance(links, str):
        links = [l.strip() for l in links.split("\n") if l.strip()]

    results = []
    for link in links:
        try:
            result = run_async(_scrape_messages(link, limit=limit), timeout=300)
            results.append({"link": link, "result": result})
        except Exception as e:
            results.append({"link": link, "result": {"status": "error", "message": str(e)}})

    # 记录任务
    tasks = load_tasks()
    task = {
        "id": f"task_{int(time.time())}",
        "type": "messages",
        "links": links,
        "limit": limit,
        "results": results,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    tasks.append(task)
    save_tasks(tasks)

    return jsonify({"status": "ok", "results": results})


# --- 24小时监听 ---
@app.route("/api/monitor/start", methods=["POST"])
def start_monitor():
    data = request.json
    account_ids = data.get("accounts", [])
    group_links = data.get("groups", [])

    if not account_ids:
        # 使用所有在线账号
        account_ids = [acc_id for acc_id, status in client_status.items() if status.get("status") == "online"]

    if not account_ids:
        return jsonify({"status": "error", "message": "没有在线账号可用"})

    try:
        result = run_async(_start_monitor(account_ids, group_links), timeout=30)
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route("/api/monitor/stop", methods=["POST"])
def stop_monitor():
    try:
        result = run_async(_stop_monitor(), timeout=10)
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route("/api/monitor/status", methods=["GET"])
def monitor_status():
    config = load_monitor_config()
    running = bool(config.get("enabled") or config.get("running") or globals().get("monitor_running"))
    config["running"] = running
    return jsonify(config)


# --- 数据统计与导出 ---
# 统计缓存
_stats_cache = {}
_stats_cache_time = 0


@app.route("/api/stats", methods=["GET"])
def get_stats():
    global _stats_cache, _stats_cache_time
    now = time.time()
    # 缓存30秒
    if now - _stats_cache_time < 30 and _stats_cache:
        return jsonify(_stats_cache)

    users = load_users_data()
    groups = load_groups()
    tasks_count = get_tasks_count()  # 只获取计数，不加载完整文件
    online_count = sum(1 for s in client_status.values() if s.get("status") == "online")
    total_accounts = len(load_accounts())

    _stats_cache = {
        "total_users": len(users),
        "total_usernames": sum(1 for u in users if u.get("username")),
        "total_groups": len(groups),
        "total_tasks": tasks_count,
        "online_accounts": online_count,
        "total_accounts": total_accounts,
        "monitor_running": monitor_running,
    }
    _stats_cache_time = now
    return jsonify(_stats_cache)


@app.route("/api/users", methods=["GET"])
def get_users():
    users = load_users_data()
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    start = (page - 1) * per_page
    end = start + per_page
    return jsonify({
        "total": len(users),
        "page": page,
        "per_page": per_page,
        "users": users[start:end]
    })


@app.route("/api/export/csv", methods=["GET"])
def export_csv():
    filepath, filename = export_users_csv()
    return send_file(filepath, as_attachment=True, download_name=filename)


@app.route("/api/export/txt", methods=["GET"])
def export_txt():
    filepath, filename = export_users_txt()
    return send_file(filepath, as_attachment=True, download_name=filename)


@app.route("/api/tasks", methods=["GET"])
def get_tasks():
    tasks = load_tasks()
    return jsonify(tasks[-20:])  # 最近20个任务


@app.route("/api/users/clear", methods=["POST"])
def clear_users():
    """清空采集数据"""
    save_users_data([])
    return jsonify({"status": "ok", "message": "数据已清空"})


# ============ 连接保活 ============
def _keepalive_worker():
    """后台保活线程 - 每60秒检查一次连接状态"""
    while True:
        time.sleep(60)
        for acc_id, client in list(clients.items()):
            try:
                if not client.is_connected():
                    future = asyncio.run_coroutine_threadsafe(client.connect(), loop)
                    future.result(timeout=15)
                    # 再确认是否仍已授权
                    auth_fut = asyncio.run_coroutine_threadsafe(client.is_user_authorized(), loop)
                    authorized = auth_fut.result(timeout=10)
                    if authorized:
                        logger.info("保活重连成功: %s", acc_id)
                        if acc_id in client_status:
                            client_status[acc_id]["status"] = "online"
                    else:
                        logger.warning("保活重连后未授权: %s", acc_id)
                        if acc_id in client_status:
                            client_status[acc_id]["status"] = "offline"
            except Exception as e:
                if acc_id in client_status:
                    client_status[acc_id]["status"] = "offline"
                logger.warning("保活检查失败 %s: %s", acc_id, e)


# ============ 启动 ============
def auto_connect_on_startup():
    """启动时自动连接所有账号，并恢复监听"""
    def _do_connect():
        time.sleep(5)  # 等待 Flask 启动
        accounts = load_accounts()
        for account in accounts:
            try:
                result = run_async(_connect_account(account), timeout=60)
                print(f"  自动连接 {account.get('phone')}: {result.get('status')}")
            except Exception as e:
                print(f"  自动连接 {account.get('phone')} 失败: {e}")
            time.sleep(2)  # 每个账号间隔2秒
        # 自动恢复24H监听
        try:
            monitor_config = load_monitor_config()
            if monitor_config.get("enabled"):
                time.sleep(3)
                online_ids = [acc_id for acc_id, status in client_status.items() if status.get("status") == "online"]
                if online_ids:
                    group_links = monitor_config.get("groups", [])
                    result = run_async(_start_monitor(online_ids, group_links), timeout=30)
                    print(f"  自动恢复24H监听: {result.get('message', 'ok')}, 账号数: {len(online_ids)}")
                else:
                    print("  无法恢复监听: 没有在线账号")
        except Exception as e:
            print(f"  自动恢复监听失败: {e}")
    threading.Thread(target=_do_connect, daemon=True).start()


if __name__ == "__main__":
    print("=" * 50)
    print("  TG 采集工具 Pro 版面板已启动")
    print("  访问地址: http://0.0.0.0:8090")
    print("=" * 50)

    # 预热统计缓存
    try:
        users = load_users_data()
        groups = load_groups()
        tasks_count = get_tasks_count()
        _stats_cache = {
            "total_users": len(users),
            "total_usernames": sum(1 for u in users if u.get("username")),
            "total_groups": len(groups),
            "total_tasks": tasks_count,
            "online_accounts": 0,
            "total_accounts": len(load_accounts()),
            "monitor_running": False,
        }
        _stats_cache_time = time.time()
        print(f"  缓存预热完成: {len(users)} 用户, {len(groups)} 群组, {tasks_count} 任务")
    except Exception as e:
        print(f"  缓存预热失败: {e}")

    # 启动保活线程
    keepalive_thread = threading.Thread(target=_keepalive_worker, daemon=True)
    keepalive_thread.start()
    print("  保活线程已启动（每60秒检查连接）")

    # 启动自动连接
    auto_connect_on_startup()

    app.run(host="0.0.0.0", port=8090, threaded=True)
