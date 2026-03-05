import os
import json
import time
import sqlite3
import asyncio
import threading
from typing import Any, Dict, Optional, List

import httpx
import discord
from fastapi import FastAPI, Request, HTTPException
import uvicorn
from concurrent.futures import Future as CFuture

TOKEN = os.getenv("DISCORD_BOT_TOKEN")
ALERT_CHANNEL_ID_RAW = os.getenv("DISCORD_ALERT_CHANNEL_ID", "")
ALERT_CHANNEL_ID = int(ALERT_CHANNEL_ID_RAW) if ALERT_CHANNEL_ID_RAW.isdigit() else 0

BRIDGE = os.getenv("AI_BRIDGE_URL", "http://127.0.0.1:9000")
LISTEN_PORT = int(os.getenv("BOT_LISTEN_PORT", "9100"))

DB_PATH = os.getenv("DISCORD_BOT_DB", "/opt/ai-bridge/discord_bot.sqlite3")
HTTP_TIMEOUT = float(os.getenv("BOT_HTTP_TIMEOUT", "10"))
MAX_DISCORD_CHARS = 1900
AUTO_ARCHIVE_MINUTES = int(os.getenv("THREAD_AUTO_ARCHIVE_MIN", "1440"))

if not TOKEN or ALERT_CHANNEL_ID == 0:
    raise RuntimeError("DISCORD_BOT_TOKEN / DISCORD_ALERT_CHANNEL_ID must be set (channel ID must be numeric).")

api = FastAPI()
shutdown_event = asyncio.Event()  # graceful shutdown signal

# --- SQLite ---
def db_init():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS incidents (
            thread_id TEXT PRIMARY KEY,
            incident_json TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
        """
    )
    con.commit()
    con.close()

def db_put_incident(thread_id: str, incident: Dict[str, Any]):
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(
        "INSERT OR REPLACE INTO incidents(thread_id, incident_json, created_at) VALUES (?, ?, ?)",
        (thread_id, json.dumps(incident, ensure_ascii=False), int(time.time())),
    )
    con.commit()
    con.close()

def db_get_incident(thread_id: str) -> Optional[Dict[str, Any]]:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT incident_json FROM incidents WHERE thread_id = ?", (thread_id,))
    row = cur.fetchone()
    con.close()
    if not row:
        return None
    try:
        return json.loads(row[0])
    except Exception:
        return None

db_init()

# --- Discord ---
intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)

# --- Queue handoff ---
incident_queue: asyncio.Queue = asyncio.Queue()

# --- key aliases (lightweight) ---
ALIASES: Dict[str, List[str]] = {
    "host": ["host", "hostname", "device", "src_host", "dest_host"],
    "src_ip": ["src_ip", "src", "srcip", "source_ip", "client_ip"],
    "dest_ip": ["dest_ip", "dst", "dstip", "destination_ip", "server_ip"],
    "signature": ["signature", "alert", "rule", "message", "event_name"],
}

def pick_value(d: Dict[str, Any], keys: List[str]) -> Optional[Any]:
    for k in keys:
        if k in d and d.get(k) not in (None, ""):
            return d.get(k)
    return None

def _safe_json(obj: Any, limit: int = 1400) -> str:
    try:
        s = json.dumps(obj, ensure_ascii=False, indent=2)
    except Exception:
        s = str(obj)
    if len(s) > limit:
        s = s[:limit] + "\n...<truncated>..."
    return s

def _clip(msg: str) -> str:
    if len(msg) <= MAX_DISCORD_CHARS:
        return msg
    return msg[:MAX_DISCORD_CHARS] + "\n...<truncated>..."

def build_card_text(incident: Dict[str, Any]) -> str:
    title = incident.get("title", "Splunk Alert")
    sev = incident.get("severity", "info")

    r = incident.get("result", {})
    if not isinstance(r, dict):
        r = {}

    host = pick_value(r, ALIASES["host"]) or incident.get("host")
    src = pick_value(r, ALIASES["src_ip"]) or incident.get("src_ip")
    dst = pick_value(r, ALIASES["dest_ip"]) or incident.get("dest_ip")
    sig = pick_value(r, ALIASES["signature"]) or incident.get("signature")

    lines = [f"🚨 **{title}**", f"- severity: `{sev}`"]
    if host: lines.append(f"- host: `{host}`")
    if src:  lines.append(f"- src: `{src}`")
    if dst:  lines.append(f"- dst: `{dst}`")
    if sig:  lines.append(f"- signature: `{sig}`")
    lines.append("")
    lines.append("이 스레드에서 질문해줘. 예) `FP 가능성?` `대응 순서` `SPL 추천`")
    return "\n".join(lines)

async def create_thread_for_incident(incident: Dict[str, Any]) -> Dict[str, str]:
    channel = client.get_channel(ALERT_CHANNEL_ID) or await client.fetch_channel(ALERT_CHANNEL_ID)
    card = build_card_text(incident)

    msg = await channel.send(card)
    thread_name = incident.get("thread_name") or f"incident-{incident.get('id','new')}"
    thread = await msg.create_thread(name=thread_name, auto_archive_duration=AUTO_ARCHIVE_MINUTES)

    db_put_incident(str(thread.id), incident)
    await thread.send("원본 이벤트(요약):\n```json\n" + _safe_json(incident, 1500) + "\n```")

    return {"thread_id": str(thread.id), "message_id": str(msg.id)}

async def incident_worker():
    while True:
        item = await incident_queue.get()
        if item is None:
            break

        incident, cfut = item
        try:
            res = await create_thread_for_incident(incident)
            if not cfut.done():
                cfut.set_result({"ok": True, **res})
        except Exception as e:
            if not cfut.done():
                cfut.set_result({"ok": False, "error": str(e)})
        finally:
            incident_queue.task_done()

@api.post("/incident/new")
async def incident_new(req: Request):
    if client.user is None:
        raise HTTPException(503, "Discord client not ready yet")

    incident = await req.json()

    # ❌ asyncio.Future 사용 금지
    # ✅ concurrent.futures.Future 사용
    cfut = CFuture()

    def _enqueue():
        incident_queue.put_nowait((incident, cfut))

    # 디스코드 루프에서 안전하게 큐에 넣기
    client.loop.call_soon_threadsafe(_enqueue)

    try:
        # FastAPI 루프에서 안전하게 결과 대기
        loop = asyncio.get_running_loop()
        result = await asyncio.wait_for(
            loop.run_in_executor(None, cfut.result),
            timeout=15
        )
        return result
    except asyncio.TimeoutError:
        return {"ok": False, "error": "timeout creating thread"}

@client.event
async def on_ready():
    print("Logged in as", client.user)
    client.loop.create_task(incident_worker())

async def ask_bridge(thread_id: str, user_text: str) -> str:
    incident = db_get_incident(thread_id) or {}
    payload = {"thread_id": thread_id, "user_text": user_text, "incident": incident}

    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as s:
        r = await s.post(f"{BRIDGE}/chat/analyze", json=payload)
        if r.status_code >= 300:
            return _clip(f"Bridge error {r.status_code}: {r.text[:300]}")
        data = r.json()

    if isinstance(data, dict):
        if "answer" in data and isinstance(data["answer"], str):
            return _clip(data["answer"].strip())
        return _clip("```json\n" + _safe_json(data, 1600) + "\n```")

    return _clip(str(data))

@client.event
async def on_message(message: discord.Message):
    if message.author.bot:
        return

    if message.guild is None:
        await message.channel.send("서버의 incident 스레드에서 질문하면 분석해줄게.")
        return

    if isinstance(message.channel, discord.Thread):
        async with message.channel.typing():
            try:
                answer = await ask_bridge(str(message.channel.id), message.content)
            except Exception as e:
                answer = _clip(f"⚠️ analyze failed: `{type(e).__name__}` `{e}`")
        await message.channel.send(answer)
        return

    if client.user and client.user.mentioned_in(message):
        await message.channel.send("알람 채널에 올라온 **incident 스레드에서** 질문하면 분석해줄게.")

def run_api():
    uvicorn.run(api, host="0.0.0.0", port=LISTEN_PORT, log_level="info")

if __name__ == "__main__":
    # FastAPI in background thread
    threading.Thread(target=run_api, daemon=True).start()
    try:
        client.run(TOKEN)
    finally:
        # best effort graceful worker stop
        try:
            loop = client.loop
            if loop and loop.is_running():
                loop.call_soon_threadsafe(shutdown_event.set)
                loop.call_soon_threadsafe(lambda: incident_queue.put_nowait(None))
        except Exception:
            pass
