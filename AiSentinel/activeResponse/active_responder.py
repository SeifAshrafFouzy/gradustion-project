# نسخة اننا نبعت تنبيه للتليجرام فى حالة تحديد هجوم 
from dotenv import load_dotenv
import sqlite3
import json
import os
import httpx
from datetime import datetime
from core.redis_client import redis_client as r 
import logging

# =========================================================
# Logging Configuration 
# =========================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("security_audit.log"), # بيكتب في ملف للأرشفة
        logging.StreamHandler()                    # بيظهر في الـ Terminal
    ]
)
logger = logging.getLogger(__name__)

# =========================================================
# Secrets (ENV ONLY)
# =========================================================
load_dotenv()

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

# =========================================================
# Telegram Alert (Async-safe)
# =========================================================
def send_telegram_alert(message, ip=None):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return False

    # Rate limiting (prevent spam)
    if r and ip:
        try:
            alert_key = f"alert_sent:{ip}" 
            if r.get(alert_key):
                return False 
            r.setex(alert_key, 30, "1")
        except Exception as e:
            logger.error(f"Redis Rate Limit Error: {e}")
            pass

    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"

    try:
        httpx.post(url, json={
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "HTML"
        }, timeout=5)
        return True
    except Exception as e:
        print(f"Telegram Error: {e}")
        return False

# =========================================================
# Save to DB (Thread-safe)
# =========================================================
def save_attack_to_db(log, source, reason, severity, timestamp):
    try:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        db_path = os.path.join(base_dir, 'users.db')

        #  تم تأمين الاتصال هنا بـ timeout=10 لضمان عدم حدوث Database locked 
        conn = sqlite3.connect(db_path, timeout=10, check_same_thread=False)
        cursor = conn.cursor()

        cursor.execute('''CREATE TABLE IF NOT EXISTS security_alerts 
                          (timestamp TEXT, source TEXT, ip TEXT, reason TEXT, severity TEXT, raw_log TEXT)''')

        ip = log.get("source_ip", "N/A")

        cursor.execute("INSERT INTO security_alerts VALUES (?, ?, ?, ?, ?, ?)",
                       (timestamp, source, ip, reason, severity, json.dumps(log)))

        conn.commit()
        conn.close()

    except Exception as e:
        print(f"DB Error: {e}")

# =========================================================
# Main Action Handler
# =========================================================
def take_action(log_entry, source, reason, severity):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip = log_entry.get("source_ip", "Unknown")
    
    clean_reason = reason if reason and str(reason).lower() != "normal" else "Suspicious Behavior Detected"

    # 🌟 تعديل مرن وذكي: فحص الكلمات المفتاحية دون التقيّد بالأقواس أو حالة الأحرف
    source_lower = str(source).lower()
    is_ai_attack = "threat" in source_lower or "anomaly" in source_lower
    
    # تحويل الـ severity لحالة موحدة للفحص
    sev_upper = str(severity).upper()
    
    if "HIGH" in sev_upper or "CRITICAL" in sev_upper or is_ai_attack:
        action_taken = "IP Blocked"
        # إذا لقطتها الـ Anomaly، نرفع الـ Severity لـ High تلقائياً ليظهر بوضوح
        if is_ai_attack and sev_upper not in ["HIGH", "CRITICAL"]:
            severity = "High"
            
        if r:
            try:
                r.setex(f"block:{ip}", 600, "blocked")
                action_taken += " (10m)"
            except Exception:
                action_taken = "Block Failed"
    else:
        action_taken = "Monitored"

    # --- Save to DB ---
    save_attack_to_db(log_entry, source, clean_reason, severity, timestamp)

    # --- Send Telegram Alert ---
    if "IP Blocked" in action_taken:
        alert_msg = (
            f"<b>🛡️ AiSentinel - Incident Triggered</b>\n"
            f"━━━━━━━━━━━━━━━\n"
            f" <b>Source Layer:</b> {source}\n"
            f" <b>Severity Tier:</b> {severity}\n"
            f" <b>Attack Type:</b> {clean_reason}\n"
            f" <b>Attacker IP:</b> <code>{ip}</code>\n"
            f" <b>Timestamp:</b> {timestamp}\n"
            f" <b>Enforced Action:</b> {action_taken}"
        )
        send_telegram_alert(alert_msg, ip)

    # --- Publish to dashboard ---
    if r:
        try:
            r.publish("security_alerts", json.dumps({
                "ip": ip,
                "reason": clean_reason,
                "severity": severity,
                "timestamp": timestamp,
                "action": action_taken
            }))
        except:
            pass

    print(f"Action: {severity} | IP: {ip} | Reason: {clean_reason} | Action Enforced: {action_taken}")
          



