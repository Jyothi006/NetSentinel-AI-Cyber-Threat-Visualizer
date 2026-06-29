import os
import sqlite3
import datetime
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

DB_TYPE = "sqlite"

SQLITE_PATH = os.path.join(
    os.path.dirname(__file__),
    "netsentinel.db"
)


def init_db():
    """Initialize SQLite database"""
    _init_sqlite()
    logging.info("SQLite database ready")


def _init_sqlite():

    conn = sqlite3.connect(SQLITE_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        src_ip TEXT,
        dest_ip TEXT,
        protocol TEXT,
        packet_size INTEGER,
        connection_count INTEGER,
        duration REAL,
        threat_level TEXT,
        threat_score REAL,
        category TEXT,
        reason TEXT
    )
    """)

    # Ensure connection_count column exists for backwards compatibility
    try:
        cursor.execute("ALTER TABLE alerts ADD COLUMN connection_count INTEGER")
    except sqlite3.OperationalError:
        pass

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS stats(
        key TEXT PRIMARY KEY,
        value INTEGER
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """)


    for key in [
        "total_packets",
        "normal_packets",
        "threat_packets"
    ]:
        cursor.execute(
            "INSERT OR IGNORE INTO stats VALUES(?,0)",
            (key,)
        )


    conn.commit()
    conn.close()



def increment_stats(is_threat=False):

    conn = sqlite3.connect(SQLITE_PATH)
    cursor = conn.cursor()


    cursor.execute(
        "UPDATE stats SET value=value+1 WHERE key='total_packets'"
    )


    if is_threat:
        cursor.execute(
            "UPDATE stats SET value=value+1 WHERE key='threat_packets'"
        )
    else:
        cursor.execute(
            "UPDATE stats SET value=value+1 WHERE key='normal_packets'"
        )


    conn.commit()
    conn.close()



def save_alert(alert):

    if "timestamp" not in alert:
        alert["timestamp"] = datetime.datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )


    conn = sqlite3.connect(SQLITE_PATH)
    cursor = conn.cursor()

    cursor.execute("PRAGMA table_info(alerts)")
    columns = [row[1] for row in cursor.fetchall()]

    if "conn_freq" in columns and "connection_count" in columns:
        cursor.execute("""
        INSERT INTO alerts(
        timestamp,src_ip,dest_ip,protocol,
        packet_size,connection_count,conn_freq,
        duration,threat_level,
        threat_score,category,reason
        )
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            alert["timestamp"],
            alert["src_ip"],
            alert["dest_ip"],
            alert["protocol"],
            alert["packet_size"],
            alert.get("connection_count",0),
            alert.get("conn_freq", alert.get("connection_count", 0)),
            alert.get("duration",0),
            alert["threat_level"],
            alert["threat_score"],
            alert["category"],
            alert["reason"]
        ))
    elif "conn_freq" in columns:
        cursor.execute("""
        INSERT INTO alerts(
        timestamp,src_ip,dest_ip,protocol,
        packet_size,conn_freq,
        duration,threat_level,
        threat_score,category,reason
        )
        VALUES(?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            alert["timestamp"],
            alert["src_ip"],
            alert["dest_ip"],
            alert["protocol"],
            alert["packet_size"],
            alert.get("conn_freq", alert.get("connection_count", 0)),
            alert.get("duration",0),
            alert["threat_level"],
            alert["threat_score"],
            alert["category"],
            alert["reason"]
        ))
    else:
        cursor.execute("""
        INSERT INTO alerts(
        timestamp,src_ip,dest_ip,protocol,
        packet_size,connection_count,
        duration,threat_level,
        threat_score,category,reason
        )
        VALUES(?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            alert["timestamp"],
            alert["src_ip"],
            alert["dest_ip"],
            alert["protocol"],
            alert["packet_size"],
            alert.get("connection_count",0),
            alert.get("duration",0),
            alert["threat_level"],
            alert["threat_score"],
            alert["category"],
            alert["reason"]
        ))

    conn.commit()
    conn.close()


    return alert



def get_recent_alerts(limit=50):

    conn = sqlite3.connect(SQLITE_PATH)
    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM alerts ORDER BY id DESC LIMIT ?",
        (limit,)
    )


    data = [
        dict(row)
        for row in cursor.fetchall()
    ]

    conn.close()

    return data




def get_stats():

    conn = sqlite3.connect(SQLITE_PATH)
    cursor = conn.cursor()


    cursor.execute(
        "SELECT key,value FROM stats"
    )

    rows = cursor.fetchall()

    conn.close()


    stats = dict(rows)


    total = stats.get("total_packets",0)
    normal = stats.get("normal_packets",0)
    threats = stats.get("threat_packets",0)


    risk = 0

    if total:
        risk = threats / total * 100


    return {

        "total_packets": total,

        "normal_packets": normal,

        "threat_packets": threats,

        "threats_detected": threats,

        "risk_percentage": round(risk,2)

    }




def clear_logs():

    conn = sqlite3.connect(SQLITE_PATH)
    cursor = conn.cursor()


    cursor.execute("DELETE FROM alerts")


    cursor.execute(
        "UPDATE stats SET value=0"
    )


    conn.commit()
    conn.close()


def create_user(username, email, password_hash):
    conn = sqlite3.connect(SQLITE_PATH)
    cursor = conn.cursor()
    created_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    success = False
    try:
        cursor.execute(
            "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (username, email, password_hash, created_at)
        )
        conn.commit()
        success = True
    except sqlite3.IntegrityError:
        success = False
    finally:
        conn.close()
    return success


def get_user_by_username(username):
    conn = sqlite3.connect(SQLITE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None
