import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo


DATABASE_PATH = Path(__file__).parent / "vendor_risk.db"


def get_connection():
    """
    SQLite veritabanı bağlantısını oluşturur.
    """

    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row

    return connection


def init_database():
    """
    Analiz sonuçlarının saklanacağı tabloyu oluşturur.
    Tablo zaten varsa tekrar oluşturmaz.
    """

    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS vendor_analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                requested_url TEXT,
                url TEXT NOT NULL,
                title TEXT,
                status_code INTEGER,
                server TEXT,

                https INTEGER,
                ssl_valid INTEGER,
                ssl_subject TEXT,
                ssl_issuer TEXT,
                ssl_not_before TEXT,
                ssl_not_after TEXT,
                ssl_days_remaining INTEGER,
                ssl_error TEXT,

                security_header_count INTEGER,
                security_header_total INTEGER,
                security_headers TEXT,

                privacy INTEGER,
                terms INTEGER,
                contact INTEGER,

                score INTEGER,
                risk_level TEXT,

                findings TEXT,
                recommendations TEXT,
                ai_summary TEXT,

                created_at TEXT NOT NULL
            )
            """
        )

        connection.commit()


def save_analysis(
    analysis,
    score,
    risk_level,
    report,
):
    """
    Yeni vendor analizini veritabanına kaydeder.
    Oluşturulan kayıt ID'sini döndürür.
    """

    created_at = datetime.now(
        timezone.utc
    ).isoformat(timespec="seconds")

    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO vendor_analyses (
                requested_url,
                url,
                title,
                status_code,
                server,

                https,
                ssl_valid,
                ssl_subject,
                ssl_issuer,
                ssl_not_before,
                ssl_not_after,
                ssl_days_remaining,
                ssl_error,

                security_header_count,
                security_header_total,
                security_headers,

                privacy,
                terms,
                contact,

                score,
                risk_level,

                findings,
                recommendations,
                ai_summary,

                created_at
            )
            VALUES (
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?,
                ?, ?,
                ?, ?, ?,
                ?
            )
            """,
            (
                analysis.get("requested_url"),
                analysis.get("url"),
                analysis.get("title"),
                analysis.get("status_code"),
                analysis.get("server"),

                int(bool(analysis.get("https"))),
                int(bool(analysis.get("ssl_valid"))),
                analysis.get("ssl_subject"),
                analysis.get("ssl_issuer"),
                analysis.get("ssl_not_before"),
                analysis.get("ssl_not_after"),
                analysis.get("ssl_days_remaining"),
                analysis.get("ssl_error"),

                analysis.get(
                    "security_header_count",
                    0,
                ),
                analysis.get(
                    "security_header_total",
                    0,
                ),
                json.dumps(
                    analysis.get(
                        "security_headers",
                        {},
                    ),
                    ensure_ascii=False,
                ),

                int(bool(analysis.get("privacy"))),
                int(bool(analysis.get("terms"))),
                int(bool(analysis.get("contact"))),

                score,
                risk_level,

                json.dumps(
                    report.get("findings", []),
                    ensure_ascii=False,
                ),
                json.dumps(
                    report.get(
                        "recommendations",
                        [],
                    ),
                    ensure_ascii=False,
                ),
                None,

                created_at,
            ),
        )

        connection.commit()

        return cursor.lastrowid


def update_ai_summary(
    analysis_id,
    ai_summary,
):
    """
    Mevcut analiz kaydına AI özetini ekler.
    """

    with get_connection() as connection:
        connection.execute(
            """
            UPDATE vendor_analyses
            SET ai_summary = ?
            WHERE id = ?
            """,
            (
                ai_summary,
                analysis_id,
            ),
        )

        connection.commit()


def get_analysis_history(limit=100):
    """
    Son analizleri yeni tarihten eski tarihe doğru getirir.
    """

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                id,
                url,
                title,
                score,
                risk_level,
                ssl_valid,
                security_header_count,
                security_header_total,
                created_at
            FROM vendor_analyses
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [
        dict(row)
        for row in rows
    ]


def get_analysis_by_id(analysis_id):
    """
    Belirtilen analiz kaydının bütün detaylarını getirir.
    """

    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT *
            FROM vendor_analyses
            WHERE id = ?
            """,
            (analysis_id,),
        ).fetchone()

    if row is None:
        return None

    result = dict(row)

    result["security_headers"] = json.loads(
        result.get("security_headers") or "{}"
    )

    result["findings"] = json.loads(
        result.get("findings") or "[]"
    )

    result["recommendations"] = json.loads(
        result.get("recommendations") or "[]"
    )

    return result


def get_vendor_score_history(url):
    """
    Belirtilen vendor için geçmiş skorları
    eski tarihten yeni tarihe doğru getirir.
    """

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                id,
                url,
                score,
                risk_level,
                created_at
            FROM vendor_analyses
            WHERE url = ?
            ORDER BY created_at ASC, id ASC
            """,
            (url,),
        ).fetchall()

    return [
        dict(row)
        for row in rows
    ]


def parse_created_at(created_at):
    """
    UTC ISO tarihini Türkiye saatine çevirir.
    """

    if not created_at:
        return None

    parsed_date = datetime.fromisoformat(
        created_at
    )

    if parsed_date.tzinfo is None:
        parsed_date = parsed_date.replace(
            tzinfo=timezone.utc
        )

    return parsed_date.astimezone(
        ZoneInfo("Europe/Istanbul")
    )


def format_created_at(created_at):
    """
    Detay ve tablo için okunabilir tarih üretir.
    """

    if not created_at:
        return "Bilinmiyor"

    try:
        turkey_time = parse_created_at(
            created_at
        )

        return turkey_time.strftime(
            "%d.%m.%Y %H:%M:%S"
        )

    except (ValueError, TypeError):
        return created_at


def format_chart_date(created_at):
    """
    Grafik için kısa tarih formatı üretir.
    """

    if not created_at:
        return "Bilinmiyor"

    try:
        turkey_time = parse_created_at(
            created_at
        )

        return turkey_time.strftime(
            "%d.%m %H:%M:%S"
        )

    except (ValueError, TypeError):
        return created_at