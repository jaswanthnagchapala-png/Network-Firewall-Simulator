
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "firewall.db"


def get_connection():
    connection = sqlite3.connect(
        DB_PATH,
        timeout=15
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database(default_rules):
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS firewall_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                protocol TEXT NOT NULL,
                port INTEGER,
                action TEXT NOT NULL
                    CHECK (action IN ('ALLOW', 'BLOCK')),
                priority INTEGER NOT NULL
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS packet_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL DEFAULT (
                    strftime(
                        '%Y-%m-%d %H:%M:%S',
                        'now',
                        'localtime'
                    )
                ),
                source_ip TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                protocol TEXT NOT NULL,
                port INTEGER NOT NULL DEFAULT 0,
                decision TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS security_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL DEFAULT (
                    strftime(
                        '%Y-%m-%d %H:%M:%S',
                        'now',
                        'localtime'
                    )
                ),
                source_ip TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                details TEXT NOT NULL,
                occurrence_count INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL DEFAULT 'OPEN'
                    CHECK (
                        status IN (
                            'OPEN',
                            'ACKNOWLEDGED',
                            'RESOLVED'
                        )
                    )
            )
        """)

        count = connection.execute(
            "SELECT COUNT(*) FROM firewall_rules"
        ).fetchone()[0]

        if count == 0:
            for priority, rule in enumerate(
                default_rules,
                start=1
            ):
                connection.execute("""
                    INSERT INTO firewall_rules (
                        source_ip,
                        destination_ip,
                        protocol,
                        port,
                        action,
                        priority
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    rule["source_ip"],
                    rule["destination_ip"],
                    rule["protocol"],
                    rule.get("port"),
                    rule["action"],
                    priority,
                ))


def get_rules():
    with get_connection() as connection:
        rows = connection.execute("""
            SELECT *
            FROM firewall_rules
            ORDER BY priority ASC, id ASC
        """).fetchall()

    return [dict(row) for row in rows]


def add_rule(rule):
    """Add a new rule at the highest priority."""
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")

        connection.execute("""
            UPDATE firewall_rules
            SET priority = priority + 1
        """)

        connection.execute("""
            INSERT INTO firewall_rules (
                source_ip,
                destination_ip,
                protocol,
                port,
                action,
                priority
            )
            VALUES (?, ?, ?, ?, ?, 1)
        """, (
            rule["source_ip"],
            rule["destination_ip"],
            rule["protocol"],
            rule.get("port"),
            rule["action"],
        ))


def delete_rule(rule_id):
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")

        connection.execute(
            "DELETE FROM firewall_rules WHERE id = ?",
            (int(rule_id),)
        )

        rows = connection.execute("""
            SELECT id
            FROM firewall_rules
            ORDER BY priority ASC, id ASC
        """).fetchall()

        # Assign temporary priorities first.
        for row in rows:
            connection.execute("""
                UPDATE firewall_rules
                SET priority = ?
                WHERE id = ?
            """, (-row["id"], row["id"]))

        # Restore sequential priorities.
        for priority, row in enumerate(rows, start=1):
            connection.execute("""
                UPDATE firewall_rules
                SET priority = ?
                WHERE id = ?
            """, (priority, row["id"]))


def reorder_rules(rule_ids):
    rule_ids = [int(rule_id) for rule_id in rule_ids]

    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")

        existing_ids = {
            row["id"]
            for row in connection.execute(
                "SELECT id FROM firewall_rules"
            ).fetchall()
        }

        if (
            len(rule_ids) != len(existing_ids)
            or set(rule_ids) != existing_ids
        ):
            raise ValueError("Invalid rule order.")

        # Move all priorities temporarily out of the normal range.
        for index, rule_id in enumerate(
            rule_ids,
            start=1
        ):
            connection.execute("""
                UPDATE firewall_rules
                SET priority = ?
                WHERE id = ?
            """, (-100000 - index, rule_id))

        for priority, rule_id in enumerate(
            rule_ids,
            start=1
        ):
            connection.execute("""
                UPDATE firewall_rules
                SET priority = ?
                WHERE id = ?
            """, (priority, rule_id))


def save_packet_log(packet):
    with get_connection() as connection:
        connection.execute("""
            INSERT INTO packet_logs (
                source_ip,
                destination_ip,
                protocol,
                port,
                decision,
                reason
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            packet["source_ip"],
            packet["destination_ip"],
            packet["protocol"],
            int(packet.get("port") or 0),
            packet["decision"],
            packet["reason"],
        ))


def get_packet_logs(limit=None):
    query = """
        SELECT *
        FROM packet_logs
        ORDER BY id DESC
    """

    parameters = ()

    if limit is not None:
        query += " LIMIT ?"
        parameters = (int(limit),)

    with get_connection() as connection:
        rows = connection.execute(
            query,
            parameters
        ).fetchall()

    return [dict(row) for row in rows]


def clear_packet_logs():
    with get_connection() as connection:
        connection.execute("DELETE FROM packet_logs")


def record_security_alert(
    source_ip,
    alert_type,
    severity,
    details,
    occurrence_count=1
):
    """Update an open alert for the same source and type,
    or create a new alert.
    """
    with get_connection() as connection:
        existing = connection.execute("""
            SELECT id, occurrence_count
            FROM security_alerts
            WHERE source_ip = ?
              AND alert_type = ?
              AND status = 'OPEN'
            ORDER BY id DESC
            LIMIT 1
        """, (
            source_ip,
            alert_type
        )).fetchone()

        if existing:
            new_count = max(
                int(occurrence_count),
                existing["occurrence_count"]
            )

            connection.execute("""
                UPDATE security_alerts
                SET occurrence_count = ?,
                    severity = ?,
                    details = ?,
                    timestamp = strftime(
                        '%Y-%m-%d %H:%M:%S',
                        'now',
                        'localtime'
                    )
                WHERE id = ?
            """, (
                new_count,
                severity,
                details,
                existing["id"],
            ))

        else:
            connection.execute("""
                INSERT INTO security_alerts (
                    source_ip,
                    alert_type,
                    severity,
                    details,
                    occurrence_count
                )
                VALUES (?, ?, ?, ?, ?)
            """, (
                source_ip,
                alert_type,
                severity,
                details,
                int(occurrence_count),
            ))


def get_security_alerts():
    with get_connection() as connection:
        rows = connection.execute("""
            SELECT *
            FROM security_alerts
            ORDER BY id DESC
        """).fetchall()

    return [dict(row) for row in rows]


def update_alert_status(alert_id, status):
    status = str(status).upper()

    if status not in {
        "OPEN",
        "ACKNOWLEDGED",
        "RESOLVED"
    }:
        raise ValueError("Invalid alert status.")

    with get_connection() as connection:
        connection.execute("""
            UPDATE security_alerts
            SET status = ?
            WHERE id = ?
        """, (
            status,
            int(alert_id)
        ))


def clear_security_alerts():
    with get_connection() as connection:
        connection.execute("DELETE FROM security_alerts")
