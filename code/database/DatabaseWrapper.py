import sqlite3
import os
from typing import Any, Dict, Tuple, Optional

from utils.logger import info, error

class DatabaseWrapper:
    def __init__(self, db_path: str = "Database/LANSecDB.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._initialize_db()

    def _connect(self) -> sqlite3.Connection:
        """Create a new database connection (safe for short operations)."""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute("PRAGMA foreign_keys = ON;")
            return conn
        
        except Exception as e:
            error(f"Failed to connect to database: {e}")
            raise

    def execute_query(self, query: str, params: Tuple = (), fetch: bool = False):
        """Execute any SQL query. If fetch=True, return results."""
        try:
            with self._connect() as conn:
                cursor = conn.cursor()
                cursor.execute(query, params)
                conn.commit()

                if fetch:
                    results = cursor.fetchall()
                    info(f"Executed query (fetch): {query} | params: {params} | results: {results}")
                    return results
                else:

                    info(f"Executed query: {query} | params: {params}")

        except Exception as e:
            error(f"Query failed: {query} | params: {params} | error: {e}")
            raise

    # ------------------- CRUD -------------------

    def insert(self, table: str, data: Dict[str, Any]):
        """Insert new record into table."""
        try:
            cols = ", ".join(data.keys())
            placeholders = ", ".join(["?"] * len(data))
            query = f"INSERT INTO {table} ({cols}) VALUES ({placeholders})"
            self.execute_query(query, tuple(data.values()))
            info(f"Inserted into {table}: {data}")

        except Exception as e:
            error(f"Insert failed in table {table}: {e}")
            raise

    def update(self, table: str, data: Dict[str, Any], where: str, params: Tuple = ()):
        """Update records in table."""
        try:
            set_clause = ", ".join([f"{col}=?" for col in data.keys()])
            query = f"UPDATE {table} SET {set_clause} WHERE {where}"
            self.execute_query(query, tuple(data.values()) + params)
            info(f"Updated {table} set {data} where {where} params {params}")

        except Exception as e:
            error(f"Update failed in table {table}: {e}")
            raise

    def delete(self, table: str, where: str, params: Tuple = ()):
        """Delete records from table."""
        try:
            query = f"DELETE FROM {table} WHERE {where}"
            self.execute_query(query, params)
            info(f"Deleted from {table} where {where} params {params}")

        except Exception as e:
            error(f"Delete failed in table {table}: {e}")
            raise

    def select(self, table: str, where: Optional[str] = None, params: Tuple = ()):
        """Select records from table."""
        try:
            query = f"SELECT * FROM {table}"
            if where:
                query += f" WHERE {where}"

            results = self.execute_query(query, params, fetch=True)
            info(f"Selected from {table} where {where} params {params} | results count: {len(results)}")
            return results
        
        except Exception as e:
            error(f"Select failed from table {table}: {e}")
            raise

    # ------------------- Database Initialization -------------------

    def _initialize_db(self):
        """Initialize all tables in a single transaction."""
        try:
            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute("BEGIN;")

            cursor.executescript("""
            CREATE TABLE IF NOT EXISTS Devices (
                deviceId INTEGER PRIMARY KEY AUTOINCREMENT,
                IP_Address TEXT NOT NULL UNIQUE,
                MAC_Address TEXT NOT NULL UNIQUE,
                Host_Name TEXT,
                Status TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS Detections (
                detectionId INTEGER PRIMARY KEY AUTOINCREMENT,
                detectionMethod TEXT NOT NULL,
                attackType TEXT NOT NULL,
                severity INTEGER NOT NULL CHECK(severity >= 1 AND severity <= 5),
                dstIp TEXT,
                timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                status TEXT NOT NULL,
                deviceId INTEGER NOT NULL,
                FOREIGN KEY(deviceId) REFERENCES Devices(deviceId) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS Statistics (
                statId INTEGER PRIMARY KEY AUTOINCREMENT,
                deviceId INTEGER NOT NULL,
                packetsSent INTEGER NOT NULL,
                packetsReceived INTEGER NOT NULL,
                timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(deviceId) REFERENCES Devices(deviceId) ON DELETE CASCADE
            );
            """)

            conn.commit()
            info("Database initialized successfully")

        except Exception as e:
            conn.rollback()
            error(f"Database initialization failed: {e}")
            raise # Raise in order to report that the DB is invalid

        finally:
            conn.close()
