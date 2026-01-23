from utils.http_normalizer import HTTPNormalizer
from scapy.all import *
import re

STATIC_EXTENSIONS = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif",
    ".svg", ".woff", ".woff2", ".ttf", ".ico"
)

BASIC_SQLI_PATTERNS = [
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",  # SQL meta-characters
    r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",  # SQL operators
    r"\b(OR|AND)\b.+\=",  # Logical operators
    r"UNION(\s+ALL)?\s+SELECT",  # UNION SELECT
    r"SELECT\s+.*\s+FROM\s+",  # Basic SELECT statement
    r"INSERT\s+INTO\s+",  # Basic INSERT statement
    r"UPDATE\s+.*\s+SET\s+",  # Basic UPDATE statement
    r"DELETE\s+FROM\s+",  # Basic DELETE statement
    r"DROP\s+TABLE\s+",  # Basic DROP TABLE statement
]

ADVANCED_SQLI_PATTERNS = [
    r"sleep\(\s*\d+\s*\)", # Blind SQLi: SLEEP function
    r"benchmark\(\s*\d+.*\)", # Blind SQLi: Benchmark function (MySQL)
    r"information_schema\.", # Accessing schema tables
    r"concat\(", # Attempt to concatenate for injection
    r"version\(\)", # Database version probing
    r"if\s*\(.+\).+then", # Conditional SQLi (MSSQL)
    r"union\s+select\s+.*--", # UNION SELECT with comment
]

"""
Explanation: Thinking oppositely,
analyzing server responses for sql error msgs
that may indicate SQLi attempts
"""
ALL_SQL_ERRORS = [
    # --- MySQL / MariaDB ---
    r"you have an error in your sql syntax",
    r"check the manual that corresponds to your mysql server version",
    r"near '.+' at line \d+",
    r"mysql_fetch_(array|assoc|row)",
    r"warning:\s*mysql_",

    # --- PostgreSQL ---
    r"error:\s*syntax error at or near",
    r"line \d+:\s*",
    r"sqlstate:\s*42601",
    r"relation \".+\" does not exist",
    r"operator does not exist:",

    # --- Microsoft SQL Server ---
    r"incorrect syntax near",
    r"unclosed quotation mark after the character string",
    r"(microsoft ole db provider for sql server|odbc sql server driver)",
    r"invalid (object|column) name",

    # --- Oracle ---
    r"ora-\d{5}:",

    # --- SQLite ---
    r"sqlite_error",
    r"near \".+\": syntax error",
    r"unrecognized token:",
    r"incomplete input",
    r"no such column:",

    # --- Generic / Driver / Framework ---
    r"sqlstate\[[0-9a-z]{5}\]",
    r"(pdoexception|jdbc exception)",
    r"fatal error:\s*uncaught exception",
    r"supplied argument is not a valid (mysql|pgsql|mysqli)",
]

SQLI_PATTERNS = BASIC_SQLI_PATTERNS + ADVANCED_SQLI_PATTERNS + ALL_SQL_ERRORS

def is_valid(payload) -> bool:
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, payload, re.IGNORECASE):
            return False
    return True


def inspect(pkt):
    req = HTTPNormalizer.normalize(pkt)
    if not req:
        return None

    path = req.path.lower()

    # Ignore static files
    if path.endswith(STATIC_EXTENSIONS):
        return None

    # No user input -> No SQLi
    if "?" not in path and not req.body:
        return None

    if not is_valid(path) or not is_valid(req.body):
        return (
            f"src: {req.src} -> dst: {req.dst}\n"
            f"method: {req.method}\n"
            f"path: {req.path}\n"
            f"body: {req.body}\n"
        )


if __name__ == "__main__":
    from colorama import Fore, init as color_init
    color_init(autoreset=True)
    from os import system

    system('clear')
    print("SQL Injection Detection")
    
    # filter for HTTP traffic (port 80, 8080, 8000) + 12345 for debugging
    sniff(prn=inspect, store=0, filter="tcp port 80 or tcp port 8080 or tcp port 8000 or tcp port 12345")