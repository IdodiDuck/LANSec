from utils.http_normalizer import HTTPNormalizer
from scapy.all import sniff
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

def is_valid(payload: str) -> bool:
    """
    Validates the input string against a database of SQL injection signatures.

    :param payload: The string content (URL path or HTTP body) to be inspected.
    :return: False if a malicious SQL pattern is detected, True otherwise.
    """
    if not payload:
        return True

    # Iterating through all signature categories (Basic, Advanced, and Error-based)
    for pattern in SQLI_PATTERNS:
        # re.IGNORECASE prevents evasion via mixed-case (e.g., 'sElEcT')
        if re.search(pattern, payload, re.IGNORECASE):
            return False
    return True


def inspect(pkt):
    """
    The primary inspection hook for SQL injection detection. 
    Performs Deep Packet Inspection (DPI) at the Application Layer.

    :param pkt: The raw network packet captured by the sniffer.
    :return: A formatted alert string if an attack is detected, else None.
    """
    req = HTTPNormalizer.normalize(pkt)
    if not req:
        return None

    path = req.path.lower()

    # Skip inspection for static assets (images, fonts, etc.)
    if path.endswith(STATIC_EXTENSIONS):
        return None

    # SQLi requires input vectors. If no query or body exists, skip
    if "?" not in path and not req.body:
        return None

    # Inspecting both GET (Path) and POST (Body) vectors
    if not is_valid(path) or not is_valid(req.body):
        return (
            f"SQL Injection Attempt Detected!\n"
            f"Method: {req.method}\n"
            f"Path:   {req.path}\n"
            f"Body:   {req.body[:200] if req.body else '[No Body Content]'}"
        )

    return None


if __name__ == "__main__":
    """
    Standalone module entry point for testing and debugging.
    """
    from colorama import init as color_init
    from os import system
    from scapy.all import sniff

    color_init(autoreset=True)
    system('clear')
    
    print("SQL Injection Detection Engine Active...")
    print("Monitoring ports: 80, 8080, 8000, 12345")
    
    sniff(prn=lambda p: print(out) if (out := inspect(p)) else None, 
          store=0, 
          filter="tcp port 80 or tcp port 8080 or tcp port 8000 or tcp port 12345")