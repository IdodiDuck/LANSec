from scapy.layers.inet import TCP
from scapy.packet import Raw

class NormalizedHTTPRequest:
    """
    A data structure representing a parsed and normalized HTTP request.
    This object makes it easier to run security signatures against specific 
    parts of the request (e.g., inspecting the 'path' for Directory Traversal).
    """
    def __init__(self, method, path, headers, body, src, dst):
        self.method = method    # HTTP Method (GET, POST, etc.)
        self.path = path        # Requested URL path
        self.headers = headers  # Dictionary of HTTP headers
        self.body = body        # Request payload/body
        self.src = src          # Source IP address
        self.dst = dst          # Destination IP address

class HTTPNormalizer:
    """
    Static utility class used to identify and parse HTTP traffic 
    from raw network packets captured by Scapy.
    """

    # Supported HTTP methods for identification
    HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]

    @staticmethod
    def normalize(pkt):
        """
        Attempts to transform a raw Scapy packet into a NormalizedHTTPRequest.
        
        :param pkt: The raw Scapy packet captured from the network.
        :return: A NormalizedHTTPRequest object if valid HTTP, otherwise None.
        """
        # Ensure the packet contains both a TCP layer and a data payload (Raw)
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return None

        # Extract the raw byte payload
        payload = pkt.getlayer(Raw).load

        # Decode the byte stream into a string, ignoring non-ASCII characters
        try:
            text = payload.decode(errors="ignore")
        except Exception:
            return None

        # Quick validation: check if the text starts with a known HTTP method
        if not any(text.startswith(m) for m in HTTPNormalizer.HTTP_METHODS):
            return None

        # Proceed to detailed parsing of the HTTP structure
        return HTTPNormalizer._parse_http_request(text, pkt)

    @staticmethod
    def _parse_http_request(text, pkt):
        """
        Parses the raw HTTP text into its constituent parts: Request Line, Headers, and Body.
        
        :param text: The decoded string representation of the HTTP payload.
        :param pkt: The original Scapy packet (used for IP metadata).
        :return: NormalizedHTTPRequest object.
        """
        # HTTP lines are delimited by Carriage Return + Line Feed (\r\n)
        lines = text.split("\r\n")
        if not lines:
            return None

        # Parse the Request Line: [METHOD] [PATH] [VERSION]
        # Example: "GET /index.html HTTP/1.1"
        request_line = lines[0]
        parts = request_line.split(" ")
        if len(parts) < 2:
            return None

        method = parts[0]
        path = parts[1]

        headers = {}
        body = ""
        header_done = False

        # Iterate through the lines to separate Headers from the Body
        for line in lines[1:]:
            # An empty line marks the boundary between Headers and the Body
            if line == "":
                header_done = True
                continue

            if not header_done:
                # Parse header fields into a dictionary (Key: Value)
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip()] = v.strip()
            else:
                # Accumulate the remaining text as the request Body
                body += line + "\n"

        # Construct the normalized object including IP metadata from the Scapy packet
        return NormalizedHTTPRequest(
            method=method,
            path=path,
            headers=headers,
            body=body.strip(),
            src=pkt[0][1].src,
            dst=pkt[0][1].dst
        )