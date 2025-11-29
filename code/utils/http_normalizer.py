from scapy.layers.inet import TCP
from scapy.packet import Raw


class NormalizedHTTPRequest:
    def __init__(self, method, path, headers, body, src, dst):
        self.method = method
        self.path = path
        self.headers = headers # HTTP headers as a dictionary
        self.body = body
        self.src = src
        self.dst = dst


class HTTPNormalizer:

    # List of valid HTTP methods
    HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]

    @staticmethod
    def normalize(pkt):
        # Only process packets that have TCP and Raw payload
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return None

        # Extract payload
        payload = pkt.getlayer(Raw).load

        # Decode bytes to string, ignoring errors
        try:
            text = payload.decode(errors="ignore")
        except Exception:
            return None

        # Check if payload starts with a known HTTP method
        if not any(text.startswith(m) for m in HTTPNormalizer.HTTP_METHODS):
            return None

        # Parse request line, headers, and body
        return HTTPNormalizer._parse_http_request(text, pkt)

    @staticmethod
    def _parse_http_request(text, pkt):
        # Split payload into lines
        lines = text.split("\r\n")
        if not lines:
            return None

        # First line should be the request line: METHOD PATH HTTP_VERSION
        request_line = lines[0]
        parts = request_line.split(" ")
        if len(parts) < 2:
            return None

        method = parts[0]
        path = parts[1]

        headers = {}
        body = ""
        header_done = False

        # Iterate over remaining lines
        for line in lines[1:]:
            # Empty line indicates end of headers
            if line == "":
                header_done = True
                continue

            if not header_done:
                # Parse headers
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip()] = v.strip()
            else:
                # Append body lines
                body += line + "\n"

        return NormalizedHTTPRequest(
            method=method,
            path=path,
            headers=headers,
            body=body.strip(),
            src=pkt[0][1].src,
            dst=pkt[0][1].dst
        )
