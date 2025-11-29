from scapy.layers.inet import TCP
from scapy.packet import Raw


class NormalizedHTTPRequest:
    def __init__(self, method, path, headers, body, src, dst):
        self.method = method
        self.path = path
        self.headers = headers
        self.body = body
        self.src = src
        self.dst = dst


class HTTPNormalizer:

    @staticmethod
    def normalize(pkt):
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return None

        payload = pkt[Raw].load
        try:
            text = payload.decode(errors="ignore")
        except:
            return None

        if not any(text.startswith(m) for m in ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]):
            return None

        return HTTPNormalizer._parse_http_request(text, pkt)

    @staticmethod
    def _parse_http_request(text, pkt):
        lines = text.split("\r\n")
        request_line = lines[0]
        parts = request_line.split(" ")

        if len(parts) < 2:
            return None

        method = parts[0]
        path = parts[1]

        headers = {}
        body = ""
        header_done = False

        for line in lines[1:]:
            if line == "":
                header_done = True
                continue

            if not header_done:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip()] = v.strip()
            else:
                body += line + "\n"

        return NormalizedHTTPRequest(
            method=method,
            path=path,
            headers=headers,
            body=body.strip(),
            src=pkt[0][1].src,
            dst=pkt[0][1].dst
        )
