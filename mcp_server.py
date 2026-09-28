import json
import sys
from client import IPv4Packet

def handle_request(req):
    method = req.get("method")
    params = req.get("params", {})
    req_id = req.get("id")

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": [
                    {
                        "name": "build_ipv4_header",
                        "description": "Construct raw IPv4 header with verified checksum",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "src_ip": {"type": "string"},
                                "dst_ip": {"type": "string"},
                                "protocol": {"type": "integer", "default": 6},
                                "payload_len": {"type": "integer", "default": 0}
                            },
                            "required": ["src_ip", "dst_ip"]
                        }
                    }
                ]
            }
        }
    elif method == "tools/call":
        name = params.get("name")
        args = params.get("arguments", {})
        if name == "build_ipv4_header":
            hdr = IPv4Packet.build_ipv4_header(args["src_ip"], args["dst_ip"], args.get("protocol", 6), args.get("payload_len", 0))
            parsed = IPv4Packet.parse_header(hdr)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": json.dumps(parsed)}]}
            }
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "Method not found"}}

def main():
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            req = json.loads(line)
            res = handle_request(req)
            sys.stdout.write(json.dumps(res) + "\n")
            sys.stdout.flush()
        except Exception as e:
            err = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(e)}}
            sys.stdout.write(json.dumps(err) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    main()
