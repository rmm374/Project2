import socket
import struct
import random
import json

# Example query spec as JSON
dns_query_spec = {
    "id": random.randint(0, 65535),
    "qr": 0,      # query
    "opcode": 0,  # standard query
    "rd": 1,      # recursion desired
    "questions": [
        {
            "qname": "ilab1.cs.rutgers.edu",
            "qtype": 1,   # Arecord
            "qclass": 1   # IN
        }
    ]
}


def build_query(query_spec):
    # Header fields
    ID = query_spec["id"]
    QR = query_spec["qr"] << 15
    OPCODE = query_spec["opcode"] << 11
    AA, TC = 0, 0
    RD = query_spec["rd"] << 8
    RA, Z, RCODE = 0, 0, 0
    flags = QR | OPCODE | AA | TC | RD | RA | Z | RCODE

    QDCOUNT = len(query_spec["questions"])
    ANCOUNT, NSCOUNT, ARCOUNT = 0, 0, 0

    header = struct.pack("!HHHHHH", ID, flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)

    # Question section
    question_bytes = b""
    for q in query_spec["questions"]:
        labels = q["qname"].split(".")
        for label in labels:
            question_bytes += struct.pack("B", len(label)) + label.encode()
        question_bytes += b"\x00"  # end of qname
        question_bytes += struct.pack("!HH", q["qtype"], q["qclass"])

    return header + question_bytes


def parse_response(data):
    response = {}
    (ID, flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT) = struct.unpack("!HHHHHH", data[:12])

    response["id"] = ID
    response["qr"] = (flags >> 15) & 1
    response["opcode"] = (flags >> 11) & 0xF
    response["aa"] = (flags >> 10) & 1
    response["tc"] = (flags >> 9) & 1
    response["rd"] = (flags >> 8) & 1
    response["ra"] = (flags >> 7) & 1
    response["rcode"] = flags & 0xF
    response["qdcount"] = QDCOUNT
    response["ancount"] = ANCOUNT

    offset = 12
    # Skip questions
    for _ in range(QDCOUNT):
        while data[offset] != 0:
            offset += data[offset] + 1
        offset += 1
        offset += 4  # qtype + qclass

    # Parse answers
    answers = []
    for _ in range(ANCOUNT):
        # name (compression: first two bits 11)
        if (data[offset] & 0xC0) == 0xC0:
            offset += 2
        else:
            while data[offset] != 0:
                offset += data[offset] + 1
            offset += 1

        atype, aclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset+10])
        offset += 10
        rdata = data[offset:offset+rdlength]
        offset += rdlength
        print("atype and rdlength",atype,rdlength,type(rdata))
        '''
		 TODO  Add code to extract IPv4 address or IPv6 address based on atype and rdlength
		 Answer should contain three fields "type","ip", and "ttl"


    '''
        if atype == 1 and rdlength == 4:
            ip_addr = socket.inet_ntop(socket.AF_INET, rdata)
            answers.append({"type": "A", "ip": ip_addr, "ttl": ttl})
        elif atype == 28 and rdlength == 16:
            ip_addr = socket.inet_ntop(socket.AF_INET6, rdata)
            answers.append({"type": "AAAA", "ip": ip_addr, "ttl": ttl})

    response["answers"] = answers
    return response


def dns_query(query_spec, server=("8.8.8.8", 53)):
    query = build_query(query_spec)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.sendto(query, server)
    data, _ = sock.recvfrom(512)
    sock.close()
    result=parse_response(data)
    return result


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Simple DNS client for A/AAAA queries.")
    parser.add_argument("domain", help="Domain name to resolve (e.g., ilab1.cs.rutgers.edu)")
    parser.add_argument("-t", "--type", choices=["A", "AAAA"], default="A",
                        help="Record type to query (default: A)")
    parser.add_argument("-s", "--server", default="8.8.8.8",
                        help="DNS server IP (default: 8.8.8.8)")
    parser.add_argument("-p", "--port", type=int, default=53,
                        help="DNS server port (default: 53)")
    parser.add_argument("--timeout", type=float, default=5.0,
                        help="UDP timeout seconds (default: 5)")
    args = parser.parse_args()

    qtype = 1 if args.type == "A" else 28  # A or AAAA

    dns_query_spec = {
        "id": random.randint(0, 65535),
        "qr": 0,      # query
        "opcode": 0,  # standard query
        "rd": 1,      # recursion desired
        "questions": [
            {
                "qname": args.domain,
                "qtype": qtype,
                "qclass": 1  # IN
            }
        ]
    }

    try:
        result = dns_query(dns_query_spec, server=(args.server, args.port))
        print(json.dumps(result, indent=2))
        
        if "answers" in result and result["answers"]:
            ips = [a.get("ip") for a in result["answers"] if a.get("ip")]
            if ips:
                print("\nResolved IPs:", ", ".join(ips))
    except socket.timeout:
        print("Query timed out.")
    except Exception as e:
        print(f"Error: {e}")
