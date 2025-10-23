import socket
import struct
import random
import json

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
    response["nscount"] = NSCOUNT
    response["arcount"] = ARCOUNT

    offset = 12
    # Skip questions
    for _ in range(QDCOUNT):
        while data[offset] != 0:
            offset += data[offset] + 1
        offset += 1
        offset += 4  # qtype + qclass

    # Answers
    answers = []
    for _ in range(ANCOUNT):
        rr, offset = parse_rr(data, offset)
        answers.append(rr)

    # Authorities (NS/SOA typically)
    authorities = []
    for _ in range(NSCOUNT):
        rr, offset = parse_rr(data, offset)
        authorities.append(rr)

    # Additionals (glue A/AAAA, etc.)
    additionals = []
    for _ in range(ARCOUNT):
        rr, offset = parse_rr(data, offset)
        additionals.append(rr)

    response["answers"] = answers
    response["authorities"] = authorities
    response["additionals"] = additionals
    return response


# Example query spec as JSON
dns_query_spec = {
    "id": random.randint(0, 65535),
    "qr": 0,      # query
    "opcode": 0,  # standard query
    "rd": 0,      # recursion desired 0 or 1
    "questions": [
        {
            "qname": "ilab1.cs.rutgers.edu",
            "qtype": 1,   # NS record
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


def parse_name(data, offset):
    labels = []
    jumped = False
    original_offset = offset

    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        # pointer
        if (length & 0xC0) == 0xC0:
            if not jumped:
                original_offset = offset + 2
            pointer = struct.unpack("!H", data[offset:offset+2])[0]
            offset = pointer & 0x3FFF
            jumped = True
            continue
        labels.append(data[offset+1:offset+1+length].decode())
        offset += length + 1

    if not jumped:
        return ".".join(labels), offset
    else:
        return ".".join(labels), original_offset

#your parse_rr from part2
def parse_rr(data, offset):
    """Parse one resource record. Returns (record_dict, new_offset)."""
    name, offset = parse_name(data, offset)
    atype, aclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset+10])
    offset += 10

    rdata_offset = offset
    rdata = data[offset:offset+rdlength]
    offset += rdlength

    type_map = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 28: "AAAA"}
    rtype = type_map.get(atype, str(atype))

    record = {
        "hostname": name,   # owner name of the RR
        "ttl": ttl,
        "atype": atype,
        "rtype": rtype,
        "ip": None,         # filled for A/AAAA
        "nsname": None      # filled for NS/CNAME (a domain-name rdata)
    }

    if atype == 1 and rdlength == 4:              # A
        record["ip"] = socket.inet_ntop(socket.AF_INET, rdata)
    elif atype == 28 and rdlength == 16:          # AAAA
        record["ip"] = socket.inet_ntop(socket.AF_INET6, rdata)
    elif atype in (2, 5):                         # NS or CNAME -> domain name in RDATA
        dname, _ = parse_name(data, rdata_offset)
        record["nsname"] = dname

    return record, offset


def dns_query(query_spec, server=("1.1.1.1", 53)):
    query = build_query(query_spec)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.sendto(query, server)
    data, _ = sock.recvfrom(512)
    sock.close()
    return parse_response(data)



def iterative_resolve(query_spec):
    # Start from a root server
    servers = ["198.41.0.4"]  # a.root-servers.net
    print("root servers", servers)

    qname = query_spec["questions"][0]["qname"]
    qtype = query_spec["questions"][0]["qtype"]  # 1=A, 28=AAAA, 2=NS
    steps = []

    for _ in range(20):  # safety cap
        if not servers:
            return {"error": "No servers to query", "steps": steps}

        server_ip = servers.pop(0)
        steps.append({"server": server_ip, "qname": qname, "qtype": qtype})

        try:
            resp = dns_query(query_spec, server=(server_ip, 53))
        except socket.timeout:
            # try next server if any
            continue

        # If final answer present (A/AAAA and matches qname + type), return it
        final = [rr for rr in resp.get("answers", [])
                 if rr.get("hostname") == qname and rr.get("ip") and rr.get("atype") == qtype]
        if final:
            return {
                "status": "OK",
                "answer": final[0]["ip"],
                "ttl": final[0]["ttl"],
                "authoritative": bool(resp.get("aa")),
                "from_server": server_ip,
                "steps": steps,
                "raw": resp
            }

        # CNAME chain: update qname and restart from root
        cname_rrs = [rr for rr in resp.get("answers", []) if rr.get("rtype") == "CNAME" and rr.get("nsname")]
        if cname_rrs:
            qname = cname_rrs[0]["nsname"]
            query_spec["questions"][0]["qname"] = qname
            servers = ["198.41.0.4"]
            continue

        # Referral: pick NS names from Authority and glue IPs from Additional
        ns_names = [rr["nsname"] for rr in resp.get("authorities", [])
                    if rr.get("rtype") == "NS" and rr.get("nsname")]
        if ns_names:
            glue_ips = [rr["ip"] for rr in resp.get("additionals", [])
                        if rr.get("ip") and rr.get("hostname") in ns_names and rr.get("rtype") in ("A", "AAAA")]
            if glue_ips:
                servers = glue_ips[:]  # follow the first glue next iteration
                continue
            else:
                return {"error": "No glue found", "authorities": resp.get("authorities", []), "steps": steps}

        # NXDOMAIN or other error → stop
        if resp.get("rcode") != 0:
            return {"error": f"RCODE={resp.get('rcode')}", "steps": steps, "raw": resp}

        # Nothing useful
        return {"error": "No answer and no referral", "steps": steps, "raw": resp}

    return {"error": "Too many iterations", "steps": steps}

         

           ## code main loop
           #1. dns_query to server_ip
           #2. check if response ['answers] has ip address, if so done , return ip addrees
           #else check if additionals has ip address, if so servers=[new_server]
           # If no glue ip address found, exit
           #if not new_server:
            #return {"error": "No glue found"}




if __name__ == "__main__":
    response = iterative_resolve(dns_query_spec)
    
    print(json.dumps(response,indent=2))
    
