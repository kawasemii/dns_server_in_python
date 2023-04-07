import socket
import glob
import json

port = 53 # default dns port
ip = '127.0.0.1'


# load zone file
def load_zones():
    jsonzone = {}
    zonefiles = glob.glob('zones/*.zone')
    for zone in zonefiles:
        with open(zone) as zonedata:
            data = json.load(zonedata)
            zonename = data["$origin"]
            jsonzone[zonename] = data
    return jsonzone

zonedata = load_zones()


# compute 2-byte flag
def getflags(flags):
    byte1 = bytes(flags[:1])
    byte2 = bytes(flags[1:2])
    QR = '1'
    opcode = (int.from_bytes(byte1, byteorder='big') & 0b01111000) >> 3
    opcode = "{:04b}".format(opcode)
    AA = '1'
    TC = '0'
    RD = '0'
    RA = '0'
    Z = '000'
    RCODE = '0000'
    return int(QR + opcode + AA + TC + RD + RA + Z + RCODE, 2).to_bytes(2, byteorder='big')
    

# get qname and qtype
def getquestiondomain(data):
    state = 0
    expected_length = 0
    domain_string = ''
    domain_parts = []
    domain_bytes = b''
    length = 0
    for byte in data:
        domain_bytes += byte.to_bytes(1, byteorder='big')
        if byte == 0:
            break
        if state == 1:
            domain_string += chr(byte)
            if len(domain_string) == expected_length:
                domain_parts.append(domain_string)
                domain_string = ''
                state = 0
        else:
            state = 1
            expected_length = byte
        length += 1
    question_type = data[length + 1: length + 3]
    return (domain_parts, question_type, domain_bytes)    


# get zone data for domain
def getzone(domain):
    global zonedata
    zone_name = '.'.join(domain) + '.'
    return zonedata[zone_name]

# return records, qtype, domain name (list)
def getrecs(data):
    domain, question_type, domain_bytes = getquestiondomain(data)
    qt = ''
    if question_type == b'\x00\x01':
        qt = 'a'       
    zone = getzone(domain)
    return (zone[qt], qt, domain, domain_bytes)


# convert records to bytes
def rectobytes(rectype, ttl, recval):
    rbytes = b'\xc0\x0c' # dns compression
    if rectype == 'a':
        rbytes += b'\x00\x01' # type
    rbytes += b'\x00\x01' # class
    rbytes += int(ttl).to_bytes(4, byteorder='big')
    if rectype == 'a':
        rbytes += b'\x00\x04' # rdlength (IP addr length)
        for part in recval.split('.'):
            rbytes += bytes([int(part)])
    return rbytes


# build dns response
def buildresponse(data):
    # transaction id
    transaction_id = data[:2]
    # flags
    flags = getflags(data[2:4])
    # question count = 1
    qdcount = b'\x00\x01'
    # answer count
    records, rectype, domain_name, dns_question = getrecs(data[12:])
    ancount = len(records).to_bytes(2, byteorder='big')
    # name server count
    nscount = (0).to_bytes(2, byteorder='big')
    # additional count
    arcount = (0).to_bytes(2, byteorder='big')
    dns_header = transaction_id + flags + qdcount + ancount + nscount + arcount
    # name + type + class
    if rectype == 'a':
        dns_question += (1).to_bytes(2, byteorder='big')
    dns_question += (1).to_bytes(2, byteorder='big')
    # records
    dns_body = b''
    for record in records:
        dns_body += rectobytes(rectype, record["ttl"], record["value"])
    return dns_header + dns_question + dns_body


    
# ipv4 UDP
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock: 
    sock.bind((ip, port))
    while True:
        data, address = sock.recvfrom(512)
        response = buildresponse(data)
        sock.sendto(response, address)