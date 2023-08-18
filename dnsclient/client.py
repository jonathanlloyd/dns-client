from dataclasses import dataclass
from enum import Enum
from pprint import pprint
import random
import socket
import struct


class DNSHeaderType(Enum):
    QUERY = 0
    RESPONSE = 1


class DNSQueryOpCode(Enum):
    QUERY = 0
    IQUERY = 1
    STATUS = 2


class DNSResponseCode(Enum):
    NO_ERROR = 0
    FORMAT_ERROR = 1
    SERVER_FAILURE = 2
    NAME_ERROR = 3
    NOT_IMPLEMENTED = 4
    REFUSED = 5


class DNSType(Enum):
    A = 1
    NS = 2
    CNAME = 5
    TXT = 16


class DNSQType(Enum):
    A = 1
    NS = 2
    CNAME = 5
    TXT = 16
    ALL = 255


class DNSClass(Enum):
    IN = 1


class DNSQClass(Enum):
    IN = 1
    ALL = 255


@dataclass
class DNSHeader:
    message_id: int
    message_type: DNSHeaderType = DNSHeaderType.QUERY
    op_code: DNSQueryOpCode = DNSQueryOpCode.QUERY
    authoritative_answer: bool = False
    truncation: bool = False
    recursion_desired: bool = False
    recursion_available: bool = False
    response_code: DNSResponseCode = DNSResponseCode.NO_ERROR
    question_count: int = 0
    answer_count: int = 0
    name_server_count: int = 0
    addtional_records_count: int = 0


@dataclass
class DNSQuestion:
    domain: str
    question_type: DNSQType
    question_class: DNSQClass


@dataclass
class DNSResourceRecord:
    domain: str
    record_type: DNSType
    record_class: DNSClass
    time_to_live: int
    data: bytes


def dns_header_to_bytes(dns_header):
    flags = 0b0000_0000_0000_0000
    flags = flags | (dns_header.message_type.value << 15)
    flags = flags | (dns_header.op_code.value << 11)
    flags = flags | (int(dns_header.authoritative_answer) << 10)
    flags = flags | (int(dns_header.truncation) << 9)
    flags = flags | (int(dns_header.recursion_desired) << 8)
    flags = flags | (int(dns_header.recursion_available) << 7)
    flags = flags | (dns_header.response_code.value << 0)

    return struct.pack(
        "!HHHHHH",
        dns_header.message_id,
        flags,
        dns_header.question_count,
        dns_header.answer_count,
        dns_header.name_server_count,
        dns_header.addtional_records_count,
    )


def dns_question_to_bytes(dns_question):
    domain_name_bytes = b''
    domain_parts = dns_question.domain.split('.')
    for part in domain_parts:
        domain_name_bytes += bytes([len(part)]) + part.encode('ascii')
    # Add trailing 0 length part
    domain_name_bytes += b'\x00'

    return domain_name_bytes + struct.pack(
        "!hh",
        dns_question.question_type.value,
        dns_question.question_class.value,
    )


def dns_header_from_bytes(message_bytes):
    header_parts = struct.unpack("!HHHHHH", message_bytes[:12])
    message_id = header_parts[0]
    flags = header_parts[1]
    question_count = header_parts[2]
    answer_count = header_parts[3]
    name_server_count = header_parts[4]
    addtional_records_count = header_parts[5]

    message_type         = DNSHeaderType((flags & 0b1000_0000_0000_0000) >> 15)
    op_code              = DNSQueryOpCode((flags & 0b0111_0000_0000_0000) >> 11)
    authoritative_answer = bool((flags & 0b0000_1000_0000_0000) >> 10)
    truncation           = bool((flags & 0b0000_0100_0000_0000) >> 9)
    recursion_desired    = bool((flags & 0b0000_0010_0000_0000) >> 8)
    recursion_available  = bool((flags & 0b0000_0001_0000_0000) >> 7)
    response_code        = DNSResponseCode((flags & 0b0000_0000_0000_1111) >> 0)

    return DNSHeader(
        message_id=message_id,
        message_type=message_type,
        op_code=op_code,
        authoritative_answer=authoritative_answer,
        truncation=truncation,
        recursion_desired=recursion_desired,
        recursion_available=recursion_available,
        response_code=response_code,
        question_count=question_count,
        answer_count=answer_count,
        name_server_count=name_server_count,
        addtional_records_count=addtional_records_count,
    )


def dns_domain_from_bytes(message_bytes, offset):
    pointer = offset
    domain_name_parts = []
    while pointer < len(message_bytes):
        length_prefix = message_bytes[pointer]
        if length_prefix == 0:
            pointer += 1
            break

        if length_prefix & 0b1100_0000:
            redirected_pointer_b = bytes([
                length_prefix & 0b0011_1111,
                message_bytes[pointer + 1],
            ])
            redirected_pointer = struct.unpack('!H', redirected_pointer_b)[0]
            domain, _ = dns_domain_from_bytes(message_bytes, redirected_pointer)
            pointer += 2
            return (domain, pointer)
        else:
            domain_name_parts.append(
                bytes(
                    message_bytes[pointer + 1:pointer + length_prefix + 1]
                )
            )
            pointer += length_prefix + 1

    domain = '.'.join([part.decode('ascii') for part in domain_name_parts])

    return (domain, pointer)


def dns_question_from_bytes(message_bytes):
    pointer = 12
    (domain, pointer) = dns_domain_from_bytes(message_bytes, pointer)

    question_type_b, question_class_b = struct.unpack(
        "!hh",
        bytes(message_bytes[pointer:pointer + 4])
    )
    pointer += 4

    question_type = DNSQType(question_type_b)
    question_class = DNSQClass(question_class_b)

    return (DNSQuestion(
        domain=domain,
        question_type=question_type,
        question_class=question_class,
    ), pointer)


def dns_resource_record_from_bytes(message_bytes, offset):
    (domain, pointer) = dns_domain_from_bytes(message_bytes, offset)

    (
        record_type_b,
        record_class_b,
        ttl,
        record_data_length,
    ) = struct.unpack('!HHIH', bytes(message_bytes[pointer:pointer+10]))
    pointer += 10

    record_type = DNSType(record_type_b)
    record_class = DNSClass(record_class_b)
    record_data = message_bytes[pointer:pointer+record_data_length]

    return DNSResourceRecord(
        domain=domain,
        record_type=record_type,
        record_class=record_class,
        time_to_live=ttl,
        data=record_data,
    )


def dns_lookup_message_bytes(domain):
    header = DNSHeader(
        message_id=random.randint(0, 65535),
        message_type=DNSHeaderType.QUERY,
        op_code=DNSQueryOpCode.QUERY,
        truncation=False,
        recursion_desired=True,
        question_count=1,
    )
    question = DNSQuestion(
        domain=domain,
        question_type=DNSQType.A,
        question_class=DNSQClass.IN,
    )
    return (
        dns_header_to_bytes(header) +
        dns_question_to_bytes(question)
    )


def parse_message_bytes(message_bytes):
    header = dns_header_from_bytes(message_bytes)
    question, pointer = dns_question_from_bytes(message_bytes)
    record = dns_resource_record_from_bytes(message_bytes, pointer)
    return (header, question, record)


def pretty_print_ip_bytes(ip_bytes):
    if len(ip_bytes) != 4:
        raise RuntimeError('IP must be 4 bytes')
    return '.'.join([str(b) for b in ip_bytes])


def print_bytes(b):
    for index, byte in enumerate(b):
        print(f'{byte:0>8b}', end=' ')
    print('\n', end='')


class DNSClient:
    def lookup(self, domain):
        message = dns_lookup_message_bytes(domain)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(message, ("8.8.8.8", 53))
        response, _ = sock.recvfrom(1024)

        header, question, record = parse_message_bytes(response)
        print('====> HEADER')
        pprint(header)
        print('====> QUESTION\n')
        pprint(question)
        print('====> RECORD\n')
        pprint(record)

        if record.record_type == DNSType.A:
            return pretty_print_ip_bytes(record.data)
        else:
            raise RuntimeError(f'Unexpected record type: {record.record_type}')
