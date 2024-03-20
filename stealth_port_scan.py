#!/usr/bin/env python
# pylint: disable=C,R,W
"""Stealth Port Scan"""
import argparse
import ipaddress
import itertools
import logging
import random
import secrets
import socket
import sys
import threading
import time
import typing as typ
from enum import IntFlag, auto

__version__ = "0.0.1"

__author__ = "Sergey M"


class ANSI:
    CSI = "\x1b["
    RESET = f"{CSI}m"
    CLEAR_LINE = f"{CSI}2K\r"
    BLACK = f"{CSI}30m"
    RED = f"{CSI}31m"
    GREEN = f"{CSI}32m"
    YELLOW = f"{CSI}33m"
    BLUE = f"{CSI}34m"
    MAGENTA = f"{CSI}35m"
    CYAN = f"{CSI}36m"
    WHITE = f"{CSI}37m"
    GREY = f"{CSI}90m"
    BRIGHT_RED = f"{CSI}91m"
    BRIGHT_GREEN = f"{CSI}92m"
    BRIGHT_YELLOW = f"{CSI}99m"
    BRIGHT_BLUE = f"{CSI}94m"
    BRIGHT_MAGENTA = f"{CSI}95m"
    BRIGHT_CYAN = f"{CSI}96m"
    BRIGHT_WHITE = f"{CSI}97m"


class ColorHandler(logging.StreamHandler):
    _log_colors: dict[int, str] = {
        logging.DEBUG: ANSI.BLUE,
        logging.INFO: ANSI.YELLOW,
        logging.WARNING: ANSI.MAGENTA,
        logging.ERROR: ANSI.RED,
        logging.CRITICAL: ANSI.BRIGHT_RED,
    }

    # _fmt = logging.Formatter(
    #     "%(threadName)-24s - %(levelname)-8s - %(message)s"
    # )

    _fmt = logging.Formatter("%(levelname)-8s - %(message)s")

    def format(self, record: logging.LogRecord) -> str:
        message = self._fmt.format(record)
        return f"{self._log_colors[record.levelno]}{message}{ANSI.RESET}"


logger = logging.getLogger(__name__)
logger.addHandler(ColorHandler())


class TcpFlags(IntFlag):
    FIN = 1
    SYN = auto()
    RST = auto()
    PSH = auto()
    ACK = auto()
    URG = auto()
    ECE = auto()
    CWR = auto()

    SYN_ACK = SYN | ACK


def get_local_ip() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("8.8.8.8", 53))
        return sock.getsockname()[0]


# В WireShark нужно поставить галочку Protocol Preferences -> Validate tche TCP checksum if possible
def checksum(data: bytes) -> int:
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s ^ 0xFFFF


def make_ip_header(
    src_ip: str,
    dst_ip: str,
    ident=0,
    tot_len: int = 40,
) -> bytes:
    """
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version|  IHL  |Type of Service|          Total Length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Identification        |Flags|      Fragment Offset    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Time to Live |    Protocol   |         Header Checksum       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Source Address                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Destination Address                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    https://www.rfc-editor.org/rfc/rfc791#section-3.1
    """

    logger.debug(f"{src_ip=}")
    logger.debug(f"{dst_ip=}")
    # logger.debug(f"{ident=:x}")

    return (
        bytes.fromhex("45 00")
        + tot_len.to_bytes(2)
        + ident.to_bytes(2)
        + bytes.fromhex("40 00 40 06")  # flags + ttl + protocol
        + b"\0\0"  # checksum
        + socket.inet_aton(src_ip)
        + socket.inet_aton(dst_ip)
    )


def make_syn_packet(
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
) -> bytes:
    """
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Source Port          |       Destination Port        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Sequence Number                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Acknowledgment Number                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Data |           |U|A|P|R|S|F|                               |
    | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
    |       |           |G|K|H|T|N|N|                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Checksum            |         Urgent Pointer        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             data                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    https://datatracker.ietf.org/doc/html/rfc793#section-3.1
    """

    # Для ip header чексуму можно не считать, ее kernel сам подставит
    iph = make_ip_header(src_ip, dst_ip)
    assert len(iph) == 20

    tcph = (
        src_port.to_bytes(2)
        + dst_port.to_bytes(2)
        + secrets.randbits(32).to_bytes(4)  # seq num
        + b"\0\0\0\0"  #  ack num
        # 5 - data offset в 4-байтных словах, 2 - SYN флаг
        + ((5 << 12) | 2).to_bytes(2)
        + (32_120).to_bytes(2)  # window size
        + b"\0\0\0\0"  # checksum + urgent pointer
    )

    assert len(tcph) == 20

    pseudo_iph = (
        socket.inet_aton(src_ip)
        + socket.inet_aton(dst_ip)
        + socket.IPPROTO_TCP.to_bytes(2)  # b'\x06\x00'
        + len(tcph).to_bytes(2)
    )

    check = checksum(pseudo_iph + tcph)

    logger.debug("tcp checksum: %x", check)

    return iph + tcph[:16] + check.to_bytes(2) + tcph[18:]


WELL_KNOWN_PORTS = frozenset(
    [
        110,
        143,
        21,
        22,
        2222,
        23,
        25,
        3306,
        443,
        465,
        5432,
        587,
        5900,
        6379,
        80,
        8080,
        8443,
        9000,
        993,
        995,
    ]
)


class NameSpace(argparse.Namespace):
    addresses: list[str]
    ports: list[str]
    debug: bool
    sniff_timeout: float
    rate_limit: int


def normalize_ports(data: list[str]) -> typ.Iterable[int]:
    for v in data:
        try:
            a, b = map(int, v.split("-", 1))
            yield from range(a, b + 1)
        except ValueError:
            yield int(v)


def normalize_addresses(data: list[str]) -> typ.Iterable[str]:
    for v in data:
        try:
            first, last = map(ipaddress.ip_address, v.split("-", 1))

            yield from map(
                str,
                itertools.chain.from_iterable(
                    ipaddress.summarize_address_range(first, last)
                ),
            )
            continue
        except ValueError:
            pass

        if "/" in v:
            yield from map(str, ipaddress.ip_network(v))
        else:
            yield socket.gethostbyname(v)


def stealth_scan(
    addresses: typ.Sequence[str],
    ports: typ.Sequence[int],
    delay: float,
    sniff_timeout: float,
) -> None:
    local_ip = get_local_ip()

    logger.debug(f"{local_ip=}")

    # Для установки соединения
    # -> SYN
    # <- SYN ACK
    # -> ACK

    sniff_th = threading.Thread(
        target=sniff_packets,
        args=(local_ip, addresses, ports),
        daemon=True,
    )

    sniff_th.start()

    sent_time = 0

    with socket.socket(
        socket.AF_INET,
        socket.SOCK_RAW,
        socket.IPPROTO_RAW,
    ) as sock:
        for dst_ip, dst_port in itertools.product(addresses, ports):
            if (dt := sent_time - time.monotonic()) > 0:
                logger.debug("wait %.3fs", dt)
                time.sleep(dt)

            pack = make_syn_packet(
                local_ip,
                random.randint(20000, 50000),
                dst_ip,
                dst_port,
            )

            try:
                n = sock.sendto(pack, (dst_ip, 0))
                logger.debug("bytes sent: %d", n)
            except BaseException as ex:
                logger.exception(ex)

            sent_time = time.monotonic() + delay

    sniff_th.join(sniff_timeout)
    logger.info("finished")


# def get_service_names() -> dict[int, str]:
#     rv = {}
#     with open("/etc/services") as f:
#         for line in f:
#             if not line.strip().endswith("/tcp"):
#                 continue
#             name, port = line.split()
#             port, _ = port.split("/")
#             rv[name] = int(port)
#     return rv


# def invert_dict(d: dict) -> dict:
#     return dict(map(reversed, d.items()))


def sniff_packets(local_ip: str, addresses: set[str], ports: set[int]) -> None:
    with socket.socket(
        socket.AF_INET,
        socket.SOCK_RAW,
        socket.IPPROTO_TCP,
    ) as sock:
        while 42:
            pack = sock.recv(65535)

            src_ip = socket.inet_ntoa(pack[12:16])
            if src_ip not in addresses:
                continue

            dst_ip = socket.inet_ntoa(pack[16:20])
            if dst_ip != local_ip:
                continue

            src_port = int.from_bytes(pack[20:22])
            # dst_port = int.from_bytes(pack[22:24])
            if src_port not in ports:
                continue

            flags = int.from_bytes(pack[32:34]) & 0b111_111_111

            # Порт открыт
            if (flags & TcpFlags.SYN_ACK) == TcpFlags.SYN_ACK:
                print(f"{src_ip}:{src_port}")


def parse_args(
    argv: list[str] | None,
) -> tuple[argparse.ArgumentParser, NameSpace]:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-a",
        "--address",
        "--addr",
        dest="addresses",
        nargs="+",
        help="hostname, ip address, ip range or cidr",
    )
    parser.add_argument(
        "-p",
        "--port",
        dest="ports",
        nargs="+",
        help="port or range of ports",
    )
    parser.add_argument(
        "-t",
        "--sniff-timeout",
        "--timeout",
        type=float,
        default=60.0,
        help="sniffer thread execution timeout after finishing sending syn packets",
    )
    parser.add_argument(
        "-r",
        "--rate-limit",
        type=int,
        default=50,
        help="maximum number of sent syn packets per second",
    )
    parser.add_argument("-d", "--debug", action="store_true", default=False)
    args = parser.parse_args(argv, namespace=NameSpace())
    return parser, args


def main(argv: list[str] | None = None) -> None:
    parser, args = parse_args(argv)

    if not args.addresses:
        parser.error("no addresses")

    if args.debug:
        logger.setLevel(logging.DEBUG)

    addresses = set(normalize_addresses(args.addresses))

    ports = set(normalize_ports(args.ports)) if args.ports else WELL_KNOWN_PORTS

    try:
        stealth_scan(
            addresses,
            ports,
            1.0 / args.rate_limit,
            args.sniff_timeout,
        )
    except KeyboardInterrupt:
        logger.warning("interruptted by user")


if __name__ == "__main__":
    sys.exit(main())
