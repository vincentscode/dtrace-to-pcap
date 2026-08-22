import argparse
import warnings

warnings.filterwarnings("ignore")

from scapy.all import Raw, wrpcap, wireshark
from scapy.layers.l2 import Ether

from pwn import hexdump

from typing import Callable, List


class ParseException(Exception):
    def __init__(self, message):
        super().__init__(message)

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("filename")
    parser.add_argument("-o", "--output-filename")
    parser.add_argument("-w", "--open-in-wireshark", action="store_true")
    parser.add_argument("--print-nwk", action="store_true")
    parser.add_argument("--print-dlc-nwk", action="store_true")
    args = parser.parse_args()

    if not any([args.output_filename, args.open_in_wireshark, args.print_nwk, args.print_dlc_nwk]):
        print("No action specified!")
        parser.print_help()
        return 1

    with open(args.filename, "r") as f:
        lines = f.read().split("\n")

    cursor = 0
    def consume_line() -> str | None:
        nonlocal cursor
        if cursor >= len(lines):
            return None
        l = lines[cursor]
        cursor += 1
        return l
    
    def consume_expected_line(expected: str):
        l = consume_line()
        if l != expected:
            raise ParseException(f"Expected \"{expected}\", got \"{l}\"")

    def consume_lines_until(predicate: Callable[[str], bool]) -> List[str]:
        ls = []
        while True:
            l = consume_line()
            assert l is not None, "unexpected eof"
            b = predicate(l)
            ls.append(l)
            if b:
                return ls

    # metadata and trace header are always printed twice for some reason
    metadata_delimiter = "-------------------------------------------------------------------------------"
    trace_header_delimiter = "===================|======="
    for _ in range(2):
        consume_expected_line(metadata_delimiter)
        consume_lines_until(lambda l: l == metadata_delimiter)
        consume_expected_line("")
        trace_header = consume_line()
        assert trace_header is not None, "unexpected eof"
        consume_expected_line(trace_header_delimiter)

    parties = tuple(trace_header.split("|"))
    assert len(parties) == 2
    parties_indentation = (0, len(parties[0]) + 1)

    def get_indentation(l: str):
        for (i, c) in enumerate(l):
            if c != " ":
                return i
        return 0

    scapy_packets = []
    while True:
        l = consume_line()
        if l is None or l == "":
            break

        indentation = get_indentation(l)
        assert indentation in parties_indentation, indentation

        packet = [l[indentation:]]
        while True:
            l = consume_line()
            assert l is not None, "unexpected eof"
            if l == "":
                break

            assert l.startswith(" " * indentation)
            packet.append(l[indentation:])

        # line 0 - packet header
        packet_header = packet[0]

        # ignore whatever this is for now
        if packet_header.startswith("Controller"):
            continue

        packet_parties, packet_layer, packet_unknown_1, packet_timestamp, *packet_unknown_2 = packet_header.split(" ")
        packet_direction = packet_parties[2]
        packet_parties = packet_parties.split(packet_direction)
        packet_unknown_2 = " ".join(packet_unknown_2)
        assert packet_direction in ["<", ">"], packet_header
        assert all(map(lambda x: x in ["F0", "F1", "P0", "P1"], packet_parties)), packet_parties
        assert packet_layer in ["DLC", "MAC_C", "NWL"], packet_layer
        assert packet_unknown_2 in ["- FP", "- Rep"], packet_unknown_2

        # line 1..n - packet hexdump
        # line n+1..end - interpretation
        packet_hexdump = []
        packet_hexdump.append(packet[1].split("): ")[1])
        assert packet[1].startswith("("), packet[1]
        packet_raw_len = int(packet[1].split(")")[0][1:])

        for (i, p) in list(enumerate(packet))[2:]:
            if p.startswith("["):
                packet_interpretation = packet[i:]
                break
            packet_hexdump.append(p)
        packet_hexdump = " ".join(packet_hexdump)
        packet_raw = bytes.fromhex(packet_hexdump)
        assert packet_raw_len == len(packet_raw), f"{packet_raw_len} != {len(packet_raw)}"
        packet_interpretation = "\n".join(packet_interpretation)

        # only print NWK
        if packet_layer == "NWL" and args.print_nwk:
            def indent_lines(text: str, indentation: int):
                return "".join([" " * indentation + l for l in text.splitlines(keepends=True)])

            print(packet_header)
            print(indent_lines(hexdump(packet_raw), 2) + "\n")
            print(indent_lines(packet_interpretation, 2) + "\n")

        # only process DLC, NWK are always contained in DLC i think
        if packet_layer not in ["DLC"]:
            continue

        # only DLC information frames with address 0x11 or 0x13
        assert packet_layer == "DLC"
        control_field = packet_raw[1]
        addr_field = packet_raw[0]

        frame_type = control_field & 0b0000_0001
        if frame_type == 1 or addr_field not in [0x11, 0x13]:
            continue

        if args.print_dlc_nwk:
            print(packet_direction.join(packet_parties), packet_layer, "->", packet_hexdump)

        scapy_packet_payload = Raw(packet_raw)
        mac1 = "42:42:42:11:11:11"
        mac2 = "42:42:42:22:22:22"
        src_mac = mac1 if packet_direction == ">" else mac2
        dst_mac = mac1 if packet_direction == "<" else mac2

        assert packet_raw_len < 0xff
        LC = 0x79
        LC_DATA_REQ = 0x05
        LC_DATA_IND = 0x06
        lc_data_kind = LC_DATA_IND if packet_direction == ">" else LC_DATA_REQ # TODO: direction may be reversed
        mcei = 0x00 # ??
        subfield = 0x00 # ???, B0 (0x00) or B1 (0x10)
        scapy_packet_mitel = Raw(bytearray([0x03, 0x01, 0x00, packet_raw_len + 5])) / Raw(bytearray([LC, lc_data_kind, mcei, subfield, packet_raw_len]))
        scapy_packets.append(Ether(src=src_mac, dst=dst_mac, type="RAW_FR") / scapy_packet_mitel / scapy_packet_payload)

    if args.output_filename:
        wrpcap(args.output_filename, scapy_packets)

    if args.open_in_wireshark:
        wireshark(scapy_packets)

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
