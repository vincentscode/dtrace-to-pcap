import argparse
import warnings

warnings.filterwarnings("ignore")

from scapy.all import Raw, wrpcap, wireshark
from scapy.layers.l2 import Ether

from pwn import hexdump
from colorama import Fore, Back, Style

from typing import Callable, List


class ParseException(Exception):
    def __init__(self, message):
        super().__init__(message)

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("filename")
    parser.add_argument("-o", "--output-filename")
    parser.add_argument("-w", "--open-in-wireshark", action="store_true")
    parser.add_argument("--print-mac", action="store_true")
    parser.add_argument("--print-dlc", action="store_true")
    parser.add_argument("--print-nwk", action="store_true")
    args = parser.parse_args()

    if not any([args.output_filename, args.open_in_wireshark, args.print_mac, args.print_dlc, args.print_nwk]):
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
        # TODO: figure out what this is and whether it is important
        if packet_header.startswith("Controller"):
            continue

        packet_parties, packet_layer, packet_unknown_1, packet_timestamp, *packet_unknown_2 = packet_header.split(" ")
        packet_direction = packet_parties[2]
        packet_parties = packet_parties.split(packet_direction)
        packet_unknown_2 = " ".join(packet_unknown_2)
        assert packet_direction in ["<", ">"], packet_header
        assert all(map(lambda x: x in ["F0", "F1", "P0", "P1"], packet_parties)), packet_parties
        assert packet_parties[0].startswith("F"), "first party is expected to be fixed"
        assert packet_parties[1].startswith("P"), "second party is expected to be portable"
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

        # print if requested
        if (packet_layer == "NWL" and args.print_nwk) or (packet_layer == "DLC" and args.print_dlc) or (packet_layer == "MAC_C" and args.print_mac):
            def indent_lines(text: str, indentation: int):
                return "".join([" " * indentation + l for l in text.splitlines(keepends=True)])

            print_parties = packet_direction.join(packet_parties)
            print_parties = (Fore.BLUE + print_parties if packet_direction == ">" else Fore.GREEN + print_parties) + Fore.RESET
            print_packet_interpretation = packet_interpretation
            print_packet_interpretation = print_packet_interpretation.replace("[", "[" + Fore.YELLOW)
            print_packet_interpretation = print_packet_interpretation.replace("]", Fore.RESET + "]")

            packet_layer_bgs = { "DLC": Back.LIGHTGREEN_EX, "NWL": Back.LIGHTYELLOW_EX, "MAC_C": Back.LIGHTCYAN_EX }
            print_packet_layer = Fore.RED + packet_layer_bgs[packet_layer] + packet_layer + Style.RESET_ALL

            print(print_parties, print_packet_layer, Style.DIM + packet_unknown_1, packet_timestamp, packet_unknown_2, Style.RESET_ALL)
            print(indent_lines(hexdump(packet_raw, total=False), 2) + "\n")
            print(indent_lines(print_packet_interpretation, 2) + "\n", Style.RESET_ALL)

        mac1 = "42:42:42:11:11:11"
        mac2 = "42:42:42:22:22:22"
        src_mac = mac1 if packet_direction == ">" else mac2
        dst_mac = mac1 if packet_direction == "<" else mac2

        # TODO: for all layers: correct timestamps / offsets in pcap / wireshark

        # skip NWK, it is contained in DLC frames anyways and would only cause chaos / duplicates
        if packet_layer == "NWK":
            continue

        # TODO: correctly include MAC_C if possible, it is unclear how much of that can be put into DECToE frames
        # for now just put it as RAW so it is there
        if packet_layer == "MAC_C":
            scapy_packet_mitel = Raw(bytearray([0x03, 0x01, 0x00, len(packet_raw)]))
            scapy_packets.append(Ether(src=src_mac, dst=dst_mac, type="LOOP") / scapy_packet_mitel / Raw(packet_raw))
            continue

        if packet_layer == "DLC":
            # strip checksum and fill-0xf0 from the end, they are not supported by DECToE in Wireshark
            packet_raw = packet_raw[:-2]
            while packet_raw[-1] == 0xf0:
                packet_raw = packet_raw[:-1]

            assert len(packet_raw) < 0xff
            LC = 0x79
            LC_DATA_REQ = 0x05
            LC_DATA_IND = 0x06
            B0 = 0x00
            B1 = 0x10
            lc_data_kind = LC_DATA_REQ if packet_direction == ">" else LC_DATA_IND
            subfield = B1 if packet_direction == ">" else B0
            # TODO: MAC Connection Endpoint Identification, if relevant / applicable? maybe related to packet_unknown_1?
            mcei = 0x00
            scapy_packet_mitel = Raw(bytearray([0x03, 0x01, 0x00, len(packet_raw) + 5])) / Raw(bytearray([LC, lc_data_kind, mcei, subfield, len(packet_raw)]))
            scapy_packets.append(Ether(src=src_mac, dst=dst_mac, type="RAW_FR") / scapy_packet_mitel / Raw(packet_raw))

    if args.output_filename:
        wrpcap(args.output_filename, scapy_packets)

    if args.open_in_wireshark:
        wireshark(scapy_packets, quiet=True)

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
