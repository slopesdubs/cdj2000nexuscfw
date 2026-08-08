from __future__ import annotations

import struct
import sys
import tempfile
import unittest
from pathlib import Path


TOOLS = Path(__file__).resolve().parents[1] / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from anlz_color import (  # noqa: E402
    choose_color_tag,
    parse_anlz,
    parse_pwv3,
    parse_pwv4,
    parse_pwv5,
    render_anlz_file,
)
from lzss_codec import compress, decompress  # noqa: E402
from ethernet_trace import compare_captures, scan_capture  # noqa: E402
from srec_parse import SRecError, parse_srec  # noqa: E402
from sh4_trace import (  # noqa: E402
    FunctionRange,
    addresses_equivalent,
    build_trace,
    canonical_address,
    enumerate_tag_comparisons,
    find_function_range,
    inspect_anlz_pwv3,
    scan_direct_calls,
    scan_indirect_calls,
    scan_literal_loads,
    scan_pointer_references,
)
from upd_build import build_srec_segment, build_upd, crc_xmodem  # noqa: E402
from upd_container import (  # noqa: E402
    find_main_payload,
    parse_single_segment_upd,
    parse_upd,
    srec_flat_image,
    verify_segment_crc,
)


def make_anlz(*tags: bytes) -> bytes:
    length = 28 + sum(len(tag) for tag in tags)
    return struct.pack(">4s6I", b"PMAI", 28, length, 0, 0, 0, 0) + b"".join(tags)


def make_pwv5(values, unknown=960305) -> bytes:
    payload = b"".join(struct.pack(">H", value) for value in values)
    length = 24 + len(payload)
    return struct.pack(">4s5I", b"PWV5", 24, length, 2, len(values), unknown) + payload


def make_pwv3(values, unknown=0x960000) -> bytes:
    payload = bytes(values)
    length = 24 + len(payload)
    return struct.pack(">4s5I", b"PWV3", 24, length, 1, len(values), unknown) + payload


def make_pwv4(entries, unknown=0) -> bytes:
    payload = b"".join(bytes(entry) for entry in entries)
    length = 24 + len(payload)
    return struct.pack(">4s5I", b"PWV4", 24, length, 6, len(entries), unknown) + payload


class CodecTests(unittest.TestCase):
    def test_lzss_round_trip(self):
        samples = (b"", b"hello world", b"A" * 5000, bytes(range(256)) * 20)
        for sample in samples:
            with self.subTest(length=len(sample)):
                self.assertEqual(decompress(compress(sample)), sample)

    def test_crc_standard_vector(self):
        self.assertEqual(crc_xmodem(b"123456789"), 0x31C3)


class SRecordTests(unittest.TestCase):
    def test_generated_segment_parses_and_flattens(self):
        segment = build_srec_segment(
            b"CDJ-2000NXS MAINVer1.44\x00    ",
            b"romobj  mot",
            [(0x20, b"hello"), (0x40, b"world")],
            0xA0000000,
        )
        header, chunks, entries = parse_srec(segment, validate=True)
        self.assertEqual(header, b"romobj  mot")
        self.assertEqual(chunks, [(0x20, b"hello"), (0x40, b"world")])
        self.assertEqual(entries, [("7", 0xA0000000)])
        image, _ = srec_flat_image(segment)
        self.assertEqual(image[0x20:0x25], b"hello")
        self.assertEqual(image[0x40:0x45], b"world")
        self.assertEqual(image[0], 0xFF)

    def test_bad_checksum_is_rejected(self):
        line = b"S1060000616263D2\n"
        damaged = line[:-3] + b"00\n"
        with self.assertRaises(SRecError):
            parse_srec(damaged, validate=True)


class UpdateContainerTests(unittest.TestCase):
    def test_container_and_crc_rules(self):
        gui_body = b"G" * 64
        gui = gui_body + crc_xmodem(gui_body).to_bytes(2, "big")
        segments = [gui]
        for marker in (b"D", b"M", b"P"):
            body = marker * 64
            segments.append(body + crc_xmodem(body).to_bytes(2, "little"))
        update = parse_upd(build_upd(segments))
        for name in ("GUI", "DRIV", "MAIN", "PANL"):
            self.assertTrue(verify_segment_crc(name, update.segments[name]).valid)

    def test_nxs_gui_pre_crc_field(self):
        body = b"GUI payload"
        segment = body + b"\x00\x00" + crc_xmodem(body).to_bytes(2, "big")
        result = verify_segment_crc("GUI", segment)
        self.assertTrue(result.valid)
        self.assertEqual(result.padding_bytes, 2)

    def test_main_payload_discovery(self):
        original = (b"colour-waveform" * 500) + bytes(range(128))
        encoded = compress(original)
        image = bytearray(b"\xFF" * (0x40000 + 4 + len(encoded) + 2))
        struct.pack_into("<I", image, 0x40000, len(encoded))
        image[0x40004 : 0x40004 + len(encoded)] = encoded
        end = 0x40004 + len(encoded)
        struct.pack_into("<H", image, end, sum(image[0x40000:end]) & 0xFFFF)
        payload = find_main_payload(bytes(image))
        self.assertTrue(payload.checksum_valid)
        self.assertEqual(payload.decompressed, original)

    def test_single_main_container(self):
        body = b"CDJ-2000NXS MAINVer1.45" + b" " * 32
        segment = body + crc_xmodem(body).to_bytes(2, "little")
        data = str(len(segment)).encode("ascii") + b"\r\n" + segment
        update = parse_single_segment_upd(data)
        self.assertEqual(update.segments["MAIN"], segment)
        self.assertTrue(verify_segment_crc("MAIN", segment).valid)


class AnlzTests(unittest.TestCase):
    def test_pwv3_bit_fields(self):
        anlz = parse_anlz(make_anlz(make_pwv3([0b10111101])))
        unknown, columns = parse_pwv3(anlz.find("PWV3")[0])
        self.assertEqual(unknown, 0x960000)
        self.assertEqual(columns[0].color, 5)
        self.assertEqual(columns[0].height, 29)

    def test_pwv5_bit_fields(self):
        value = (7 << 13) | (5 << 10) | (3 << 7) | (31 << 2)
        anlz = parse_anlz(make_anlz(make_pwv5([value])))
        unknown, columns = parse_pwv5(anlz.find("PWV5")[0])
        self.assertEqual(unknown, 960305)
        self.assertEqual((columns[0].red, columns[0].green, columns[0].blue), (7, 5, 3))
        self.assertEqual(columns[0].height, 31)

    def test_pwv4_boundaries_and_auto_priority(self):
        pwv4 = make_pwv4([(1, 127, 10, 20, 30, 40), (2, 64, 50, 60, 70, 80)])
        anlz = parse_anlz(make_anlz(make_pwv5([0]), pwv4))
        selected = choose_color_tag(anlz)
        self.assertEqual(selected.kind, "PWV4")
        _, columns = parse_pwv4(selected)
        self.assertEqual(len(columns), 2)
        self.assertEqual(columns[1].blue_height, 80)

    def test_render_png(self):
        values = [
            (index % 8 << 13)
            | ((7 - index % 8) << 10)
            | ((index // 2) % 8 << 7)
            | ((index % 32) << 2)
            for index in range(128)
        ]
        data = make_anlz(make_pwv5(values))
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "ANLZ0000.EXT"
            output = Path(directory) / "waveform.png"
            source.write_bytes(data)
            used = render_anlz_file(source, output, width=480, height=128)
            rendered = output.read_bytes()
        self.assertEqual(used, "PWV5")
        self.assertTrue(rendered.startswith(b"\x89PNG\r\n\x1a\n"))
        self.assertGreater(len(rendered), 100)


class EthernetTraceTests(unittest.TestCase):
    def test_pcap_finds_tag_size_and_payload_prefix(self):
        anlz = make_anlz(make_pwv3(range(64)))
        packet = b"ethernet" + b"PWV3" + (64).to_bytes(4, "big") + bytes(range(64))
        global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        packet_header = struct.pack("<IIII", 1, 500000, len(packet), len(packet))
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "track-load.pcap"
            sample = Path(directory) / "ANLZ0000.EXT"
            capture.write_bytes(global_header + packet_header + packet)
            sample.write_bytes(anlz)
            result = scan_capture(capture, sample)
        names = {hit["needle"] for hit in result["hits"]}
        self.assertIn("PWV3", names)
        self.assertIn("entry_count_be32", names)
        self.assertIn("PWV3_payload_prefix_64", names)

    def test_capture_repeatability_summary(self):
        captures = [
            {"capture": "/tmp/one.pcap", "hits": [{"needle": "PWV3"}]},
            {
                "capture": "/tmp/two.pcap",
                "hits": [{"needle": "PWV3"}, {"needle": "PMAI"}],
            },
        ]
        result = compare_captures(captures)
        self.assertTrue(result["repeatability_test_possible"])
        self.assertEqual(result["needles_seen_in_every_capture"], ["PWV3"])


class Sh4TraceTests(unittest.TestCase):
    BASE = 0xA4000000

    @staticmethod
    def make_image() -> bytes:
        image = bytearray(b"\x00" * 0x140)
        struct.pack_into("<H", image, 0x00, 0x4F22)  # sts.l pr,@-r15
        struct.pack_into("<H", image, 0x20, 0xD517)  # literal 0x80 -> r5
        struct.pack_into("<H", image, 0x22, 0xD118)  # literal 0x84 -> r1
        struct.pack_into("<H", image, 0x24, 0x410B)  # jsr @r1
        struct.pack_into("<H", image, 0x26, 0xE604)  # mov #4,r6 (delay slot)
        struct.pack_into("<H", image, 0x40, 0x000B)  # rts
        struct.pack_into("<H", image, 0x42, 0x0009)  # nop delay slot
        struct.pack_into("<H", image, 0x60, 0xB00E)  # bsr 0x80
        struct.pack_into("<I", image, 0x80, 0xA4000100)
        struct.pack_into("<I", image, 0x84, 0x04388E5C)
        image[0x100:0x108] = b"PWV3\x00\x00\x00\x00"
        return bytes(image)

    def test_address_aliases(self):
        self.assertEqual(canonical_address(0xA4388E5C), 0x04388E5C)
        self.assertTrue(addresses_equivalent(0xA4388E5C, 0x04388E5C))

    def test_literal_and_indirect_call_resolution(self):
        image = self.make_image()
        tag_loads = scan_literal_loads(image, self.BASE, 0x04000100)
        self.assertEqual([item.instruction for item in tag_loads], [self.BASE + 0x20])
        calls = scan_indirect_calls(image, self.BASE, 0xA4388E5C)
        self.assertEqual([item.instruction for item in calls], [self.BASE + 0x24])
        self.assertEqual(calls[0].kind, "jsr_literal")

    def test_pointer_and_direct_call_resolution(self):
        image = self.make_image()
        pointers = scan_pointer_references(image, self.BASE, 0x04000100, 2)
        self.assertEqual([item.address for item in pointers], [self.BASE + 0x80])
        calls = scan_direct_calls(image, self.BASE, self.BASE + 0x80)
        self.assertEqual([item.instruction for item in calls], [self.BASE + 0x60])

    def test_function_and_tag_comparison_recovery(self):
        image = self.make_image()
        function = find_function_range(image, self.BASE, self.BASE + 0x20)
        self.assertEqual(function.start, self.BASE)
        self.assertEqual(function.end, self.BASE + 0x44)
        comparisons = enumerate_tag_comparisons(
            image, self.BASE, FunctionRange(self.BASE, self.BASE + 0x44, "test")
        )
        self.assertEqual([item.tag for item in comparisons], ["PWV3"])
        self.assertTrue(comparisons[0].length_is_four)
        self.assertTrue(
            addresses_equivalent(comparisons[0].compare_target, 0xA4388E5C)
        )

    def test_function_start_includes_register_saves(self):
        image = bytearray(self.make_image())
        struct.pack_into("<H", image, 0x00, 0x2FA6)  # mov.l r10,@-r15
        struct.pack_into("<H", image, 0x02, 0x2FB6)  # mov.l r11,@-r15
        struct.pack_into("<H", image, 0x04, 0x4F22)  # sts.l pr,@-r15
        function = find_function_range(bytes(image), self.BASE, self.BASE + 0x20)
        self.assertEqual(function.start, self.BASE)

    def test_anlz_positive_control_summary(self):
        data = make_anlz(make_pwv3([1, 2, 3, 4]))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ANLZ0000.EXT"
            path.write_bytes(data)
            result = inspect_anlz_pwv3(path)
        self.assertEqual(result["entry_size"], 1)
        self.assertEqual(result["entry_count"], 4)
        self.assertEqual(result["payload_length"], 4)
        self.assertTrue(result["size_product_matches_payload"])

    def test_firmware_tag_presence_controls(self):
        image = bytearray(self.make_image())
        image[0x108:0x110] = b"PWAVPWV2"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "MAIN_decomp.bin"
            path.write_bytes(image)
            trace, _ = build_trace(path, lookup_sites=())
        self.assertTrue(trace["tag_presence_controls"]["PWV3"])
        self.assertTrue(trace["tag_presence_controls"]["PWAV"])
        self.assertTrue(trace["tag_presence_controls"]["PWV2"])
        self.assertEqual(trace["tag_presence_controls"]["PWV4"], [])
        self.assertEqual(trace["tag_presence_controls"]["PWV5"], [])


if __name__ == "__main__":
    unittest.main()
