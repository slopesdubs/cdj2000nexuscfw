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
from gui_receiver_trace import (  # noqa: E402
    CANONICAL_COLUMNS,
    FINAL,
    RECORD_ARENA_BASE,
    RECORD_ARENA_CLEAR_BYTES,
    RECORD_ARENA_END,
    RECORD_STRIDE,
    ZEROFILL,
    flatten_code,
    parse_ldr_blocks,
)
from nxs_wave_emulator import (  # noqa: E402
    CRC_OFFSET,
    EXTENSION_PAYLOAD_CAPACITY,
    FIRST_PAYLOAD_CAPACITY,
    FRAME_SIZE,
    LEGACY_RGB555_PALETTE,
    WaveEmulatorError,
    decode_gui_wave_columns,
    decode_pwv5_patch_columns,
    emulate_anlz_file,
    emulate_gui_receiver,
    emulate_pwv5_patch,
    encode_detail_frames,
    extract_waveform_source,
    inspect_detail_frames,
    pack_gui_wave_records,
    pack_gui_column_colors,
    reassemble_detail_frames,
    rgb555_to_rgb888,
    rgb888_to_rgb555,
    expand_3_to_5,
)
from nxs_color_patch import (  # noqa: E402
    MAIN_INTERNAL_VERSION_OFFSET,
    MAIN_TAG_OFFSETS,
    MAIN_TRANSPORT_LENGTH_OFFSET,
    MAIN_TRANSPORT_LENGTH_PWV5,
    MAIN_TRANSPORT_LENGTH_STOCK,
    ColorPatchError,
    locate_ldr_blocks,
    patch_main_decompressed,
)
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
    scan_constructed_constants,
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


class NxsWaveEmulatorTests(unittest.TestCase):
    def test_real_size_pwv3_frame_round_trip(self):
        payload = bytes(index & 0xFF for index in range(29_804))
        frames = encode_detail_frames(payload, 0x1234, 0x5678)
        information = inspect_detail_frames(frames)

        self.assertEqual(len(frames), 34)
        self.assertTrue(all(len(frame) == FRAME_SIZE for frame in frames))
        self.assertTrue(all(item.crc_valid for item in information))
        self.assertEqual(struct.unpack_from("<H", frames[0], 0)[0], 32)
        self.assertEqual(struct.unpack_from("<I", frames[0], 2)[0], 1)
        self.assertEqual(struct.unpack_from("<I", frames[0], 6)[0], len(payload))
        self.assertEqual(struct.unpack_from("<HH", frames[0], 10), (0x1234, 0x5678))
        self.assertEqual(information[0].payload_bytes, FIRST_PAYLOAD_CAPACITY)
        self.assertEqual(information[1].payload_bytes, EXTENSION_PAYLOAD_CAPACITY)
        self.assertEqual(reassemble_detail_frames(frames), payload)

    def test_final_extension_retains_reusable_buffer_tail(self):
        payload = bytes(index & 0xFF for index in range(880 + 888 + 10))
        frames = encode_detail_frames(payload)
        self.assertEqual(len(frames), 3)
        previous_payload = frames[1][6:CRC_OFFSET]
        final_payload_area = frames[2][6:CRC_OFFSET]
        self.assertEqual(final_payload_area[:10], payload[-10:])
        self.assertEqual(final_payload_area[10:], previous_payload[10:])
        self.assertEqual(reassemble_detail_frames(frames), payload)

    def test_corrupt_frame_is_rejected(self):
        frames = encode_detail_frames(b"waveform" * 200)
        damaged = list(frames)
        frame = bytearray(damaged[1])
        frame[20] ^= 0x80
        damaged[1] = bytes(frame)
        with self.assertRaisesRegex(WaveEmulatorError, "CRC mismatch"):
            inspect_detail_frames(damaged)

    def test_gui_receiver_reassembles_and_decodes_legacy_columns(self):
        payload = bytes((0b10111101, 0b01000011, 0b11111111))
        result = emulate_gui_receiver(encode_detail_frames(payload))
        self.assertEqual(result.payload, payload)
        self.assertEqual(
            [(column.height, column.color_code) for column in result.columns],
            [(29, 5), (3, 2), (31, 7)],
        )
        self.assertEqual(result.columns[0].packed_word, 0x051D)
        self.assertEqual(result.columns[0].rgb555, LEGACY_RGB555_PALETTE[5])
        self.assertEqual(result.records, pack_gui_wave_records(payload))
        self.assertEqual(result.records[:3], b"\x1D\x05\x00")
        self.assertEqual(len(result.records), len(payload) * 12)

    def test_gui_column_decoder_is_exhaustive(self):
        columns = decode_gui_wave_columns(bytes(range(256)))
        self.assertEqual({column.height for column in columns}, set(range(32)))
        self.assertEqual({column.color_code for column in columns}, set(range(8)))
        self.assertEqual({column.rgb555 for column in columns}, set(LEGACY_RGB555_PALETTE))

    def test_verified_gui_rgb555_palette_and_packer(self):
        payload = bytes(code << 5 for code in range(8))
        colors = pack_gui_column_colors(payload)
        self.assertEqual(
            struct.unpack("<8H", colors),
            LEGACY_RGB555_PALETTE,
        )
        self.assertEqual(rgb888_to_rgb555(255, 255, 255), 0x7FFF)
        self.assertEqual(rgb888_to_rgb555(255, 0, 0), 0x7C00)
        self.assertEqual(rgb555_to_rgb888(0x7FFF), (255, 255, 255))
        with self.assertRaises(WaveEmulatorError):
            rgb888_to_rgb555(256, 0, 0)

    def test_experimental_pwv5_backwards_record_conversion(self):
        values = (
            (7 << 13) | (5 << 10) | (3 << 7) | (31 << 2),
            (1 << 13) | (2 << 10) | (4 << 7) | (9 << 2),
        )
        payload = struct.pack(">2H", *values)
        result = emulate_pwv5_patch(encode_detail_frames(payload))
        self.assertEqual(result.payload, payload)
        self.assertEqual([column.height for column in result.columns], [31, 9])
        expected_first = (
            (expand_3_to_5(7) << 10)
            | (expand_3_to_5(5) << 5)
            | expand_3_to_5(3)
        )
        self.assertEqual(result.columns[0].rgb555, expected_first)
        self.assertEqual(struct.unpack_from("<H", result.records)[0], 31)
        self.assertEqual(struct.unpack_from("<H", result.records, 4)[0], expected_first)
        self.assertEqual(struct.unpack_from("<H", result.record_rgb555)[0], expected_first)
        self.assertEqual(result.records[2:4], b"\0\0")
        self.assertEqual(result.records[6:12], b"\0" * 6)
        self.assertEqual(len(decode_pwv5_patch_columns(payload)), 2)

    def test_real_size_pwv5_uses_stock_envelope_in_68_frames(self):
        payload = bytes(index & 0xFF for index in range(29_804 * 2))
        frames = encode_detail_frames(payload)
        result = emulate_pwv5_patch(frames)
        self.assertEqual(len(frames), 68)
        self.assertEqual(len(result.columns), 29_804)
        self.assertEqual(len(result.record_rgb555), len(payload))

    def test_anlz_artifacts_are_byte_identical(self):
        payload = bytes(range(64)) * 20
        anlz = make_anlz(make_pwv3(payload))
        source = extract_waveform_source(anlz)
        self.assertEqual(source.payload, payload)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_path = root / "ANLZ0000.EXT"
            output = root / "emulated"
            input_path.write_bytes(anlz)
            manifest = emulate_anlz_file(input_path, output)
            reassembled = (output / "reassembled-payload.bin").read_bytes()
            gui_record_size = (output / "gui-column-records.bin").stat().st_size
            gui_color_size = (output / "gui-column-colors-rgb555.bin").stat().st_size
            manifest_on_disk = (output / "manifest.json").read_text("utf-8")

        self.assertEqual(reassembled, payload)
        self.assertTrue(manifest["verification"]["all_crc_valid"])
        self.assertTrue(manifest["verification"]["byte_identical_round_trip"])
        self.assertEqual(manifest["gui_receiver"]["first_consumer"], "0x00D2F51C")
        self.assertEqual(gui_record_size, len(payload) * 12)
        self.assertEqual(gui_color_size, len(payload) * 2)
        self.assertEqual(
            manifest["gui_receiver"]["renderer"]["pixel_format"],
            "RGB555, little-endian 16-bit storage",
        )
        self.assertIn('"frame_size": 896', manifest_on_disk)


class GuiReceiverTraceTests(unittest.TestCase):
    def test_stock_record_arena_capacity_covers_canonical_waveform(self):
        self.assertEqual(RECORD_ARENA_CLEAR_BYTES, 10_800_600)
        self.assertEqual(RECORD_ARENA_END, 0x01A5E718)
        self.assertEqual(RECORD_ARENA_CLEAR_BYTES // RECORD_STRIDE, 900_050)
        self.assertLess(
            RECORD_ARENA_BASE + CANONICAL_COLUMNS * RECORD_STRIDE,
            RECORD_ARENA_END,
        )

    def test_ldr_parser_and_code_flattening(self):
        header = b"CDJ-2000NXS GUIVer1.44\0".ljust(32, b" ")
        code = struct.pack("<IIH", 0x00C60010, 4, 0) + b"ABCD"
        zero = struct.pack("<IIH", 0x00C60020, 3, ZEROFILL)
        final = struct.pack("<IIH", 0x00C60030, 2, FINAL) + b"EF"
        blocks = parse_ldr_blocks(header + code + zero + final)
        image = flatten_code(blocks)
        self.assertEqual(len(blocks), 3)
        self.assertEqual(image[0x10:0x14], b"ABCD")
        self.assertEqual(image[0x20:0x23], b"\0\0\0")
        self.assertEqual(image[0x30:0x32], b"EF")


class ColorPatchTests(unittest.TestCase):
    @staticmethod
    def make_main_image() -> bytes:
        image = bytearray(b"\0" * (MAIN_TRANSPORT_LENGTH_OFFSET + 2))
        image[MAIN_INTERNAL_VERSION_OFFSET : MAIN_INTERNAL_VERSION_OFFSET + 4] = b"1.44"
        for offset in MAIN_TAG_OFFSETS:
            image[offset : offset + 4] = b"PWV3"
        image[
            MAIN_TRANSPORT_LENGTH_OFFSET : MAIN_TRANSPORT_LENGTH_OFFSET + 2
        ] = MAIN_TRANSPORT_LENGTH_STOCK
        return bytes(image)

    def test_main_patch_accepts_pwv5_and_sends_payload_bytes(self):
        patched = patch_main_decompressed(
            self.make_main_image(), main_version=b"1.46", strict_hash=False
        )
        self.assertEqual(
            patched[MAIN_INTERNAL_VERSION_OFFSET : MAIN_INTERNAL_VERSION_OFFSET + 4],
            b"1.46",
        )
        self.assertTrue(
            all(patched[offset : offset + 4] == b"PWV5" for offset in MAIN_TAG_OFFSETS)
        )
        self.assertEqual(
            patched[
                MAIN_TRANSPORT_LENGTH_OFFSET : MAIN_TRANSPORT_LENGTH_OFFSET + 2
            ],
            MAIN_TRANSPORT_LENGTH_PWV5,
        )

    def test_main_patch_rejects_unknown_transport_instruction(self):
        image = bytearray(self.make_main_image())
        image[
            MAIN_TRANSPORT_LENGTH_OFFSET : MAIN_TRANSPORT_LENGTH_OFFSET + 2
        ] = b"\0\0"
        with self.assertRaisesRegex(ColorPatchError, "entry-count load"):
            patch_main_decompressed(bytes(image), strict_hash=False)

    def test_patch_ldr_locator_reports_file_offsets(self):
        header = b"CDJ-2000NXS GUIVer1.44\0".ljust(32, b" ")
        code = struct.pack("<IIH", 0x00C60010, 4, 0) + b"ABCD"
        final = struct.pack("<IIH", 0x00C60030, 2, FINAL) + b"EF"
        blocks = locate_ldr_blocks(header + code + final)
        self.assertEqual(blocks[0].header_offset, 0x20)
        self.assertEqual(blocks[0].data_offset, 0x2A)
        self.assertEqual(blocks[0].address, 0x00C60010)
        self.assertEqual(blocks[-1].flags, FINAL)


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

    def test_interleaved_constant_build_recovery(self):
        image = bytearray(b"\x00" * 0x20)
        struct.pack_into("<H", image, 0x00, 0xE20E)  # mov #14,r2
        struct.pack_into("<H", image, 0x02, 0x6013)  # unrelated mov r1,r0
        struct.pack_into("<H", image, 0x04, 0x4218)  # shll8 r2
        struct.pack_into("<H", image, 0x06, 0x63C3)  # unrelated mov r12,r3
        struct.pack_into("<H", image, 0x08, 0x7250)  # add #80,r2 => 0xE50
        hits = scan_constructed_constants(bytes(image), self.BASE, (0xE50,))
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].address, self.BASE + 0x08)
        self.assertEqual(hits[0].register, 2)
        self.assertEqual(hits[0].operations, (self.BASE, self.BASE + 4, self.BASE + 8))

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
