from __future__ import annotations

import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from scripts.lib.companion_bundle_inspection import (
    BUNDLE_SIGNATURE, CORE_NAME, BundleInspectionError, inspect_bundle,
)


PUBLIC_KEY = b"-----BEGIN PUBLIC KEY-----\nfixture-public-only\n-----END PUBLIC KEY-----\n"
CORE = b"synthetic-core-before\0" + PUBLIC_KEY + b"\0synthetic-core-after"


def string(value):
    data = value.encode("utf-8") if isinstance(value, str) else value
    size, prefix = len(data), bytearray()
    while size >= 128:
        prefix.append((size & 127) | 128); size >>= 7
    return bytes(prefix) + bytes([size]) + data


def fixture(entries=None, *, flags=0, major=6, minor=0):
    # Synthetic PE32+ layout: headers [0,512), one native section [512,1024), then bundle.
    data = bytearray(1024)
    data[:2] = b"MZ"; struct.pack_into("<I", data, 60, 128)
    data[128:132] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 132, 0x8664, 1, 0, 0, 0, 240, 0x22)
    struct.pack_into("<H", data, 152, 0x20B)
    struct.pack_into("<I", data, 212, 512)
    struct.pack_into("<II", data, 408, 512, 512)
    data[608:640] = BUNDLE_SIGNATURE
    entries = entries if entries is not None else [(CORE_NAME, 1, CORE), ("App.deps.json", 3, b"{}"), ("App.runtimeconfig.json", 4, b"{}")]
    records, locations = [], {}
    for name, kind, content in entries:
        records.append((len(data), len(content), 0, kind, name))
        if kind in (3, 4): locations[kind] = (len(data), len(content))
        data.extend(content)
    header = len(data)
    struct.pack_into("<q", data, 600, header)
    data.extend(struct.pack("<IIi", major, minor, len(records)) + string("Fixture_ID12"))
    locations_offset = len(data)
    data.extend(struct.pack("<qqqqQ", *locations.get(3, (0, 0)), *locations.get(4, (0, 0)), flags))
    entry_offsets = []
    for offset, size, compressed, kind, name in records:
        entry_offsets.append(len(data))
        data.extend(struct.pack("<qqqB", offset, size, compressed, kind) + string(name))
    return data, {"header": header, "locations": locations_offset, "entries": entry_offsets}


class BundleInspectionTests(unittest.TestCase):
    def inspect(self, data, core=CORE, key=PUBLIC_KEY):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "App.exe"
            path.write_bytes(data)
            return inspect_bundle(path, core, key)

    def rejected(self, data, **kwargs):
        with self.assertRaises(BundleInspectionError):
            self.inspect(data, **kwargs)

    def test_valid_bundle_reports_narrow_public_evidence(self):
        data, meta = fixture()
        result = self.inspect(data)
        self.assertEqual((result["majorVersion"], result["minorVersion"]), (6, 0))
        self.assertEqual(result["headerOffset"], meta["header"])
        self.assertEqual(result["manifestEnd"], len(data))
        self.assertEqual(result["entryCount"], 3)
        self.assertEqual(result["coreSha256"], hashlib.sha256(CORE).hexdigest())
        self.assertEqual(result["hostMachine"], "AMD64")
        self.assertTrue(result["publicKeyBytesPresent"])
        self.assertFalse(result["publicKeyResourceVerified"])
        self.assertNotIn(PUBLIC_KEY.decode(), str(result))

    def test_safe_culture_subdirectory_and_multibyte_length(self):
        # Keep each component within 128 characters while making the path need a two-byte prefix.
        entries = [(CORE_NAME, 1, CORE), ("zh-Hans/" + "A" * 112 + ".resources.dll", 1, b"assembly")]
        self.assertEqual(self.inspect(fixture(entries)[0])["assemblyCount"], 2)

    def test_no_manifest_resource_claim_from_key_substring(self):
        core = b"unrelated bytes merely containing " + PUBLIC_KEY
        result = self.inspect(fixture([(CORE_NAME, 1, core)])[0], core=core)
        self.assertFalse(result["publicKeyResourceVerified"])

    def test_rejects_wrong_core_or_key(self):
        for kwargs in ({"core": CORE + b"x"}, {"key": b"another-public-key"}, {"core": b""}, {"key": b""}, {"key": "not-bytes"}):
            with self.subTest(kwargs=tuple(kwargs)):
                self.rejected(fixture()[0], **kwargs)

    def test_rejects_missing_or_wrongly_typed_core(self):
        for entries in ([("Other.dll", 1, CORE)], [(CORE_NAME.lower(), 1, CORE)], [(CORE_NAME, 3, CORE)]):
            with self.subTest(entries=entries[0][:2]): self.rejected(fixture(entries)[0])

    def test_rejects_native_unknown_symbols_and_unrecognized_types(self):
        for kind in (0, 2, 5, 6, 255):
            with self.subTest(kind=kind):
                self.rejected(fixture([(CORE_NAME, 1, CORE), ("payload.dll", kind, b"data")])[0])

    def test_rejects_compressed_or_negative_compressed_size(self):
        for size in (1, -1, 2**63 - 1):
            data, meta = fixture(); struct.pack_into("<q", data, meta["entries"][0] + 16, size)
            with self.subTest(size=size): self.rejected(data)

    def test_rejects_every_nonzero_header_flag(self):
        for flags in (1, 2, 2**63, 2**64 - 1):
            with self.subTest(flags=flags): self.rejected(fixture(flags=flags)[0])

    def test_rejects_non_v6_or_nonzero_minor(self):
        for major, minor in ((0, 0), (5, 0), (7, 0), (6, 1)):
            with self.subTest(version=(major, minor)): self.rejected(fixture(major=major, minor=minor)[0])

    def test_rejects_absent_duplicate_or_nonhost_signature(self):
        data, _ = fixture(); data[608] ^= 1; self.rejected(data)
        data, _ = fixture(); data.extend(BUNDLE_SIGNATURE); self.rejected(data)
        data, _ = fixture(); data[608:640] = bytes(32); data.extend(BUNDLE_SIGNATURE); self.rejected(data)

    def test_rejects_header_offset_outside_overlay(self):
        for value in (-1, 0, 600, 1023, 2**63 - 1):
            data, _ = fixture(); struct.pack_into("<q", data, 600, value)
            with self.subTest(offset=value): self.rejected(data)

    def test_rejects_invalid_entry_offsets_or_lengths(self):
        for offset, size in ((-1, 1), (0, 1), (1000, 1), (1024, 0), (1024, -1), (1024, 2**63 - 1), (2**63 - 1, 1)):
            data, meta = fixture(); struct.pack_into("<qq", data, meta["entries"][0], offset, size)
            with self.subTest(span=(offset, size)): self.rejected(data)
        data, meta = fixture(); struct.pack_into("<q", data, meta["entries"][0], meta["header"])
        self.rejected(data)

    def test_rejects_payload_overlap(self):
        data, meta = fixture(); struct.pack_into("<q", data, meta["entries"][1], 1025)
        struct.pack_into("<q", data, meta["locations"], 1025)
        self.rejected(data)

    def test_rejects_duplicate_or_case_alias_names(self):
        for name in (CORE_NAME, CORE_NAME.lower()):
            with self.subTest(name=name): self.rejected(fixture([(CORE_NAME, 1, CORE), (name, 1, CORE)])[0])

    def test_rejects_unsafe_or_oversized_names(self):
        names = ("../App.dll", "/App.dll", "C:/App.dll", "x\\App.dll", "x//App.dll", "x/./App.dll",
                 "x/../App.dll", "App.dll.", "App.dll ", "CON.dll", "dir/NUL", "COM1.dll", "LPT9.dll",
                 "\x00App.dll", "é.dll", "A" * 129, "a/" * 256 + "App.dll", "")
        for name in names:
            with self.subTest(name=name): self.rejected(fixture([(CORE_NAME, 1, CORE), (name, 1, b"x")])[0])

    def test_rejects_noncanonical_overflow_and_truncated_strings(self):
        for encoded in (b"\x81\x00A", b"\xff\xff\xff\xff\x08", b"\x80" * 5, b"\x80", b"\x01\xff"):
            data, meta = fixture(); start = meta["entries"][0] + 25
            data[start:] = encoded
            with self.subTest(encoded=encoded): self.rejected(data)

    def test_rejects_truncation_at_header_and_entry_boundaries(self):
        data, meta = fixture()
        for end in (0, 10, 63, 130, 410, 640, meta["header"], meta["header"] + 11, meta["locations"] + 39, len(data) - 1):
            with self.subTest(end=end): self.rejected(data[:end])

    def test_rejects_entry_count_bounds_or_manifest_truncation(self):
        for count in (-1, 0, 4, 4097, 2**31 - 1):
            data, meta = fixture(); struct.pack_into("<i", data, meta["header"] + 8, count)
            with self.subTest(count=count): self.rejected(data)

    def test_rejects_json_header_mismatch_and_duplicate_json_types(self):
        for displacement in (0, 8, 16, 24):
            data, meta = fixture(); struct.pack_into("<q", data, meta["locations"] + displacement, -1)
            with self.subTest(displacement=displacement): self.rejected(data)
        self.rejected(fixture([(CORE_NAME, 1, CORE), ("A.deps.json", 3, b"{}"), ("B.deps.json", 3, b"{}")])[0])

    def test_rejects_wrong_pe_host(self):
        mutations = ((0, b"NO"), (128, b"NOPE"), (132, struct.pack("<H", 0xAA64)),
                     (134, struct.pack("<H", 0)), (134, struct.pack("<H", 97)),
                     (148, struct.pack("<H", 0)), (150, struct.pack("<H", 0x2002)),
                     (150, struct.pack("<H", 0)), (152, struct.pack("<H", 0x10B)),
                     (60, struct.pack("<I", 2**32 - 1)), (212, struct.pack("<I", 0)),
                     (408, struct.pack("<I", 2**32 - 1)), (412, struct.pack("<I", 0)))
        for offset, value in mutations:
            data, _ = fixture(); data[offset:offset + len(value)] = value
            with self.subTest(offset=offset, value=value): self.rejected(data)


if __name__ == "__main__":
    unittest.main()
