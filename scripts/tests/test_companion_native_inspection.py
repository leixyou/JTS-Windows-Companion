"""Synthetic PE fixtures: inspect bytes only; never load a Windows executable."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib.companion_native_inspection import NativePe, inspect_bootstrap


def manifest(level="requireAdministrator", access="false"):
    return (f'<assembly xmlns="urn:schemas-microsoft-com:asm.v1"><trustInfo>'
            f'<requestedExecutionLevel level="{level}" uiAccess="{access}"/>'
            '</trustInfo></assembly>').encode()


class PeFixture:
    """One backed section, one import, and independently addressable resources."""
    OPTIONAL = 0x98
    SECTION = OPTIONAL + 240
    RAW = 0x200
    RVA = 0x1000
    RESOURCE = RAW + 0x300

    def __init__(self, resources=None, library=b"KERNEL32.dll"):
        self.data = bytearray(0x2400)
        self.data[:2] = b"MZ"
        self.put("I", 60, 0x80)
        self.data[0x80:0x84] = b"PE\0\0"
        self.put("HHIIIHH", 0x84, 0x8664, 1, 0, 0, 0, 240, 2)
        self.put("H", self.OPTIONAL, 0x20B)
        self.put("I", self.OPTIONAL+108, 16)
        self.put("IIII", self.SECTION+8, 0x2200, self.RVA, 0x2200, self.RAW)
        self.directory(1, self.RVA+0x100, 40)
        self.put("IIIII", self.RAW+0x100, 0, 0, 0, self.RVA+0x180, 1)
        self.data[self.RAW+0x180:self.RAW+0x180+len(library)+1] = library+b"\0"
        self.directory(2, self.RVA+0x300, 0x1900)
        tree = {}
        for key, value in resources or [((24, 1, 1033), manifest()), ((10, 200, 1033), b"payload")]:
            tree.setdefault(key[0], {}).setdefault(key[1], {})[key[2]] = value
        self.cursor = 0
        self.spans = {}
        self.build_tree(tree, ())

    def put(self, fmt, offset, *values):
        struct.pack_into("<"+fmt, self.data, offset, *values)

    def directory(self, index, rva, length):
        self.put("II", self.OPTIONAL+112+index*8, rva, length)

    def allocate(self, size):
        result = self.cursor
        self.cursor = (self.cursor+size+3) & ~3
        return result

    def build_tree(self, values, path):
        relative = self.allocate(16+8*len(values))
        self.put("IIHHHH", self.RESOURCE+relative, 0, 0, 0, 0, 0, len(values))
        for index, (name, value) in enumerate(sorted(values.items())):
            if isinstance(value, dict):
                target = self.build_tree(value, path+(name,)) | 0x80000000
            else:
                target = self.allocate(16)
                position = self.allocate(len(value))
                self.put("IIII", self.RESOURCE+target, self.RVA+0x300+position, len(value), 0, 0)
                self.data[self.RESOURCE+position:self.RESOURCE+position+len(value)] = value
                self.spans[path+(name,)] = (self.RESOURCE+position, len(value), self.RESOURCE+target)
            self.put("II", self.RESOURCE+relative+16+index*8, name, target)
        return relative


class NativeBootstrapInspectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.file = Path(self.temporary.name) / "example.exe"
        self.file.write_bytes(b"payload")

    def check(self, fixture):
        return inspect_bootstrap(fixture.data, [self.file])

    def test_valid_outer_native_inventory(self):
        result = self.check(PeFixture())
        self.assertEqual(result["verifiedPayloadResources"], 1)
        self.assertEqual(result["imports"], ["kernel32.dll"])
        self.assertFalse(result["managed"])

    def test_elevation_uses_real_outer_manifest_not_decoy(self):
        fixture = PeFixture([((24, 1, 1033), manifest("asInvoker")), ((10, 200, 1033), b"payload")])
        fixture.data[-100:-80] = b"requireAdministrator"
        with self.assertRaisesRegex(ValueError, "ELEVATION_REJECTED"):
            self.check(fixture)

    def test_ui_access_is_not_allowed(self):
        fixture = PeFixture([((24, 1, 1033), manifest(access="true")), ((10, 200, 1033), b"payload")])
        with self.assertRaises(ValueError): self.check(fixture)

    def test_malformed_manifest_has_fixed_failure(self):
        fixture = PeFixture([((24, 1, 1033), b"<invalid>"), ((10, 200, 1033), b"payload")])
        with self.assertRaisesRegex(ValueError, "MANIFEST_REJECTED"):
            self.check(fixture)

    def test_resource_tampering_is_rejected(self):
        fixture = PeFixture()
        position, _, _ = fixture.spans[(10, 200, 1033)]
        fixture.data[position] ^= 1
        with self.assertRaisesRegex(ValueError, "HASH_REJECTED"): self.check(fixture)

    def test_resource_size_is_exact(self):
        fixture = PeFixture()
        self.file.write_bytes(b"payload plus")
        with self.assertRaisesRegex(ValueError, "SIZE_REJECTED"): self.check(fixture)

    def test_missing_and_extra_resource_rejected(self):
        for entries in ([((24, 1, 1033), manifest())],
                        [((24, 1, 1033), manifest()), ((10, 200, 1033), b"payload"), ((10, 201, 1033), b"extra")]):
            with self.subTest(entries=len(entries)), self.assertRaises(ValueError): self.check(PeFixture(entries))

    def test_duplicate_language_does_not_hide_extra_payload(self):
        fixture = PeFixture([((24, 1, 1033), manifest()), ((10, 200, 1033), b"payload"), ((10, 200, 0), b"payload")])
        with self.assertRaises(ValueError): self.check(fixture)

    def test_wrong_resource_identifier_is_rejected(self):
        fixture = PeFixture([((24, 1, 1033), manifest()), ((10, 201, 1033), b"payload")])
        with self.assertRaises(ValueError): self.check(fixture)

    def test_external_runtime_or_import_path_rejected(self):
        for library in (b"libstdc++-6.dll", b"VCRUNTIME140.dll", b"api-ms-win-core-../evil.dll"):
            with self.subTest(library=library), self.assertRaises(ValueError): self.check(PeFixture(library=library))

    def test_windows_api_set_is_allowed(self):
        self.check(PeFixture(library=b"api-ms-win-crt-runtime-l1-1-0.dll"))

    def test_managed_outer_and_delay_import_rejected(self):
        for index in (13, 14):
            fixture = PeFixture()
            fixture.directory(index, fixture.RVA+0x100, 40)
            with self.subTest(directory=index), self.assertRaises(ValueError): self.check(fixture)

    def test_wrong_architecture_or_dll_rejected(self):
        for machine, flags in ((0x14c, 2), (0x8664, 0x2002)):
            fixture = PeFixture()
            fixture.put("H", 0x84, machine)
            fixture.put("H", 0x84+18, flags)
            with self.subTest(machine=machine, flags=flags), self.assertRaises(ValueError): self.check(fixture)

    def test_resource_cyclic_tree_rejected(self):
        fixture = PeFixture()
        fixture.put("I", fixture.RESOURCE+20, 0x80000000)
        with self.assertRaises(ValueError): self.check(fixture)

    def test_resource_cannot_point_outside_resource_directory(self):
        fixture = PeFixture()
        _, _, entry = fixture.spans[(10, 200, 1033)]
        fixture.put("I", entry, fixture.RVA+0x100)
        with self.assertRaises(ValueError): self.check(fixture)

    def test_truncation_rejected_without_loading(self):
        fixture = PeFixture()
        for length in (1, 62, 0x83, 0x99, 0x201, len(fixture.data)-1):
            with self.subTest(length=length), self.assertRaises(ValueError): NativePe(fixture.data[:length])


if __name__ == "__main__":
    unittest.main()
