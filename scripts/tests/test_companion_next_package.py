from pathlib import Path
import importlib.util
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from lib.companion_next_package import EXES, MANIFEST, REQUIRED_NATIVE, merge_published, payload_files, write_resources
import build_companion_next_setup as builder


class CompanionNextPackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.payload = self.root / "payload"
        self.payload.mkdir()
        for name in (*EXES, *REQUIRED_NATIVE):
            (self.payload / name).write_bytes(name.encode())

    def test_closed_inventory(self):
        self.assertEqual(len(payload_files(self.payload)), 5)

    def test_required_native_and_exe_must_exist(self):
        (self.payload / "e_sqlite3.dll").unlink()
        with self.assertRaises(ValueError):
            payload_files(self.payload)

    def test_extra_role_script_and_private_key_are_rejected(self):
        for name in ("extra.exe", "script.ps1", "private.pem", "config.json", "CON.dll"):
            extra = self.payload / name
            extra.write_bytes(b"not permitted")
            with self.assertRaises(ValueError):
                payload_files(self.payload)
            extra.unlink()

    def test_link_and_directory_rejected(self):
        extra = self.payload / "extra.dll"
        extra.mkdir()
        with self.assertRaises(ValueError):
            payload_files(self.payload)
        extra.rmdir()
        try:
            extra.symlink_to(self.payload / "e_sqlite3.dll")
        except OSError:
            self.skipTest("Symlink creation unavailable")
        with self.assertRaises(ValueError):
            payload_files(self.payload)

    def test_native_collision_requires_exact_bytes(self):
        source = self.root / "publish"
        source.mkdir()
        role = "AuthorityService"
        (source / EXES[0]).write_bytes(EXES[0].encode())
        (source / "e_sqlite3.dll").write_bytes(b"different runtime")
        with self.assertRaises(ValueError):
            merge_published(source, self.payload, role)
        (source / "e_sqlite3.dll").write_bytes(b"e_sqlite3.dll")
        merge_published(source, self.payload, role)

    def test_resource_table_has_exact_hashes_names_and_no_private_material(self):
        (self.payload / MANIFEST).write_bytes(b"public signed inventory")
        generated = self.root / "generated"
        write_resources(self.payload, generated)
        table = (generated / "payload_table.h").read_text()
        self.assertEqual(table.count("ULL"), 6)
        self.assertIn(MANIFEST, table)
        self.assertNotIn(str(self.root), table)
        self.assertNotIn("private", table.lower())
        with self.assertRaises(FileExistsError):
            write_resources(self.payload, generated)

    def test_no_key_fallback_or_overwrite(self):
        host = Path(sys.executable).resolve()
        args = builder.options(["--dotnet", str(host), "--tool-dotnet", str(host), "--output", str(self.root / "out"),
                                "--development", "--mingw-prefix", "fixture-"])
        builder.validate(args)
        args.release_key = self.root / "key.pem"
        with self.assertRaises(ValueError):
            builder.validate(args)
        args.release_key = None
        args.output.mkdir()
        with self.assertRaises(ValueError):
            builder.validate(args)

    def test_opt_in_build_graph_does_not_relax_native_extraction(self):
        text = (ROOT / "Directory.Build.targets").read_text()
        self.assertIn("'$(JtsNextPackageBuild)' == 'true'", text)
        self.assertIn("<IncludeNativeLibrariesForSelfExtract>false", text)
        self.assertIn("<IncludeAllContentForSelfExtract>false", text)
        self.assertIn("packaging/next-locks/$(MSBuildProjectName).lock.json", text)


if __name__ == "__main__":
    unittest.main()
