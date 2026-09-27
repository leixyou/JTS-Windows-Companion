#!/usr/bin/env python3
"""Build a native-bootstrap 2.5 first-install candidate; never run/install it."""
from __future__ import annotations

import argparse
import json
import mmap
import os
import platform
import re
import shutil
import subprocess
import tempfile
import uuid
import zipfile
from pathlib import Path

from lib.companion_bundle_inspection import inspect_bundle
from lib.companion_next_package import EXES, MANIFEST, ROLES, digest, merge_published, payload_files, write_resources
from lib.companion_native_inspection import inspect_bootstrap

ROOT = Path(__file__).resolve().parents[1]
COMPANION = ROOT


def options(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dotnet", type=Path, required=True, help="Absolute .NET SDK 10 host")
    parser.add_argument("--tool-dotnet", type=Path, required=True, help="Absolute .NET 8 host for signing tool")
    parser.add_argument("--output", type=Path, required=True, help="New output directory (never overwritten)")
    parser.add_argument("--release-key", type=Path, help="External protected P-256 private key; never packaged")
    parser.add_argument("--release-id", default="2.5.0-preview.1")
    parser.add_argument("--development", action="store_true", help="Disposable key, explicitly non-distributable output")
    parser.add_argument("--authorized-lab", action="store_true", help="Explicit owner-authorized test handoff; requires --development")
    parser.add_argument("--mingw-prefix", help="Cross compiler prefix (development only), e.g. x86_64-w64-mingw32-")
    return parser.parse_args(argv)


def validate(args):
    if args.authorized_lab and not args.development:
        raise ValueError("Authorized lab handoff requires a disposable development key")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", args.release_id):
        raise ValueError("Invalid release ID")
    if args.development == bool(args.release_key):
        raise ValueError("Choose a development key OR an external release key")
    if not args.development and (os.name != "nt" or platform.machine().lower() not in ("amd64", "x86_64")):
        raise ValueError("A release-identity package requires a Windows x64 build host")
    if args.mingw_prefix and not args.development:
        raise ValueError("Cross compiling is development-only")
    for host in (args.dotnet, args.tool_dotnet):
        if not host.is_absolute() or not host.is_file():
            raise ValueError("Dotnet hosts must be absolute existing files")
    if args.release_key and (not args.release_key.is_absolute() or args.release_key.is_symlink()
                            or not args.release_key.is_file() or args.release_key.resolve().is_relative_to(ROOT)):
        raise ValueError("Release private key must be an external regular file")
    if args.output.exists() or args.output.is_symlink():
        raise ValueError("Output directory already exists")
    if os.name != "nt" and not args.mingw_prefix:
        raise ValueError("Non-Windows development needs an explicit MinGW prefix")


class Commands:
    def __init__(self, log: Path):
        self.log = log

    def run(self, arguments, *, capture=False):
        # No shell and no command/argument echo; private-key paths never enter logs.
        result = subprocess.run([str(a) for a in arguments], cwd=ROOT, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=900, check=False)
        with self.log.open("ab") as output:
            output.write(result.stdout)
        if result.returncode:
            raise RuntimeError("Build command failed; inspect the local build log")
        return result.stdout.decode("utf-8", errors="strict") if capture else None


def build(args):
    validate(args)
    args.output.mkdir(parents=True)
    run = Commands(args.output / "build.log")
    sdk = run.run([args.dotnet, "--version"], capture=True).strip()
    if sdk != "10.0.401":
        raise ValueError("Packaging requires the reviewed .NET 10 SDK")
    release_id = "development-" + uuid.uuid4().hex if args.development else args.release_id
    with tempfile.TemporaryDirectory(prefix="jts-next-package-") as temporary:
        work = Path(temporary).resolve()
        payload = work / "payload"; payload.mkdir()
        tool_output = work / "signing-tool"
        tool_project = COMPANION / "tools/JTS.WindowsCompanion.ReleaseManifestTool/JTS.WindowsCompanion.ReleaseManifestTool.csproj"
        run.run([args.dotnet, "build", tool_project, "-c", "Release", "--nologo", "--artifacts-path", work / "tool-build", "-o", tool_output])
        tool = tool_output / "JTS.WindowsCompanion.ReleaseManifestTool.dll"
        private = args.release_key or work / "disposable-private.pem"
        public = work / "public.pem"
        if args.development:
            run.run([args.tool_dotnet, tool, "keygen", "--private-key", private])
        run.run([args.tool_dotnet, tool, "public-key", "--private-key", private, "--output", public])
        properties = ["-p:JtsNextPackageBuild=true", f"-p:CompanionReleasePublicKeyPath={public}"]
        artifacts = work / "managed-build"
        core_bytes = None
        core_path = None
        bundle_evidence = []
        for role in ROLES:
            print(f"Publishing {role} (no native extraction)", flush=True)
            project = COMPANION / f"src/JTS.WindowsCompanion.{role}/JTS.WindowsCompanion.{role}.csproj"
            destination = work / role
            common = ["--runtime", "win-x64", "--artifacts-path", artifacts, "-p:SelfContained=true", *properties]
            run.run([args.dotnet, "restore", project, "--locked-mode", "--nologo", *common])
            run.run([args.dotnet, "publish", project, "-c", "Release", "--self-contained", "true", "--no-restore",
                     "--nologo", "--output", destination, *common])
            executable = destination / f"JTS.WindowsCompanion.{role}.exe"
            (args.output / f"publish-inventory-{role}.json").write_text(json.dumps([
                {"name": p.name, "size": p.stat().st_size if p.is_file() else None,
                 "sha256": digest(p) if p.is_file() else None} for p in sorted(destination.iterdir())], indent=2) + "\n", encoding="utf-8")
            if core_bytes is None:
                candidates = list((artifacts / "bin/JTS.WindowsCompanion.Core").rglob("JTS.WindowsCompanion.Core.dll"))
                if len(candidates) != 1:
                    raise ValueError("Ambiguous compiled Core assembly")
                core_path = candidates[0]; core_bytes = core_path.read_bytes()
            print(f"Inspecting {role} bundle and native dependencies", flush=True)
            bundle_evidence.append({"role": role, **inspect_bundle(executable, core_bytes, public.read_bytes())})
            merge_published(destination, payload, role)
        files = payload_files(payload)
        sign = [args.tool_dotnet, tool, "sign-bundle", "--private-key", private, "--release-id", release_id, "--output", payload / MANIFEST]
        for item in files:
            sign.extend(["--file", item])
        run.run(sign)
        inspector_project = COMPANION / "tools/JTS.WindowsCompanion.NextPackageInspector/JTS.WindowsCompanion.NextPackageInspector.csproj"
        inspector_output = work / "inspector"
        run.run([args.dotnet, "restore", inspector_project, "--locked-mode", "--nologo", "--artifacts-path", work / "inspector-build"])
        run.run([args.dotnet, "build", inspector_project, "--no-restore", "--nologo", "-c", "Release", "--artifacts-path", work / "inspector-build", "-o", inspector_output])
        verification = json.loads(run.run([args.dotnet, inspector_output / "JTS.WindowsCompanion.NextPackageInspector.dll",
                                          core_path, public, payload / MANIFEST, payload], capture=True))
        generated = work / "generated"
        write_resources(payload, generated)
        native = work / "native-build"
        configure = ["cmake", "-S", COMPANION / "native/UnattendedBootstrap", "-B", native,
                     f"-DJTS_PAYLOAD_DIR={generated}", "-DCMAKE_BUILD_TYPE=Release"]
        if args.mingw_prefix:
            configure += ["-G", "Unix Makefiles", "-DCMAKE_SYSTEM_NAME=Windows",
                          f"-DCMAKE_CXX_COMPILER={args.mingw_prefix}g++", f"-DCMAKE_RC_COMPILER={args.mingw_prefix}windres"]
        else:
            configure += ["-A", "x64"]
        run.run(configure)
        run.run(["cmake", "--build", native, "--config", "Release", "--parallel", "2"])
        outputs = list(native.rglob("JTS.WindowsCompanion.Setup.exe"))
        if len(outputs) != 1:
            raise ValueError("Native bootstrap output missing or ambiguous")
        with outputs[0].open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as binary:
            native_evidence = inspect_bootstrap(binary, payload_files(payload, with_manifest=True))
        marker = "AUTHORIZED-LAB-ONLY" if args.authorized_lab else "DEVELOPMENT-NOT-FOR-DISTRIBUTION" if args.development else "RELEASE-CANDIDATE"
        name = f"JTS-Windows-Companion-2.5-{marker}-win-x64.exe"
        with outputs[0].open("rb") as source, (args.output / name).open("xb") as destination:
            shutil.copyfileobj(source, destination)
        evidence = {"kind": marker, "authorizedLabHandoff": args.authorized_lab, "sdk": sdk, "releaseId": release_id, "nativeWindowsExecuted": False,
                    "authenticode": False, "bootstrapSha256": digest(args.output / name),
                    "releaseVerification": verification, "nativeBootstrap": native_evidence, "managedBundles": bundle_evidence,
                    "payload": [{"name": p.name, "size": p.stat().st_size, "sha256": digest(p)} for p in payload_files(payload, with_manifest=True)]}
        (args.output / "packaging-evidence.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
        (args.output / "README.txt").write_text(
            f"{marker}\nJTS Terminal 2.5 Windows enrollment candidate.\n"
            "Run only the outer EXE on an explicitly authorized Windows x64 test machine.\n"
            "UAC elevation is required. Interactive setup remains available with no arguments.\n"
            "Open the outer EXE, paste the one-use code from Mac Companion Devices, and select Connect.\n"
            "First use installs Authority/Worker; later uses open the installed enrollment manager.\n"
            "Use --manage for the manager, --status for structured status, or --enroll-code with the code on stdin only.\n"
            "Keep the Mac access-code sheet open or poll jts_device_status action=codeStatus until complete.\n"
            "Binding does not require RDP login. Unbound codes expire after 30 minutes; bound device authorization lasts until revoked.\n"
            "A new enrollment-enabled relay admits Windows dynamically without JSON editing or restart.\n"
            "Legacy public-request installation remains available:\n"
            "Owner-delegated setup imports the exact Mac public identity and lane grants without a second pairing prompt:\n"
            "  EXE --relay https://relay.example.com:8443 --delegated-enrollment C:\\path\\request.json --sha256 REQUEST_SHA256 --export C:\\path\\enrollment.json\n"
            "All file arguments are absolute; export must be a new file. Request lifetime is at most 30 minutes.\n"
            "HTTPS/WSS transport stays encrypted; outer certificate PKI checks are skipped by default. Inner pinned mutual TLS is mandatory.\n"
            "The legacy file flow exports installedAwaitingRelayAdmission and requires manual node admission.\n"
            "Control uses a dedicated Worker account; files use ProgramData\\JTS Terminal\\Companion25\\shared; RDP bridges only 127.0.0.1:3389.\n"
            "No RDP listener/firewall/account policy is silently enabled. No upgrade, uninstall or automatic repair is supplied.\n"
            "Native Windows acceptance and the complete 2.5 release gates remain open.\n"
            "Authenticode is absent. Do not disable SmartScreen or organization policy.\n"
            "Obtain the expected installer digest through an independently trusted distribution channel.\n"
            + ("Disposable test key; hand off only to the owner's explicitly authorized test computers. Not a public release.\n" if args.authorized_lab else "Disposable release key; never distribute or embed in the Mac app.\n" if args.development else "Designated release key; not evidence of release acceptance.\n"), encoding="utf-8")
        (args.output / "SHA256SUMS").write_text(f"{digest(args.output / name)}  {name}\n", encoding="ascii")
        with zipfile.ZipFile(args.output / f"{Path(name).stem}.zip", "x", compression=zipfile.ZIP_DEFLATED) as archive:
            for item in (name, "README.txt", "SHA256SUMS", "packaging-evidence.json"):
                archive.write(args.output / item, item)
    print(f"Built {marker}; no Windows binary was executed.")


if __name__ == "__main__":
    try:
        build(options())
    except ValueError as error:
        code = str(error) if re.fullmatch(r"[A-Za-z0-9_ .-]{1,160}", str(error)) else "PAYLOAD_VALIDATION_FAILED"
        raise SystemExit(f"NEXT_SETUP_PACKAGE_FAILED: {code}; no acceptance claimed.")
    except (OSError, RuntimeError, subprocess.SubprocessError):
        raise SystemExit("NEXT_SETUP_PACKAGE_FAILED: no acceptance claimed; inspect local output/log and preserve existing artifacts.")
