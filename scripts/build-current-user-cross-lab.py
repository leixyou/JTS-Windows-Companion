#!/usr/bin/env python3
"""Cross-publish the real Windows/UIA current-user setup for an owner-authorized lab.

Never executes it, imports certificate trust, retains private keys or creates a production release.
"""
import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dotnet", type=Path, required=True)
    parser.add_argument("--tool-dotnet", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    for host in (args.dotnet, args.tool_dotnet):
        if not host.is_absolute() or not host.is_file():
            raise ValueError("absolute dotnet executables required")
    if not args.output.is_absolute() or args.output.exists():
        raise ValueError("new absolute output directory required")
    args.output.mkdir(parents=True)
    companion = Path(__file__).resolve().parents[1]

    def run(arguments):
        result = subprocess.run([str(a) for a in arguments], cwd=companion, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=900)
        with (args.output / "build.log").open("ab") as log:
            log.write(result.stdout)
        if result.returncode:
            raise RuntimeError("cross-lab build failed; inspect build.log")

    def digest(path):
        return hashlib.file_digest(path.open("rb"), "sha256").hexdigest()

    with tempfile.TemporaryDirectory(prefix="jts-current-user-cross-lab-") as temporary:
        work = Path(temporary)
        tool = work / "tool"
        run([args.dotnet, "build", companion / "tools/JTS.WindowsCompanion.ReleaseManifestTool/JTS.WindowsCompanion.ReleaseManifestTool.csproj",
             "-c", "Release", "--artifacts-path", work / "tool-artifacts", "-o", tool, "--nologo"])
        manifest_tool = tool / "JTS.WindowsCompanion.ReleaseManifestTool.dll"
        private, public = work / "private.pem", work / "public.pem"
        run([args.tool_dotnet, manifest_tool, "keygen", "--private-key", private])
        run([args.tool_dotnet, manifest_tool, "public-key", "--private-key", private, "--output", public])

        def publish(role, extra=()):
            destination = work / role
            print("Publishing real Windows branch: " + role, flush=True)
            run([args.dotnet, "publish", companion / f"src/JTS.WindowsCompanion.{role}/JTS.WindowsCompanion.{role}.csproj",
                 "--configuration", "Release", "--runtime", "win-x64", "--self-contained", "true", "--output", destination,
                 "--artifacts-path", work / "artifacts", "--nologo", "-p:OS=Windows_NT", "-p:EnableWindowsTargeting=true",
                 "-p:PublishSingleFile=true", "-p:IncludeNativeLibrariesForSelfExtract=true", "-p:PublishTrimmed=false",
                 "-p:DebugType=None", "-p:DebugSymbols=false", "-p:ContinuousIntegrationBuild=true",
                 f"-p:CompanionReleasePublicKeyPath={public}", *extra])
            return destination / f"JTS.WindowsCompanion.{role}.exe"

        agent = publish("Agent")
        broker = publish("UacBroker")
        release = work / "JTS.WindowsCompanion.release.json"
        release_id = "authorized-lab-cross-" + uuid.uuid4().hex
        run([args.tool_dotnet, manifest_tool, "sign", "--private-key", private, "--release-id", release_id,
             "--output", release, "--file", agent, "--file", broker])
        setup = publish("Setup", [f"-p:AgentPayloadPath={agent}", f"-p:BrokerPayloadPath={broker}", f"-p:ReleaseManifestPath={release}"])
        name = "JTS-Windows-Companion-CurrentUser-AUTHORIZED-LAB-ONLY-win-x64.exe"
        files = []
        for role, source, relative in [("setup", setup, name), ("agent", agent, "payloads/JTS.WindowsCompanion.Agent.exe"),
                ("broker", broker, "payloads/JTS.WindowsCompanion.UacBroker.exe"),
                ("release-manifest", release, "JTS.WindowsCompanion.release.json"),
                ("release-public-key", public, "JTS.WindowsCompanion.release-public.pem")]:
            destination = args.output / relative
            destination.parent.mkdir(exist_ok=True)
            shutil.copyfile(source, destination)
            if digest(source) != digest(destination):
                raise RuntimeError("copied artifact hash mismatch")
            files.append({"role": role, "relativePath": relative, "sizeBytes": destination.stat().st_size, "sha256": digest(destination)})
        evidence = {"schemaVersion": 1, "evidenceKind": "authorized-lab-cross-build", "releaseId": release_id,
                    "productionIdentity": False, "authenticode": False, "nativeWindowsExecuted": False,
                    "windowsUIABranchCompiled": True, "files": files}
        (args.output / "build-evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
        (args.output / "SHA256SUMS").write_text("".join(f"{f['sha256']}  {f['relativePath']}\n" for f in files))
        (args.output / "README.txt").write_text(
            "AUTHORIZED LAB ONLY. Cross-compiled real Windows UIA branch; not native Windows acceptance or production release.\n"
            "Run this current-user Setup as the intended logged-in Windows user before the independent service installer UAC step.\n"
            "Setup --install --quiet installs the existing DVC/UIA Agent and UAC broker. Existing identity/delegation is preserved.\n"
            "A new device requires its normal exact-identity DVC delegated enrollment after its first hello; do not reuse another Windows identity.\n"
            "No private key or certificate-store modification is included. Never embed this disposable build into the Mac app.\n")
    print("Built authorized lab current-user candidate; no Windows program executed.")


if __name__ == "__main__":
    main()
