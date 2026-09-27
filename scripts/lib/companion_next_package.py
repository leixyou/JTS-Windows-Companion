"""Closed payload/resource generation for the native 2.5 setup bootstrap."""
from __future__ import annotations

import hashlib
import re
import shutil
from pathlib import Path

ROLES = ("AuthorityService", "WorkerRunner", "AuthorityProvisioner", "UnattendedSetup")
EXES = tuple(f"JTS.WindowsCompanion.{role}.exe" for role in ROLES)
MANIFEST = "JTS.WindowsCompanion.release.json"
# The SDK's Windows singlefilehost contains CoreCLR/JIT in the authenticated EXE.
# SQLite remains adjacent; the bundle inspector rejects any extractable native entries.
REQUIRED_NATIVE = {"e_sqlite3.dll"}
RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def portable_name(name: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name)
                and name.split(".")[0].upper() not in RESERVED)


def merge_published(source: Path, destination: Path, role: str) -> None:
    """Merge only the known app + adjacent native DLLs; collision requires exact bytes."""
    expected = f"JTS.WindowsCompanion.{role}.exe"
    entries = list(source.iterdir())
    if not any(p.name == expected for p in entries):
        raise ValueError("Published role missing")
    for item in entries:
        if item.is_symlink() or not item.is_file() or not portable_name(item.name):
            raise ValueError("Unexpected publish entry")
        if item.name != expected and item.suffix.lower() != ".dll":
            raise ValueError("Unexpected publish output")
        if item.stat().st_size < 1:
            raise ValueError("Empty publish output")
        collisions = [p for p in destination.iterdir() if p.name.casefold() == item.name.casefold()]
        if collisions:
            if len(collisions) != 1 or collisions[0].name != item.name or digest(collisions[0]) != digest(item):
                raise ValueError("Conflicting shared native dependency")
        else:
            with item.open("rb") as incoming, (destination / item.name).open("xb") as outgoing:
                shutil.copyfileobj(incoming, outgoing)


def payload_files(root: Path, *, with_manifest: bool = False) -> list[Path]:
    files = sorted(root.iterdir(), key=lambda p: p.name)
    names = [p.name for p in files]
    if not set(EXES).issubset(names) or not REQUIRED_NATIVE.issubset(names):
        raise ValueError("INCOMPLETE_MANAGED_NATIVE_PAYLOAD")
    if not 5 <= len(files) <= 128 or len({n.casefold() for n in names}) != len(names):
        raise ValueError("Invalid payload count or duplicate")
    for path in files:
        if path.is_symlink() or not path.is_file() or not portable_name(path.name):
            raise ValueError("Invalid payload entry")
        if path.name not in EXES and path.suffix.lower() != ".dll" and not (with_manifest and path.name == MANIFEST):
            raise ValueError("Unexpected payload role")
        if not 1 <= path.stat().st_size <= 1024**3:
            raise ValueError("Payload size rejected")
    if with_manifest and MANIFEST not in names:
        raise ValueError("Missing manifest")
    if sum(p.stat().st_size for p in files) > 2 * 1024**3:
        raise ValueError("Package too large")
    return files


def write_resources(payload: Path, generated: Path) -> None:
    files = payload_files(payload, with_manifest=True)
    generated.mkdir()
    table = ["#pragma once", "struct PayloadFile { int resourceId; const wchar_t* name; unsigned long long size; const char* sha256; };",
             "inline constexpr PayloadFile kPayloadFiles[] = {"]
    resources = ["#pragma code_page(65001)"]
    for resource_id, path in enumerate(files, 200):
        table.append(f'    {{{resource_id}, L"{path.name}", {path.stat().st_size}ULL, "{digest(path)}"}},')
        escaped = str(path.resolve()).replace("\\", "/").replace('"', '\\"')
        resources.append(f'{resource_id} RCDATA "{escaped}"')
    table.append("};")
    (generated / "payload_table.h").write_text("\n".join(table) + "\n", encoding="utf-8")
    (generated / "payload.rc").write_text("\n".join(resources) + "\n", encoding="utf-8")
