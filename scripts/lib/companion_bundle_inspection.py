"""Fail-closed inspection of this product's uncompressed .NET 6.0 bundle format.

Format sources (Microsoft, pinned .NET 10):
https://github.com/dotnet/runtime/tree/v10.0.0/src/installer/managed/Microsoft.NET.HostModel/Bundle
Manifest.cs, FileEntry.cs, FileType.cs and Bundler.cs are authoritative; the
FileEntry.Write implementation, not its older field-order comment, defines order.
PE host fields: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
This is package evidence, not a Windows loader, signature or CLR-resource verifier.
"""
from __future__ import annotations

import hashlib
import mmap
import os
from pathlib import Path
import re
import stat
import struct


BUNDLE_SIGNATURE = bytes.fromhex("8b1202b96a612038727b930214d7a03213f5b9e6efae3318ee3b2dce24b36aae")
CORE_NAME = "JTS.WindowsCompanion.Core.dll"
_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_RESERVED = re.compile(r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)", re.I)


class BundleInspectionError(ValueError):
    """The binary does not meet the narrow distributable-bundle contract."""


def _require(condition, code):
    if not condition:
        raise BundleInspectionError(code)


class _Reader:
    def __init__(self, data, position=0):
        self.data, self.position = data, position

    def take(self, size):
        end = self.position + size
        _require(0 <= self.position <= end <= len(self.data), "BUNDLE_TRUNCATED")
        value = self.data[self.position:end]
        self.position = end
        return value

    def unpack(self, fmt):
        return struct.unpack("<" + fmt, self.take(struct.calcsize("<" + fmt)))

    def string(self, maximum):
        size = 0
        for index in range(5):
            byte = self.unpack("B")[0]
            _require(index < 4 or byte <= 7, "BUNDLE_STRING_LENGTH")
            size |= (byte & 127) << (7 * index)
            if byte < 128:
                _require(index == 0 or byte != 0, "BUNDLE_STRING_LENGTH")
                break
        _require(1 <= size <= maximum, "BUNDLE_STRING_LENGTH")
        try:
            return self.take(size).decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise BundleInspectionError("BUNDLE_STRING_UTF8") from error


def _pe_host_end(data):
    _require(len(data) >= 64 and data[:2] == b"MZ", "BUNDLE_PE_HOST_INVALID")
    pe = _Reader(data, 60).unpack("I")[0]
    _require(pe >= 64, "BUNDLE_PE_HOST_INVALID")
    reader = _Reader(data, pe)
    _require(reader.take(4) == b"PE\0\0", "BUNDLE_PE_HOST_INVALID")
    machine, sections, _, _, _, optional_size, characteristics = reader.unpack("HHIIIHH")
    _require(machine == 0x8664 and 1 <= sections <= 96 and optional_size >= 112
             and characteristics & 2 and not characteristics & 0x2000, "BUNDLE_PE_HOST_INVALID")
    optional = _Reader(reader.take(optional_size))
    _require(optional.unpack("H")[0] == 0x20B, "BUNDLE_PE_HOST_INVALID")
    optional.position = 60
    headers_end = optional.unpack("I")[0]
    _require(reader.position + sections * 40 <= headers_end <= len(data), "BUNDLE_PE_HOST_INVALID")
    spans = []
    for _ in range(sections):
        section = _Reader(reader.take(40), 16)
        size, start = section.unpack("II")
        if size:
            _require(headers_end <= start < start + size <= len(data), "BUNDLE_PE_HOST_INVALID")
            spans.append((start, start + size))
    _require(bool(spans), "BUNDLE_PE_HOST_INVALID")
    spans.sort()
    _require(all(left[1] <= right[0] for left, right in zip(spans, spans[1:])), "BUNDLE_PE_HOST_INVALID")
    return max(headers_end, spans[-1][1])


def _safe_name(name):
    parts = name.split("/")
    return all(_COMPONENT.fullmatch(part) and not part.endswith(".") and not _RESERVED.match(part) for part in parts)


def _inspect(data, expected_core_bytes, expected_public_key_bytes):
    host_end = _pe_host_end(data)
    marker = data.find(BUNDLE_SIGNATURE)
    _require(marker >= 8 and data.find(BUNDLE_SIGNATURE, marker + 1) == -1, "BUNDLE_SIGNATURE_INVALID")
    _require(marker + len(BUNDLE_SIGNATURE) <= host_end, "BUNDLE_SIGNATURE_OUTSIDE_HOST")
    header = _Reader(data, marker - 8).unpack("q")[0]
    _require(host_end <= header < len(data), "BUNDLE_HEADER_OFFSET_INVALID")
    reader = _Reader(data, header)
    major, minor, count = reader.unpack("IIi")
    _require((major, minor) == (6, 0), "BUNDLE_VERSION_UNSUPPORTED")
    _require(1 <= count <= 4096, "BUNDLE_ENTRY_COUNT_INVALID")
    bundle_id = reader.string(128)
    _require(re.fullmatch(r"[A-Za-z0-9_-]+", bundle_id) is not None, "BUNDLE_ID_INVALID")
    deps_offset, deps_size, runtime_offset, runtime_size, flags = reader.unpack("qqqqQ")
    _require(flags == 0, "BUNDLE_EXTRACTION_FLAGS_REJECTED")
    spans, names, json_locations, counts, core = [], set(), {}, {1: 0, 3: 0, 4: 0}, None
    for _ in range(count):
        offset, size, compressed, kind = reader.unpack("qqqB")
        name = reader.string(512)
        _require(kind in counts, "BUNDLE_ENTRY_TYPE_REJECTED")
        _require(compressed == 0, "BUNDLE_COMPRESSION_REJECTED")
        _require(_safe_name(name) and name.casefold() not in names, "BUNDLE_ENTRY_NAME_REJECTED")
        _require(host_end <= offset < offset + size <= header, "BUNDLE_ENTRY_SPAN_INVALID")
        names.add(name.casefold()); spans.append((offset, offset + size)); counts[kind] += 1
        if kind in (3, 4):
            _require(kind not in json_locations, "BUNDLE_JSON_LOCATION_INVALID")
            json_locations[kind] = (offset, size)
        if name == CORE_NAME:
            _require(kind == 1, "BUNDLE_CORE_TYPE_INVALID")
            _require(size == len(expected_core_bytes), "BUNDLE_CORE_MISMATCH")
            core = data[offset:offset + size]
    spans.sort()
    _require(all(left[1] <= right[0] for left, right in zip(spans, spans[1:])), "BUNDLE_ENTRY_OVERLAP")
    _require(json_locations.get(3, (0, 0)) == (deps_offset, deps_size)
             and json_locations.get(4, (0, 0)) == (runtime_offset, runtime_size), "BUNDLE_JSON_LOCATION_INVALID")
    _require(core is not None and core == expected_core_bytes, "BUNDLE_CORE_MISMATCH")
    _require(expected_public_key_bytes in core, "BUNDLE_PUBLIC_KEY_BYTES_MISSING")
    return {"format": "dotnet-bundle", "majorVersion": major, "minorVersion": minor,
            "headerOffset": header, "manifestEnd": reader.position, "entryCount": count, "flags": flags,
            "hostMachine": "AMD64", "assemblyCount": counts[1], "depsJsonCount": counts[3],
            "runtimeConfigJsonCount": counts[4], "coreSha256": hashlib.sha256(core).hexdigest(),
            "publicKeyBytesPresent": True, "publicKeyResourceVerified": False}


def inspect_bundle(path, expected_core_bytes: bytes, expected_public_key_bytes: bytes) -> dict:
    """Inspect without executing or extracting code; caller supplies trusted build bytes.

    Key byte presence does NOT establish the CLR manifest-resource name or semantics.
    Verify that resource independently against the exact Core bytes before release.
    """
    _require(isinstance(expected_core_bytes, bytes) and 1 <= len(expected_core_bytes) <= 32 * 1024 * 1024
             and isinstance(expected_public_key_bytes, bytes) and 1 <= len(expected_public_key_bytes) <= 4096,
             "BUNDLE_EXPECTATIONS_INVALID")
    with Path(path).open("rb") as stream:
        info = os.fstat(stream.fileno())
        _require(stat.S_ISREG(info.st_mode) and 64 <= info.st_size <= 1024 * 1024 * 1024, "BUNDLE_FILE_SIZE_INVALID")
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            return _inspect(data, expected_core_bytes, expected_public_key_bytes)
