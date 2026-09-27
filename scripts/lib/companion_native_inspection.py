"""Inspect the outer native PE's real resources/imports, never execute it.

Layout: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
"""
from __future__ import annotations

import hashlib
import re
import struct
import xml.etree.ElementTree as ET


class NativePe:
    def __init__(self, data):
        self.data = data
        if data[:2] != b"MZ": self.fail()
        pe, = self.read("I", 60)
        if data[pe:pe+4] != b"PE\0\0": self.fail()
        machine, count, _, _, _, optional_size, flags = self.read("HHIIIHH", pe+4)
        self.optional = pe+24
        magic, = self.read("H", self.optional)
        if machine != 0x8664 or magic != 0x20B or not flags & 2 or flags & 0x2000 or not 1 <= count <= 96 or optional_size < 240:
            self.fail()
        self.sections = []
        for i in range(count):
            virtual_size, rva, raw_size, raw = self.read("IIII", self.optional+optional_size+40*i+8)
            if raw + raw_size > len(data): self.fail()
            self.sections.append((rva, raw_size, raw))
        if self.directory(14) != (0, 0): self.fail()  # Outer bootstrap must not need a CLR.
        if self.directory(13) != (0, 0): self.fail()  # No uninspected delay-loaded libraries.

    @staticmethod
    def fail(): raise ValueError("NATIVE_BOOTSTRAP_PE_REJECTED")

    def read(self, fmt, offset):
        size = struct.calcsize("<"+fmt)
        if offset < 0 or offset+size > len(self.data): self.fail()
        return struct.unpack_from("<"+fmt, self.data, offset)

    def directory(self, index):
        count, = self.read("I", self.optional+108)
        if count <= index: self.fail()
        return self.read("II", self.optional+112+index*8)

    def offset(self, rva, size):
        matches = [raw+rva-start for start, length, raw in self.sections if start <= rva and rva+size <= start+length]
        if size < 1 or len(matches) != 1: self.fail()
        return matches[0]

    def imports(self):
        rva, size = self.directory(1)
        start = self.offset(rva, size)
        result = []
        for index in range(min(size//20, 128)):
            record = self.read("IIIII", start+20*index)
            if not any(record):
                if not result: self.fail()
                return result
            name_start = self.offset(record[3], 1)
            end = self.data.find(b"\0", name_start, name_start+128)
            if end < 0: self.fail()
            self.offset(record[3], end-name_start+1)
            name = self.data[name_start:end].decode("ascii").lower()
            if name not in {"kernel32.dll", "user32.dll", "advapi32.dll", "shell32.dll", "ole32.dll", "bcrypt.dll", "msvcrt.dll", "ucrtbase.dll", "ntdll.dll"} \
                    and not re.fullmatch(r"(?:api-ms-win-(?:core|crt)|ext-ms-win)-[a-z0-9]+(?:-[a-z0-9]+)*\.dll", name):
                raise ValueError("NATIVE_BOOTSTRAP_EXTERNAL_RUNTIME_REJECTED")
            result.append(name)
        self.fail()

    def resources(self):
        rva, size = self.directory(2)
        base = self.offset(rva, size)
        result = {}
        visited = set()

        def bounded(offset, length):
            if not 0 <= offset <= offset+length <= size: self.fail()
            return base+offset

        def walk(relative, path):
            if relative in visited or len(path) > 2: self.fail()
            visited.add(relative)
            _, _, _, _, named, ids = self.read("IIHHHH", bounded(relative, 16))
            if named != 0 or not 1 <= ids <= 256: self.fail()
            bounded(relative+16, ids*8)
            seen = set()
            for index in range(ids):
                name, target = self.read("II", base+relative+16+index*8)
                if name & 0x80000000 or name in seen: self.fail()
                seen.add(name)
                key = path+(name,)
                if target & 0x80000000:
                    if len(key) >= 3: self.fail()
                    walk(target & 0x7fffffff, key)
                else:
                    if len(key) != 3: self.fail()
                    value_rva, length, _, reserved = self.read("IIII", bounded(target, 16))
                    if reserved != 0: self.fail()
                    position = self.offset(value_rva, length)
                    if not base <= position <= position+length <= base+size: self.fail()
                    result[key] = (position, length)
        walk(0, ())
        return result


def inspect_bootstrap(data, files):
    pe = NativePe(data)
    imports = pe.imports()
    resources = pe.resources()
    manifests = [value for key, value in resources.items() if key[:2] == (24, 1)]
    if len(manifests) != 1 or manifests[0][1] > 16384:
        raise ValueError("NATIVE_BOOTSTRAP_MANIFEST_REJECTED")
    offset, length = manifests[0]
    try:
        root = ET.fromstring(data[offset:offset+length])
    except ET.ParseError as error:
        raise ValueError("NATIVE_BOOTSTRAP_MANIFEST_REJECTED") from error
    levels = [e for e in root.iter() if e.tag.rsplit("}", 1)[-1] == "requestedExecutionLevel"]
    if len(levels) != 1 or levels[0].get("level") != "requireAdministrator" or levels[0].get("uiAccess") != "false":
        raise ValueError("NATIVE_BOOTSTRAP_ELEVATION_REJECTED")
    payload = {key[1]: value for key, value in resources.items() if key[0] == 10}
    if len(payload) != len(files) or len(resources) != len(files)+1:
        raise ValueError("NATIVE_BOOTSTRAP_RESOURCE_INVENTORY_REJECTED")
    for resource_id, file in enumerate(files, 200):
        span = payload.get(resource_id)
        if span is None or span[1] != file.stat().st_size:
            raise ValueError("NATIVE_BOOTSTRAP_RESOURCE_SIZE_REJECTED")
        position, length = span
        with file.open("rb") as stream:
            expected = hashlib.file_digest(stream, "sha256").digest()
        view = memoryview(data)[position:position+length]
        try: actual = hashlib.sha256(view).digest()
        finally: view.release()
        if actual != expected:
            raise ValueError("NATIVE_BOOTSTRAP_RESOURCE_HASH_REJECTED")
    return {"machine": "AMD64", "managed": False, "requestedExecutionLevel": "requireAdministrator",
            "imports": imports, "verifiedPayloadResources": len(files)}
