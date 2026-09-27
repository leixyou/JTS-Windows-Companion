#include "Bootstrap.h"
#include "payload_table.h"
#include <algorithm>
#include <cstring>
#include <iterator>
#include <set>

namespace jts {
namespace {
std::wstring LowerAscii(std::wstring value) {
    for (auto& letter : value) if (letter >= L'A' && letter <= L'Z') letter += L'a' - L'A';
    return value;
}

bool SafeName(const std::wstring& name) {
    if (name.empty() || name.size() > 128 || name.front() == L'.' || name.back() == L'.') return false;
    for (const auto letter : name)
        if (!((letter >= L'A' && letter <= L'Z') || (letter >= L'a' && letter <= L'z')
            || (letter >= L'0' && letter <= L'9') || letter == L'.' || letter == L'_' || letter == L'-')) return false;
    if (name.find(L"..") != std::wstring::npos) return false;
    const auto stem = LowerAscii(name.substr(0, name.find(L'.')));
    if (stem == L"con" || stem == L"prn" || stem == L"aux" || stem == L"nul") return false;
    return !(stem.size() == 4 && (stem.substr(0, 3) == L"com" || stem.substr(0, 3) == L"lpt") && stem[3] >= L'1' && stem[3] <= L'9');
}

void ValidateTable() {
    Require(std::size(kPayloadFiles) >= 5 && std::size(kPayloadFiles) <= 128, L"BOOTSTRAP_PAYLOAD_COUNT_REJECTED");
    std::set<std::wstring> names; std::set<int> ids;
    unsigned long long total = 0;
    for (const auto& file : kPayloadFiles) {
        Require(file.name && SafeName(file.name) && names.insert(LowerAscii(file.name)).second
            && file.resourceId > 0 && file.resourceId <= 65535 && ids.insert(file.resourceId).second,
            L"BOOTSTRAP_PAYLOAD_NAME_REJECTED");
        Require(file.size > 0 && file.size <= 1024ULL * 1024 * 1024 && file.sha256 && std::strlen(file.sha256) == 64,
            L"BOOTSTRAP_PAYLOAD_METADATA_REJECTED");
        for (const char* digit = file.sha256; *digit; ++digit)
            Require((*digit >= '0' && *digit <= '9') || (*digit >= 'a' && *digit <= 'f'), L"BOOTSTRAP_PAYLOAD_HASH_REJECTED");
        total += file.size;
    }
    Require(total <= 2ULL * 1024 * 1024 * 1024, L"BOOTSTRAP_PAYLOAD_SIZE_REJECTED");
    for (const auto* required : {L"jts.windowscompanion.unattendedsetup.exe", L"jts.windowscompanion.authorityservice.exe",
        L"jts.windowscompanion.workerrunner.exe", L"jts.windowscompanion.authorityprovisioner.exe", L"jts.windowscompanion.release.json"})
        Require(names.count(required) == 1, L"BOOTSTRAP_PAYLOAD_REQUIRED_FILE_MISSING");
}

Handle ExtractOne(const Staging& staging, const PayloadFile& file) {
    const auto module = GetModuleHandleW(nullptr);
    const auto resource = FindResourceW(module, MAKEINTRESOURCEW(file.resourceId), RT_RCDATA);
    Require(resource != nullptr && SizeofResource(module, resource) == file.size, L"BOOTSTRAP_RESOURCE_SIZE_REJECTED");
    const auto loaded = LoadResource(module, resource);
    const auto* bytes = static_cast<const unsigned char*>(LockResource(loaded));
    Require(bytes != nullptr && HashBytes(bytes, static_cast<ULONG>(file.size)) == file.sha256, L"BOOTSTRAP_RESOURCE_HASH_REJECTED");
    const auto path = staging.directory + L"\\" + file.name;
    Require(path.size() < 260, L"BOOTSTRAP_PAYLOAD_PATH_TOO_LONG");
    Handle output = CreateProtectedFile(path);
    unsigned long long offset = 0;
    while (offset < file.size) {
        const auto count = static_cast<DWORD>((std::min)(file.size - offset, 1024ULL * 1024)); DWORD written = 0;
        Require(WriteFile(output.get(), bytes + static_cast<size_t>(offset), count, &written, nullptr) != FALSE
            && written == count, L"BOOTSTRAP_PAYLOAD_WRITE_FAILED");
        offset += written;
    }
    Require(FlushFileBuffers(output.get()) != FALSE, L"BOOTSTRAP_PAYLOAD_FLUSH_FAILED");
    output.reset(); // Windows image loading must not retain a write-access handle.
    Handle lease(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    FILE_ATTRIBUTE_TAG_INFO attributes{}; LARGE_INTEGER size{};
    Require(lease.valid() && GetFileInformationByHandleEx(lease.get(), FileAttributeTagInfo, &attributes, sizeof(attributes)) != FALSE
        && (attributes.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0
        && GetFileSizeEx(lease.get(), &size) != FALSE && static_cast<unsigned long long>(size.QuadPart) == file.size
        && HashFile(lease.get()) == file.sha256, L"BOOTSTRAP_EXTRACTED_PAYLOAD_REJECTED");
    return lease;
}
}

std::vector<Handle> ExtractPayload(const Staging& staging) {
    ValidateTable(); std::vector<Handle> leases; leases.reserve(std::size(kPayloadFiles));
    for (const auto& file : kPayloadFiles) leases.push_back(ExtractOne(staging, file));
    return leases;
}
}
