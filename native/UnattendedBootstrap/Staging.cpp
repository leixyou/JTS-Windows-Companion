#include "Bootstrap.h"
#include <shlobj.h>
#include <objbase.h>
#include <array>

namespace jts {
namespace {
std::wstring KnownFolder(REFKNOWNFOLDERID id) {
    PWSTR raw = nullptr;
    const auto result = SHGetKnownFolderPath(id, KF_FLAG_DONT_VERIFY, nullptr, &raw);
    if (FAILED(result)) { if (raw) CoTaskMemFree(raw); throw Failure{L"BOOTSTRAP_SYSTEM_PATH_FAILED"}; }
    std::wstring path(raw); CoTaskMemFree(raw); return path;
}

void CanonicalLocalPath(const std::wstring& path) {
    Require(path.size() >= 3 && path.size() <= 220
        && ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z'))
        && path[1] == L':' && path[2] == L'\\' && path.find_first_of(L"/\"\r\n\t") == std::wstring::npos
        && path.find(L':', 2) == std::wstring::npos, L"BOOTSTRAP_SYSTEM_PATH_REJECTED");
    size_t offset = 3;
    while (offset < path.size()) {
        auto end = path.find(L'\\', offset); if (end == std::wstring::npos) end = path.size();
        const auto part = path.substr(offset, end - offset);
        Require(!part.empty() && part != L"." && part != L".." && part.back() != L'.' && part.back() != L' ',
            L"BOOTSTRAP_SYSTEM_PATH_REJECTED");
        offset = end + 1;
    }
}

void HoldAncestors(const std::wstring& path, std::vector<Handle>& leases) {
    CanonicalLocalPath(path);
    leases.push_back(OpenTrustedDirectory(path.substr(0, 3), false));
    size_t offset = 3;
    while (offset < path.size()) {
        auto end = path.find(L'\\', offset); if (end == std::wstring::npos) end = path.size();
        leases.push_back(OpenTrustedDirectory(path.substr(0, end), false)); offset = end + 1;
    }
}

void EnsureProtectedParent(const std::wstring& path, std::vector<Handle>& leases, bool sharedReadOnlyParent = false) {
    const auto attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        Require(GetLastError() == ERROR_FILE_NOT_FOUND, L"BOOTSTRAP_PARENT_LOOKUP_FAILED");
        CreateProtectedDirectory(path, sharedReadOnlyParent); // Concurrent creation fails; no adoption after a failed create.
    }
    leases.push_back(OpenTrustedDirectory(path, true)); // Never repair/re-ACL a pre-existing parent.
}
}

SystemPaths ReadSystemPaths() {
    std::array<wchar_t, MAX_PATH> windows{}, system{};
    const UINT windowsLength = GetWindowsDirectoryW(windows.data(), static_cast<UINT>(windows.size()));
    const UINT systemLength = GetSystemDirectoryW(system.data(), static_cast<UINT>(system.size()));
    Require(windowsLength != 0 && windowsLength < windows.size() && systemLength != 0 && systemLength < system.size(),
        L"BOOTSTRAP_SYSTEM_PATH_FAILED");
    SystemPaths result{std::wstring(windows.data(), windowsLength), std::wstring(system.data(), systemLength),
        KnownFolder(FOLDERID_ProgramData), KnownFolder(FOLDERID_Profile)};
    for (const auto* path : {&result.windows, &result.system, &result.programData, &result.profile}) CanonicalLocalPath(*path);
    return result;
}

Staging CreateStaging(const SystemPaths& paths) {
    Staging result;
    HoldAncestors(paths.programData, result.directoryLeases);
    auto parent = paths.programData + L"\\JTS Terminal";
    // Other JTS components must be able to inspect this shared ancestor, not write it.
    EnsureProtectedParent(parent, result.directoryLeases, true);
    parent += L"\\.Setup25";
    EnsureProtectedParent(parent, result.directoryLeases);
    GUID id{}; Require(SUCCEEDED(CoCreateGuid(&id)), L"BOOTSTRAP_STAGE_ID_FAILED");
    std::array<wchar_t, 40> idText{};
    Require(StringFromGUID2(id, idText.data(), static_cast<int>(idText.size())) == 39, L"BOOTSTRAP_STAGE_ID_FAILED");
    auto uuid = std::wstring(idText.data() + 1, 36);
    for (auto& value : uuid) if (value >= L'A' && value <= L'F') value += L'a' - L'A';
    result.directory = parent + L"\\" + uuid;
    result.temp = result.directory + L"\\Temp";
    Require(result.temp.size() < 240, L"BOOTSTRAP_STAGE_PATH_TOO_LONG");
    CreateProtectedDirectory(result.directory);
    result.directoryLeases.push_back(OpenTrustedDirectory(result.directory, true));
    CreateProtectedDirectory(result.temp);
    result.directoryLeases.push_back(OpenTrustedDirectory(result.temp, true));
    return result; // Retained for explicit diagnostic cleanup on every outcome.
}
}
