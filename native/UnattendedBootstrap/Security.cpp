#include "Bootstrap.h"
#include <aclapi.h>
#include <sddl.h>
#include <array>

namespace jts {
namespace {
class Descriptor final {
public:
    PSECURITY_DESCRIPTOR value = nullptr;
    ~Descriptor() { if (value) LocalFree(value); }
};

bool TrustedSid(PSID sid, bool allowInstaller) {
    if (!sid || !IsValidSid(sid)) return false;
    if (IsWellKnownSid(sid, WinLocalSystemSid) || IsWellKnownSid(sid, WinBuiltinAdministratorsSid)) return true;
    if (!allowInstaller) return false;
    PSID installer = nullptr;
    Require(ConvertStringSidToSidW(L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", &installer) != FALSE,
        L"BOOTSTRAP_TRUSTED_SID_FAILED");
    const bool result = EqualSid(sid, installer) != FALSE;
    LocalFree(installer); return result;
}

void VerifySecurity(HANDLE handle, bool protectedParent) {
    Descriptor descriptor; PSID owner = nullptr; PACL acl = nullptr;
    Require(GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &owner, nullptr, &acl, nullptr, &descriptor.value) == ERROR_SUCCESS, L"BOOTSTRAP_DIRECTORY_SECURITY_UNREADABLE");
    Require(TrustedSid(owner, !protectedParent) && acl != nullptr && IsValidAcl(acl), L"BOOTSTRAP_DIRECTORY_OWNER_REJECTED");
    SECURITY_DESCRIPTOR_CONTROL control = 0; DWORD revision = 0;
    Require(GetSecurityDescriptorControl(descriptor.value, &control, &revision) != FALSE, L"BOOTSTRAP_DIRECTORY_SECURITY_INVALID");
    Require(!protectedParent || (control & SE_DACL_PROTECTED) != 0, L"BOOTSTRAP_DIRECTORY_NOT_PROTECTED");
    DWORD forbidden = GENERIC_ALL | GENERIC_WRITE | DELETE | WRITE_DAC | WRITE_OWNER | FILE_DELETE_CHILD;
    if (protectedParent) forbidden |= FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES;
    for (DWORD index = 0; index < acl->AceCount; ++index) {
        void* raw = nullptr;
        Require(GetAce(acl, index, &raw) != FALSE, L"BOOTSTRAP_DIRECTORY_ACE_INVALID");
        const auto* header = static_cast<const ACE_HEADER*>(raw);
        Require(header->AceType == ACCESS_ALLOWED_ACE_TYPE || header->AceType == ACCESS_DENIED_ACE_TYPE,
            L"BOOTSTRAP_DIRECTORY_ACE_UNSUPPORTED");
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw);
        auto sid = const_cast<DWORD*>(&ace->SidStart);
        Require(IsValidSid(sid) != FALSE, L"BOOTSTRAP_DIRECTORY_ACE_INVALID");
        if (header->AceType == ACCESS_ALLOWED_ACE_TYPE && (header->AceFlags & INHERIT_ONLY_ACE) == 0
            && !TrustedSid(sid, !protectedParent) && (ace->Mask & forbidden) != 0)
            throw Failure{L"BOOTSTRAP_DIRECTORY_WRITABLE_BY_OTHER_ACCOUNT"};
    }
}
}

void RequireElevatedInteractiveCaller() {
    static_assert(sizeof(void*) == 8, "Only Windows x64 bootstrap is supported.");
    HANDLE threadToken = nullptr;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &threadToken)) {
        Handle unexpected(threadToken); throw Failure{L"BOOTSTRAP_IMPERSONATION_REJECTED"};
    }
    Require(GetLastError() == ERROR_NO_TOKEN, L"BOOTSTRAP_THREAD_TOKEN_UNCONFIRMED");
    HANDLE raw = nullptr;
    Require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw) != FALSE, L"BOOTSTRAP_TOKEN_UNREADABLE");
    Handle token(raw); TOKEN_ELEVATION elevation{}; DWORD returned = 0, session = 0;
    Require(GetTokenInformation(token.get(), TokenElevation, &elevation, sizeof(elevation), &returned) != FALSE
        && elevation.TokenIsElevated != 0, L"BOOTSTRAP_ELEVATION_REQUIRED");
    alignas(TOKEN_USER) std::array<unsigned char, sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE> user{};
    Require(GetTokenInformation(token.get(), TokenUser, user.data(), static_cast<DWORD>(user.size()), &returned) != FALSE,
        L"BOOTSTRAP_TOKEN_UNREADABLE");
    Require(!IsWellKnownSid(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid, WinLocalSystemSid), L"BOOTSTRAP_SYSTEM_REJECTED");
    std::array<unsigned char, SECURITY_MAX_SID_SIZE> adminSid{};
    DWORD adminSize = static_cast<DWORD>(adminSid.size()); BOOL administrator = FALSE;
    Require(CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, adminSid.data(), &adminSize) != FALSE
        && CheckTokenMembership(nullptr, adminSid.data(), &administrator) != FALSE && administrator != FALSE,
        L"BOOTSTRAP_ADMINISTRATOR_REQUIRED");
    Require(ProcessIdToSessionId(GetCurrentProcessId(), &session) != FALSE && session != 0, L"BOOTSTRAP_INTERACTIVE_SESSION_REQUIRED");
    USEROBJECTFLAGS flags{};
    Require(GetUserObjectInformationW(GetProcessWindowStation(), UOI_FLAGS, &flags, sizeof(flags), &returned) != FALSE
        && (flags.dwFlags & WSF_VISIBLE) != 0, L"BOOTSTRAP_INTERACTIVE_SESSION_REQUIRED");
}

Handle OpenTrustedDirectory(const std::wstring& path, bool protectedParent) {
    // Hold a no-delete-share handle for every ancestor until the managed child exits.
    Handle directory(CreateFileW(path.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    Require(directory.valid(), L"BOOTSTRAP_DIRECTORY_OPEN_FAILED");
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    Require(GetFileInformationByHandleEx(directory.get(), FileAttributeTagInfo, &attributes, sizeof(attributes)) != FALSE
        && (attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0
        && (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0, L"BOOTSTRAP_DIRECTORY_LINK_REJECTED");
    VerifySecurity(directory.get(), protectedParent); return directory;
}

void CreateProtectedDirectory(const std::wstring& path, bool sharedReadOnlyParent) {
    Descriptor security;
    const auto sddl = sharedReadOnlyParent
        ? L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;AU)"
        : L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
    Require(ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, SDDL_REVISION_1, &security.value, nullptr) != FALSE,
        L"BOOTSTRAP_PRIVATE_DESCRIPTOR_FAILED");
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), security.value, FALSE};
    Require(CreateDirectoryW(path.c_str(), &attributes) != FALSE, L"BOOTSTRAP_EXCLUSIVE_DIRECTORY_CREATE_FAILED");
}

Handle CreateProtectedFile(const std::wstring& path) {
    Descriptor security;
    Require(ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)", SDDL_REVISION_1, &security.value, nullptr) != FALSE,
        L"BOOTSTRAP_PRIVATE_DESCRIPTOR_FAILED");
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), security.value, FALSE};
    Handle file(CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &attributes, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    Require(file.valid(), L"BOOTSTRAP_EXCLUSIVE_FILE_CREATE_FAILED");
    return file;
}
}
