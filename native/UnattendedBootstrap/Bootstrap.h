#pragma once
#include <windows.h>
#include <string>
#include <utility>
#include <vector>

#if !defined(_M_X64) && !defined(__x86_64__)
#error The unattended bootstrap supports Windows x64 only.
#endif

namespace jts {
struct Failure { const wchar_t* code; };
inline void Require(bool condition, const wchar_t* code) { if (!condition) throw Failure{code}; }

class Handle final {
    HANDLE value_ = INVALID_HANDLE_VALUE;
public:
    Handle() = default;
    explicit Handle(HANDLE value) : value_(value) {}
    ~Handle() { reset(); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value_(std::exchange(other.value_, INVALID_HANDLE_VALUE)) {}
    Handle& operator=(Handle&& other) noexcept {
        if (this != &other) { reset(); value_ = std::exchange(other.value_, INVALID_HANDLE_VALUE); }
        return *this;
    }
    HANDLE get() const { return value_; }
    bool valid() const { return value_ != INVALID_HANDLE_VALUE && value_ != nullptr; }
    void reset() { if (valid()) CloseHandle(value_); value_ = INVALID_HANDLE_VALUE; }
};

struct SystemPaths { std::wstring windows, system, programData, profile; };
struct Staging {
    std::wstring directory, temp;
    std::vector<Handle> directoryLeases;
};

void RequireElevatedInteractiveCaller();
Handle OpenTrustedDirectory(const std::wstring& path, bool protectedParent);
void CreateProtectedDirectory(const std::wstring& path, bool sharedReadOnlyParent = false);
Handle CreateProtectedFile(const std::wstring& path);
SystemPaths ReadSystemPaths();
Staging CreateStaging(const SystemPaths& paths);
std::vector<Handle> ExtractPayload(const Staging& staging);
DWORD RunManagedSetup(const SystemPaths& paths, const Staging& staging, const std::wstring& arguments);
std::string HashBytes(const unsigned char* bytes, ULONG length);
std::string HashFile(HANDLE file);
}
