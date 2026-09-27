#include "Bootstrap.h"

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR arguments, int) {
    try {
        jts::Require(arguments != nullptr && wcslen(arguments) <= 8192, L"BOOTSTRAP_ARGUMENTS_REJECTED");
        jts::Require(SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) != FALSE
            && SetDllDirectoryW(L"") != FALSE, L"BOOTSTRAP_DLL_SEARCH_HARDENING_FAILED");
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);
        jts::RequireElevatedInteractiveCaller();
        if (*arguments == L'\0') MessageBoxW(nullptr,
            L"JTS Terminal will prepare protected setup files. The next screen asks for the relay address and explicit approval before creating any accounts or services.\n\n"
            L"Preparation files are retained for local diagnostics. This step does not grant remote access.",
            L"JTS Terminal — Optional unattended setup", MB_OK | MB_ICONINFORMATION);
        const auto paths = jts::ReadSystemPaths();
        const auto staging = jts::CreateStaging(paths);
        [[maybe_unused]] const auto payloadLeases = jts::ExtractPayload(staging);
        // Fixed, authenticated child parses the exact delegated-install CLI. No shell or environment expansion.
        const DWORD result = jts::RunManagedSetup(paths, staging, arguments);
        // Owned files and all parent directory leases stay open until the exact child has exited.
        if (result != 0)
            MessageBoxW(nullptr, L"Setup did not report successful completion. Protected preparation files have been retained.\n\n"
                L"Use the setup result for local diagnosis; do not assume installation or rollback completed.",
                L"JTS Terminal — Setup incomplete", MB_OK | MB_ICONWARNING);
        return result == 0 ? 0 : 20;
    } catch (const jts::Failure& failure) {
        const auto message = std::wstring(L"Setup preparation or completion could not be confirmed. Setup may still be running; check its state locally before retrying.\n\n"
            L"Any preparation files are retained; no automatic cleanup is attempted.\n\n")
            + L"Diagnostic code: " + failure.code;
        MessageBoxW(nullptr, message.c_str(), L"JTS Terminal — Setup preparation failed", MB_OK | MB_ICONERROR);
        return 21;
    } catch (...) {
        MessageBoxW(nullptr, L"Protected setup could not continue. Preparation files are retained for local diagnosis.\n\n"
            L"Diagnostic code: BOOTSTRAP_UNEXPECTED_FAILURE", L"JTS Terminal — Setup preparation failed", MB_OK | MB_ICONERROR);
        return 22;
    }
}
