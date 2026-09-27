#include "Bootstrap.h"
#include <map>

namespace jts {
namespace {
std::vector<wchar_t> Environment(const SystemPaths& paths, const Staging& staging) {
    // Rebuild from trusted OS path APIs. Never inherit DOTNET/COMPlus/COR/profiler hooks,
    // extraction roots, credentials, user PATH entries or a preselected relay origin.
    const std::map<std::wstring, std::wstring> values{
        {L"ALLUSERSPROFILE", paths.programData}, {L"COMSPEC", paths.system + L"\\cmd.exe"},
        {L"HOMEDRIVE", paths.profile.substr(0, 2)}, {L"HOMEPATH", paths.profile.substr(2)},
        {L"PATH", paths.system}, {L"PROGRAMDATA", paths.programData},
        {L"SYSTEMDRIVE", paths.windows.substr(0, 2)}, {L"SYSTEMROOT", paths.windows},
        {L"TEMP", staging.temp}, {L"TMP", staging.temp}, {L"USERPROFILE", paths.profile}, {L"WINDIR", paths.windows}
    };
    std::vector<wchar_t> block;
    for (const auto& [name, value] : values) {
        const auto entry = name + L"=" + value;
        block.insert(block.end(), entry.begin(), entry.end()); block.push_back(L'\0');
    }
    block.push_back(L'\0'); return block;
}

void WaitExactProcess(HANDLE process) {
    while (true) {
        const auto result = MsgWaitForMultipleObjects(1, &process, FALSE, INFINITE, QS_ALLINPUT);
        if (result == WAIT_OBJECT_0) return;
        Require(result == WAIT_OBJECT_0 + 1, L"BOOTSTRAP_CHILD_STOP_UNCONFIRMED");
        MSG message{};
        while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
            // A close/quit request is not proof that the installer or its services stopped.
            if (message.message != WM_QUIT) { TranslateMessage(&message); DispatchMessageW(&message); }
        }
    }
}
}

DWORD RunManagedSetup(const SystemPaths& paths, const Staging& staging, const std::wstring& arguments) {
    auto environment = Environment(paths, staging);
    const auto executable = staging.directory + L"\\JTS.WindowsCompanion.UnattendedSetup.exe";
    auto command = L"\"" + executable + L"\"" + (arguments.empty() ? L"" : L" " + arguments);
    STARTUPINFOW startup{}; startup.cb = sizeof(startup); PROCESS_INFORMATION created{};
    Require(CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE,
        CREATE_UNICODE_ENVIRONMENT, environment.data(), staging.directory.c_str(), &startup, &created) != FALSE,
        L"BOOTSTRAP_MANAGED_START_FAILED");
    Handle process(created.hProcess), thread(created.hThread);
    WaitExactProcess(process.get());
    DWORD code = 0;
    Require(GetExitCodeProcess(process.get(), &code) != FALSE, L"BOOTSTRAP_CHILD_STOP_UNCONFIRMED");
    return code;
}
}
