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

Handle DuplicateStandardHandle(DWORD which, bool inputRequired) {
    auto source = GetStdHandle(which);
    Handle fallback;
    if (source == nullptr || source == INVALID_HANDLE_VALUE) {
        Require(!inputRequired, L"BOOTSTRAP_CODE_STDIN_REQUIRED");
        fallback = Handle(CreateFileW(L"NUL", which == STD_INPUT_HANDLE ? GENERIC_READ : GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr));
        Require(fallback.valid(), L"BOOTSTRAP_STANDARD_HANDLE_UNAVAILABLE");
        source = fallback.get();
    }
    HANDLE duplicate = nullptr;
    Require(DuplicateHandle(GetCurrentProcess(), source, GetCurrentProcess(), &duplicate, 0, TRUE,
        DUPLICATE_SAME_ACCESS) != FALSE, L"BOOTSTRAP_STANDARD_HANDLE_UNAVAILABLE");
    return Handle(duplicate);
}

class StandardHandles final {
    Handle input_, output_, error_;
    std::vector<unsigned char> attributes_;
    LPPROC_THREAD_ATTRIBUTE_LIST list_ = nullptr;
    HANDLE handles_[3]{};
public:
    StandardHandles(STARTUPINFOEXW& startup, bool enroll)
        : input_(DuplicateStandardHandle(STD_INPUT_HANDLE, enroll)),
          output_(DuplicateStandardHandle(STD_OUTPUT_HANDLE, false)),
          error_(DuplicateStandardHandle(STD_ERROR_HANDLE, false)) {
        SIZE_T bytes = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
        Require(bytes != 0, L"BOOTSTRAP_HANDLE_LIST_FAILED");
        attributes_.resize(bytes);
        auto list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes_.data());
        Require(InitializeProcThreadAttributeList(list, 1, 0, &bytes) != FALSE, L"BOOTSTRAP_HANDLE_LIST_FAILED");
        handles_[0] = input_.get(); handles_[1] = output_.get(); handles_[2] = error_.get();
        if (!UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            handles_, sizeof(handles_), nullptr, nullptr)) {
            DeleteProcThreadAttributeList(list); throw Failure{L"BOOTSTRAP_HANDLE_LIST_FAILED"};
        }
        list_ = list;
        startup.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = input_.get(); startup.StartupInfo.hStdOutput = output_.get();
        startup.StartupInfo.hStdError = error_.get(); startup.lpAttributeList = list_;
    }
    ~StandardHandles() { if (list_ != nullptr) DeleteProcThreadAttributeList(list_); }
    StandardHandles(const StandardHandles&) = delete;
    StandardHandles& operator=(const StandardHandles&) = delete;
};
}

bool IsConsoleEntry(const std::wstring& arguments) {
    const auto first = arguments.find_first_not_of(L" \t");
    if (first == std::wstring::npos) return false;
    const auto trimmed = arguments.substr(first, arguments.find_last_not_of(L" \t") - first + 1);
    return trimmed == L"--status" || trimmed == L"--enroll-code";
}

DWORD RunManagedSetup(const SystemPaths& paths, const Staging& staging, const std::wstring& arguments) {
    auto environment = Environment(paths, staging);
    const auto executable = staging.directory + L"\\JTS.WindowsCompanion.UnattendedSetup.exe";
    auto command = L"\"" + executable + L"\"" + (arguments.empty() ? L"" : L" " + arguments);
    PROCESS_INFORMATION created{};
    if (IsConsoleEntry(arguments)) {
        STARTUPINFOEXW startup{}; startup.StartupInfo.cb = sizeof(startup);
        StandardHandles handles(startup, arguments.find(L"--enroll-code") != std::wstring::npos);
        // Only these three fresh duplicates cross the boundary; never inherit other process handles.
        Require(CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, TRUE,
            CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT, environment.data(), staging.directory.c_str(),
            &startup.StartupInfo, &created) != FALSE, L"BOOTSTRAP_MANAGED_START_FAILED");
    } else {
        STARTUPINFOW startup{}; startup.cb = sizeof(startup);
        Require(CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE,
            CREATE_UNICODE_ENVIRONMENT, environment.data(), staging.directory.c_str(), &startup, &created) != FALSE,
            L"BOOTSTRAP_MANAGED_START_FAILED");
    }
    Handle process(created.hProcess), thread(created.hThread);
    WaitExactProcess(process.get());
    DWORD code = 0;
    Require(GetExitCodeProcess(process.get(), &code) != FALSE, L"BOOTSTRAP_CHILD_STOP_UNCONFIRMED");
    return code;
}
}
