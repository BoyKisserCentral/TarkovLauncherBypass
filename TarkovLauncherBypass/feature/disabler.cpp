//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// Disabler is a cleaned up version of PVE BattlEye Bypass by x3e
/// https://www.unknowncheats.me/forum/escape-from-tarkov/728902-pve-battleyent-alternative.html
/// Credit goes to all original contributors.
/// 

#include "disabler.h"

#include "../libs/ntdll.h"
#include "../libs/detours.h"
#include <psapi.h>
#include <regex>
#include <shlwapi.h>
#include <fstream>
#include <iosfwd>
#include <mutex>
#include <string>

#include "../util/globals.h"
#include "../util/logger.h"

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ntdll.lib")

static bool patch_completed = false;
static DWORD eft_pid = false;

void patch_bytes(const HANDLE hProcess, void* address, const std::vector<std::uint8_t>& data)
{
    const size_t size = data.size();
    DWORD dwOldProtect = 0;
    VirtualProtectEx(hProcess, address, size, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    WriteProcessMemory(hProcess, address, data.data(), size, nullptr);
    FlushInstructionCache(hProcess, address, size);
    VirtualProtectEx(hProcess, address, size, dwOldProtect, &dwOldProtect);
}

HMODULE find_module(const HANDLE hProcess, const char* name)
{
    HMODULE hMods[1024];
    DWORD cbNeeded;
    char szModName[MAX_PATH];

    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        return FALSE;
    }

    for (unsigned int i = 0; i < cbNeeded / sizeof(HMODULE); i++)
    {
        if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(char)))
        {
            if (StrStrIA(szModName, name))
            {
                return hMods[i];
            }
        }
    }

    return nullptr;
}

using CreateProcessInternalW_t = BOOL(WINAPI *)(
    HANDLE hUserToken,
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation,
    PHANDLE hRestrictedUserToken
);

static CreateProcessInternalW_t oCreateProcessInternalW;

BOOL WINAPI hkCreateProcessInternalW(
    HANDLE hUserToken,
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation,
    PHANDLE hRestrictedUserToken
)
{
    if (lpCommandLine && wcsstr(lpCommandLine, L"EscapeFromTarkov_BE"))
    {
        auto commandLine = std::regex_replace(
            lpCommandLine, std::wregex(L"EscapeFromTarkov_BE"), L"EscapeFromTarkov"
        );

        STARTUPINFOW si;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);

        PROCESS_INFORMATION pi;
        ZeroMemory(&pi, sizeof(pi));

        const auto ret = oCreateProcessInternalW(
            nullptr,
            nullptr,
            const_cast<LPWSTR>(commandLine.data()),
            nullptr,
            nullptr,
            false,
            CREATE_SUSPENDED,
            nullptr,
            lpCurrentDirectory,
            &si,
            &pi,
            nullptr
        );

        HANDLE hProcess = pi.hProcess;
        HANDLE hThread = pi.hThread;

        PROCESS_BASIC_INFORMATION pbi;
        if (!NT_SUCCESS(NtQueryInformationProcess(
            hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr
        )))
        {
            logger::error("Failed to get pbi");
            return FALSE;
        }

        PEB peb = {};
        if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), nullptr))
        {
            return FALSE;
        }

        IMAGE_DOS_HEADER idh = {};
        if (!ReadProcessMemory(hProcess, peb.ImageBaseAddress, &idh, sizeof(idh), nullptr))
        {
            return FALSE;
        }

        IMAGE_NT_HEADERS inh = {};
        if (!ReadProcessMemory(
            hProcess,
            reinterpret_cast<LPVOID>( // NOLINT(performance-no-int-to-ptr)
                reinterpret_cast<ULONG_PTR>(peb.ImageBaseAddress) + idh.e_lfanew
            ),
            &inh,
            sizeof(inh),
            nullptr
        ))
        {
            return FALSE;
        }

        UINT_PTR entry = inh.OptionalHeader.AddressOfEntryPoint + inh.OptionalHeader.ImageBase;

        std::vector<uint8_t> buf(2);
        ReadProcessMemory(hProcess, reinterpret_cast<LPVOID>(entry), buf.data(), 2, nullptr); // NOLINT(performance-no-int-to-ptr, performance-no-int-to-ptr)
        patch_bytes(hProcess, reinterpret_cast<LPVOID>(entry), {0xEB, 0xFE});
        ResumeThread(hThread);

        CONTEXT context;
        GetThreadContext(hThread, &context);
        context.ContextFlags = CONTEXT_FULL;
        for (int i = 0; context.Rip != entry; Sleep(100))
        {
            if (++i > 50)
            {
                logger::error("Entrypoint timed out");
                return FALSE;
            }
            context.ContextFlags = CONTEXT_CONTROL;
            GetThreadContext(hThread, &context);
        }

        SuspendThread(hThread);

        HMODULE hUnityPlayer = find_module(hProcess, "UnityPlayer");
        auto* beCheckFunc =
            reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hUnityPlayer) + 0x491E60); // NOLINT(performance-no-int-to-ptr)
        // B0 01 mov al, 1
        // C3    ret
        patch_bytes(hProcess, beCheckFunc, {0xB0, 0x01, 0xC3});

        patch_bytes(hProcess, reinterpret_cast<LPVOID>(entry), buf);

        ResumeThread(hThread);

        HMODULE hGameAssembly;
        while (!(hGameAssembly = find_module(hProcess, "GameAssembly")))
        {
            Sleep(10);
        }

        auto* loadBEClient =
            reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hGameAssembly) + 0x37E89B0); // NOLINT(performance-no-int-to-ptr)
        patch_bytes(hProcess, loadBEClient, {0xC3}); // C3 ret

        eft_pid = GetProcessId(hProcess);
        patch_completed = true;

        return ret;
    }

    return oCreateProcessInternalW(
        hUserToken,
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation,
        hRestrictedUserToken
    );
}

namespace disabler
{
    DWORD disable()
    {
        std::ifstream config_file(globals::DLL_CONFIG_FILE);
        if (config_file)
        {
            std::string enabled_string;
            for (int i = 0; i < 4; ++i)
            {
                std::getline(config_file, enabled_string);
            }
            enabled_string = enabled_string.substr(9);
            if (enabled_string != "true") return 0;
        }
        else
        {
            return 0;
        }
        logger::info("Disabler Enabled");
        config_file.close();

        DetourRestoreAfterWith();
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        oCreateProcessInternalW = reinterpret_cast<CreateProcessInternalW_t>(
            DetourFindFunction("KernelBase.dll", "CreateProcessInternalW")
        );
        DetourAttach(reinterpret_cast<PVOID*>(&oCreateProcessInternalW), hkCreateProcessInternalW); // NOLINT(clang-diagnostic-microsoft-cast)

        if (DetourTransactionCommit() != NO_ERROR)
        {
            logger::error("Failed to hook CreateProcessInternalW");
            return 0;
        }


        while (!patch_completed)
        {
            Sleep(100);
        }
        return eft_pid;
    }

    void exit()
    {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(reinterpret_cast<PVOID*>(&oCreateProcessInternalW), hkCreateProcessInternalW); // NOLINT(clang-diagnostic-microsoft-cast)
        DetourTransactionCommit();
    }
}
