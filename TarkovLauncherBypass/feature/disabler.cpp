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

static bool eft_started = false;
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

static HMODULE find_module(const HANDLE hProcess, const char* name)
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

        eft_pid = GetProcessId(hProcess);
        eft_started = true;

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
        patch_bytes(hProcess, reinterpret_cast<LPVOID>(entry), {0xEB, 0xFE}); // NOLINT(performance-no-int-to-ptr)
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
        MODULEINFO unityInfo = {};
        GetModuleInformation(hProcess, hUnityPlayer, &unityInfo, sizeof(MODULEINFO));
        auto unityModule = new char[unityInfo.SizeOfImage];
        ReadProcessMemory(hProcess, unityInfo.lpBaseOfDll, unityModule, unityInfo.SizeOfImage, nullptr);
        std::string checkBeServicePattern = "48 89 5C 24 ? 48 89 6C 24 ? 56 57 41 56 48 83 EC ? 33 C0 0F 57 C0";
        UINT64 checkBeServiceOffset = globals::find_pattern(checkBeServicePattern, unityModule, unityInfo.SizeOfImage);
        if (checkBeServiceOffset == 0)
        {
            logger::error("Disabler Failed: Check BE Service Function Missing");
            TerminateProcess(hProcess, 0);
            Sleep(2000);
            exit(0); // NOLINT(concurrency-mt-unsafe)
        }
        auto* beCheckFunc =
            reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hUnityPlayer) + checkBeServiceOffset); // NOLINT(performance-no-int-to-ptr)
        delete[] unityModule;

        // B0 01 mov al, 1
        // C3    ret
        patch_bytes(hProcess, beCheckFunc, {0xB0, 0x01, 0xC3});

        patch_bytes(hProcess, reinterpret_cast<LPVOID>(entry), buf); // NOLINT(performance-no-int-to-ptr)

        ResumeThread(hThread);

        HMODULE hGameAssembly;
        while (!((hGameAssembly = find_module(hProcess, "GameAssembly"))))
        {
            Sleep(10);
        }

        MODULEINFO gameInfo = {};
        GetModuleInformation(hProcess, hGameAssembly, &gameInfo, sizeof(MODULEINFO));
        auto gameModule = new char[gameInfo.SizeOfImage];
        ReadProcessMemory(hProcess, gameInfo.lpBaseOfDll, gameModule, gameInfo.SizeOfImage, nullptr);
        std::string loadBeClientPattern =
            "48 89 4C 24 ? 53 56 57 41 54 41 55 41 56 41 57 48 83 EC ? 48 8B F9 80 3D ? ? ? ? 00 0F 85 ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? ? ? ? ? 00 48 8D 0D ? ? ? ? E8 ? ? ? ? ? ? ? ? 00 48 8D 0D ? ? ? ? E8 ? ? ? ? ? ? ? ? 00 48 8D 0D ? ? ? ? E8 ? ? ? ? ? ? ? ? 00 48 8D 0D ? ? ? ? E8 ? ? ? ? ? ? ? ? 00 48 8D 0D ? ? ? ? E8 ? ? ? ? ? ? ? ? 00 48 8D 0D ? ? ? ? E8 ? ? ? ? ? ? ? ? 00 48 8D 0D ? ? ? ? E8 ? ? ? ? ? ? ? ? 00 48 8D 0D ? ? ? ? E8 ? ? ? ? ? ? ? ? 00 48 8D 0D ? ? ? ? E8 ? ? ? ? ? ? ? ? 00 48 8D 0D ? ? ? ? E8 ? ? ? ? ? ? ? ? 00 48 8D 0D ? ? ? ? E8 ? ? ? ? ? ? ? ? 00 C6 05";
        UINT64 loadBeClientOffset = globals::find_pattern(loadBeClientPattern, gameModule, gameInfo.SizeOfImage);
        if (loadBeClientOffset == 0)
        {
            logger::error("Disabler Failed: Load BE Client Function Missing");
            TerminateProcess(hProcess, 0);
            Sleep(2000);
            exit(0); // NOLINT(concurrency-mt-unsafe)
        }
        auto* loadBEClient =
            reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hGameAssembly) + loadBeClientOffset); // NOLINT(performance-no-int-to-pt
        delete[] gameModule;
        patch_bytes(hProcess, loadBEClient, {0xC3}); // C3 ret

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


        while (!eft_started)
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
