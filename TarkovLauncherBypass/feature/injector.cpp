#include "injector.h"

#include <fstream>
#include <iostream>
#include <string>
#include <wbemcli.h>

#include "../util/globals.h"
#include "../util/logger.h"

namespace injector
{
    std::string dllIn;

    void init()
    {
        std::ifstream file(globals::DLL_CONFIG_FILE);
        if (file)
        {
            std::string enabled_string;
            for (int i = 0; i < 2; ++i)
            {
                std::getline(file, dllIn);
            }
            for (int i = 0; i < 3; ++i)
            {
                std::getline(file, enabled_string);
            }
            dllIn = dllIn.substr(7);
            enabled_string = enabled_string.substr(7);
            if (enabled_string != "true") return;
        }
        else
        {
            return;
        }
        logger::info("Injector Enabled");
        file.close();
    }

    void inject(DWORD eft_pid)
    {
        logger::info("Injecting: " + dllIn);
        WCHAR path[MAX_PATH];
        GetModuleFileNameW(nullptr, path, MAX_PATH);
        auto wpath = std::wstring(path);
        size_t filename = wpath.find(L"BsgLauncher.exe");
        wpath = wpath.substr(0, filename);
        dllIn = std::string(wpath.begin(), wpath.end()).append(dllIn);
        auto dll = const_cast<char*>(dllIn.c_str());
        HANDLE eft = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
            PROCESS_VM_OPERATION, false, eft_pid);
        if (eft != nullptr)
        {
            auto fnLoadLibrary = reinterpret_cast<LPVOID>(GetProcAddress(
                GetModuleHandle(L"kernel32.dll"), "LoadLibraryA"));
            LPVOID mem = VirtualAllocEx(eft, nullptr, strlen(dll) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            WriteProcessMemory(eft, mem, dll, strlen(dll) + 1, nullptr);
            HANDLE thread = CreateRemoteThread(eft, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(fnLoadLibrary),
                                               mem, 0, nullptr);
            while (WaitForSingleObject(thread, 0) != WAIT_OBJECT_0)
            {
                Sleep(10);
            }
            VirtualFreeEx(eft, mem, strlen(dll) + 1, MEM_RELEASE);
            CloseHandle(eft);
        }
    }
}
