#include <iostream>
#include <thread>
#include <windows.h>

#include "feature/disabler.h"
#include "feature/injector.h"
#include "feature/spoofer.h"
#include "util/logger.h"

void init()
{
    // init
    AllocConsole();
    int _ = freopen_s(reinterpret_cast<FILE**>(stdout), "conout$", "w", stdout);
    logger::info("Loaded");

    // spoof hwid
    spoofer::init();

    // inject on start
    injector::init();

    // disable anticheat
    DWORD eft_pid = disabler::disable();

    if (eft_pid != 0)
    {
        Sleep(1000);
        // inject dll
        injector::inject(eft_pid);
    }

    logger::info("Exiting");
    exit(0); // NOLINT(concurrency-mt-unsafe)
}

void detatch()
{
    disabler::exit();
    int _ = fclose(stdout);
    FreeConsole();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(init), nullptr, 0, nullptr); // NOLINT(clang-diagnostic-cast-function-type-strict)
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        if (lpReserved != nullptr)
        {
            break;
        }
        detatch();
        break;
    }

    return TRUE;
}
