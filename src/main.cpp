
#include "mge/configuration.h"
#include "mge/mgeversion.h"
#include "mge/mwinitpatch.h"
#include "mwse/mgebridge.h"
#include "support/winheader.h"
#include "support/log.h"

#include <cstdio>
#include <cstring>



extern void* CreateD3DWrapper(UINT);
extern void* CreateInputWrapper(void*);

static FARPROC getProc1(const char* lib, const char* funcname);
static void setDPIScalingAware();

static const char* welcomeMessage = XE_VERSION_STRING;
static bool isMW;
static bool isCS;

static void OpenLog() {
    if (isMW) {
        LOG::open("mgeXE.log");
    }
    else if (isCS) {
        LOG::open("mgeXE-CS.log");
    }
    LOG::logline(welcomeMessage);
}

extern "C" BOOL _stdcall DllMain(HANDLE hModule, DWORD reason, void* unused) {
    if (reason != DLL_PROCESS_ATTACH) {
        return true;
    }

    // Check if MW is in-process, avoid hooking the CS
    isMW = bool(GetModuleHandleA("Morrowind.exe"));
    isCS = bool(GetModuleHandleA("TES Construction Set.exe"));
    const auto affectsModule = isMW || isCS;
    if (!affectsModule) {
        return true;
    }

    OpenLog();

    if (GetModuleHandleA(nullptr) != reinterpret_cast<HMODULE>(0x400000)) {
        LOG::logline("ERROR: Application was relocated from its expected base address. Disable compatibility shims or Exploit Protection forced ASLR for this executable.");
        LOG::logline("MGE XE load failed.");

        return true;
    }

    if (isMW) {
        setDPIScalingAware();

        if (!Configuration.LoadSettings()) {
            LOG::logline("Error: MGE XE is not configured. MGE XE will be disabled for this session.");
            isMW = false;
            return true;
        }

        if (Configuration.MGEFlags & MGE_DISABLED) {
            // Signal that DirectX proxies should not load
            isMW = false;
        }

        // Early startup patches
        MWInitPatch::patch();

        if (~Configuration.MGEFlags & MWSE_DISABLED) {
            // Load MWSE dll, it injects by itself
            HMODULE dll = LoadLibraryA("MWSE.dll");

            if (dll) {
                if ((~Configuration.MGEFlags & MGE_DISABLED) && !Configuration.OnlyProxyD3D8To9) {
                    // MWSE-MGE integration
                    MWSE_MGEPlugin::init(dll);
                }
                LOG::logline("MWSE.dll injected.");
            } else {
                const auto lastError = GetLastError();
                char message[1024] = {};
                FormatMessageA(
                    FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                    nullptr,
                    lastError,
                    0,
                    message,
                    sizeof(message),
                    nullptr
                );
                message[std::strcspn(message, "\r\n")] = '\0';

                LOG::logline("MWSE failed to load. Last error (%lu): %s ", lastError, message);
            }
        } else {
            LOG::logline("MWSE is disabled.");
        }
    }

    // Load extender for CS, if Construction Set detected
    if (isCS) {
        // Load CSSE dll, it injects by itself
        const auto hCSSE = LoadLibraryA("CSSE.dll");
        if (hCSSE) {
            LOG::logline("CSSE.dll injected.");
        }
        else {
            const auto lastError = GetLastError();
            char message[1024] = {};
            FormatMessageA(
                FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                nullptr,
                lastError,
                0,
                message,
                sizeof(message),
                nullptr
            );
            message[std::strcspn(message, "\r\n")] = '\0';

            LOG::logline("CSSE failed to load. Last error (%lu): %s ", lastError, message);
        }
    }

    return true;
}



extern "C" void* _stdcall FakeDirect3DCreate(UINT version) {
    // Wrap Morrowind only, not TESCS
    if (isMW) {
        return CreateD3DWrapper(version);
    } else {
        // Use system D3D8
        typedef void* (_stdcall * D3DProc) (UINT);
        D3DProc func = (D3DProc)getProc1("d3d8.dll", "Direct3DCreate8");
        return (func)(version);
    }
}

extern "C" HRESULT _stdcall FakeDirectInputCreate(HINSTANCE a, DWORD b, REFIID c, void** d, void* e) {
    typedef HRESULT (_stdcall * DInputProc) (HINSTANCE, DWORD, REFIID, void**, void*);
    DInputProc func = (DInputProc)getProc1("dinput8.dll", "DirectInput8Create");

    void* dinput = 0;
    HRESULT hr = (func)(a, b, c, &dinput, e);

    if (hr == S_OK) {
        if (isMW) {
            *d = CreateInputWrapper(dinput);
        } else {
            *d = dinput;
        }
    }

    return hr;
}


FARPROC getProc1(const char* lib, const char* funcname) {
    // Get the address of a single function from a dll
    char syspath[MAX_PATH], path[MAX_PATH];
    GetSystemDirectoryA(syspath, sizeof(syspath));

    int str_sz = std::snprintf(path, sizeof(path), "%s\\%s", syspath, lib);
    if (str_sz >= sizeof(path)) {
        return NULL;
    }

    HMODULE dll = LoadLibraryA(path);
    if (dll == NULL) {
        return NULL;
    }

    return GetProcAddress(dll, funcname);
}

void setDPIScalingAware() {
    // Prevent DPI scaling from affecting chosen window size
    typedef BOOL (WINAPI * dpiProc)();
    dpiProc SetProcessDPIAware = (dpiProc)getProc1("user32.dll", "SetProcessDPIAware");

    if (SetProcessDPIAware) {
        SetProcessDPIAware();
    }
}
