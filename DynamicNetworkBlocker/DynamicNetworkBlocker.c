#pragma comment(lib, "ws2_32.lib")

#define BUILDING_DLL 1

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <tchar.h>
#include <winsock2.h>
#include <windows.h>
#include "LogFile.h"
#include "DynamicNetworkBlocker.h"

typedef int (WSAAPI *PSEND)(
    __in  SOCKET s,
    __in  const char *buf,
    __in  int len,
    __in  int flags);
typedef int (WSAAPI *PWSASEND)(
    __in   SOCKET s,
    __in   LPWSABUF lpBuffers,
    __in   DWORD dwBufferCount,
    __out  LPDWORD lpNumberOfBytesSent,
    __in   DWORD dwFlags,
    __in   LPWSAOVERLAPPED lpOverlapped,
    __in   LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
typedef int (WSAAPI *PWSASENDTO)(
    __in   SOCKET s,
    __in   LPWSABUF lpBuffers,
    __in   DWORD dwBufferCount,
    __out  LPDWORD lpNumberOfBytesSent,
    __in   DWORD dwFlags,
    __in   const struct sockaddr *lpTo,
    __in   int iToLen,
    __in   LPWSAOVERLAPPED lpOverlapped,
    __in   LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

typedef BOOL (WINAPI *PCREATEPROCESSW)(
    __in_opt     LPCWSTR lpApplicationName,
    __inout_opt  LPWSTR lpCommandLine,
    __in_opt     LPSECURITY_ATTRIBUTES lpProcessAttributes,
    __in_opt     LPSECURITY_ATTRIBUTES lpThreadAttributes,
    __in         BOOL bInheritHandles,
    __in         DWORD dwCreationFlags,
    __in_opt     LPVOID lpEnvironment,
    __in_opt     LPCWSTR lpCurrentDirectory,
    __in         LPSTARTUPINFOW lpStartupInfo,
    __out        LPPROCESS_INFORMATION lpProcessInformation);
typedef BOOL (WINAPI *PCREATEPROCESSA)(
    __in_opt     LPCSTR lpApplicationName,
    __inout_opt  LPSTR lpCommandLine,
    __in_opt     LPSECURITY_ATTRIBUTES lpProcessAttributes,
    __in_opt     LPSECURITY_ATTRIBUTES lpThreadAttributes,
    __in         BOOL bInheritHandles,
    __in         DWORD dwCreationFlags,
    __in_opt     LPVOID lpEnvironment,
    __in_opt     LPCSTR lpCurrentDirectory,
    __in         LPSTARTUPINFOA lpStartupInfo,
    __out        LPPROCESS_INFORMATION lpProcessInformation);
typedef BOOL (WINAPI *PCREATEPROCESSASUSERW)(
    __in_opt     HANDLE hToken,
    __in_opt     LPCWSTR lpApplicationName,
    __inout_opt  LPWSTR lpCommandLine,
    __in_opt     LPSECURITY_ATTRIBUTES lpProcessAttributes,
    __in_opt     LPSECURITY_ATTRIBUTES lpThreadAttributes,
    __in         BOOL bInheritHandles,
    __in         DWORD dwCreationFlags,
    __in_opt     LPVOID lpEnvironment,
    __in_opt     LPCWSTR lpCurrentDirectory,
    __in         LPSTARTUPINFO lpStartupInfo,
    __out        LPPROCESS_INFORMATION lpProcessInformation);
typedef BOOL (WINAPI *PCREATEPROCESSASUSERA)(
    __in_opt     HANDLE hToken,
    __in_opt     LPCSTR lpApplicationName,
    __inout_opt  LPSTR lpCommandLine,
    __in_opt     LPSECURITY_ATTRIBUTES lpProcessAttributes,
    __in_opt     LPSECURITY_ATTRIBUTES lpThreadAttributes,
    __in         BOOL bInheritHandles,
    __in         DWORD dwCreationFlags,
    __in_opt     LPVOID lpEnvironment,
    __in_opt     LPCSTR lpCurrentDirectory,
    __in         LPSTARTUPINFO lpStartupInfo,
    __out        LPPROCESS_INFORMATION lpProcessInformation);
typedef BOOL (WINAPI *PCREATEPROCESSWITHLOGONW)(
    __in         LPCWSTR lpUsername,
    __in_opt     LPCWSTR lpDomain,
    __in         LPCWSTR lpPassword,
    __in         DWORD dwLogonFlags,
    __in_opt     LPCWSTR lpApplicationName,
    __inout_opt  LPWSTR lpCommandLine,
    __in         DWORD dwCreationFlags,
    __in_opt     LPVOID lpEnvironment,
    __in_opt     LPCWSTR lpCurrentDirectory,
    __in         LPSTARTUPINFOW lpStartupInfo,
    __out        LPPROCESS_INFORMATION lpProcessInfo);
typedef BOOL (WINAPI *PCREATEPROCESSWITHTOKENW)(
    __in         HANDLE hToken,
    __in         DWORD dwLogonFlags,
    __in_opt     LPCWSTR lpApplicationName,
    __inout_opt  LPWSTR lpCommandLine,
    __in         DWORD dwCreationFlags,
    __in_opt     LPVOID lpEnvironment,
    __in_opt     LPCWSTR lpCurrentDirectory,
    __in         LPSTARTUPINFOW lpStartupInfo,
    __out        LPPROCESS_INFORMATION lpProcessInfo);

static PSEND        gOrigSend        = NULL;
static PWSASEND        gOrigWSASend    = NULL;
static PWSASENDTO    gOrigWSASendTo    = NULL;

static PCREATEPROCESSW          gOrigCreateProcessW          = NULL;
static PCREATEPROCESSA          gOrigCreateProcessA          = NULL;
static PCREATEPROCESSASUSERW    gOrigCreateProcessAsUserW    = NULL;
static PCREATEPROCESSASUSERA    gOrigCreateProcessAsUserA    = NULL;
static PCREATEPROCESSWITHLOGONW gOrigCreateProcessWithLogonW = NULL;
static PCREATEPROCESSWITHTOKENW gOrigCreateProcessWithTokenW = NULL;

static char gSelfPath[MAX_PATH] = {0};

static int InjectSuspendedProcess(HANDLE hProcess, HANDLE hThread)
{
    int ret = -1;

    HANDLE hInject = INVALID_HANDLE_VALUE;
    LPVOID pNameAddress = NULL;

    do 
    {
        /* get Kernel32.dll->LoadLibraryA address */
        LPTHREAD_START_ROUTINE lpfLoadLibraryA = 
            (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA");

        if (lpfLoadLibraryA == NULL)
            break;

        /* malloc a space in hVictim to store DLL name */
        pNameAddress = VirtualAllocEx(
            hProcess, 
            NULL, 
            strlen(gSelfPath), 
            MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);

        if (pNameAddress == NULL)
            break;

        /* write DLL name to pNameAddress */
        if(!WriteProcessMemory(hProcess, pNameAddress, gSelfPath, strlen(gSelfPath), NULL))
            break;

        /* create a remote thread to load DLL_NAME */
        hInject = CreateRemoteThread(
            hProcess, 
            NULL, 
            0, 
            lpfLoadLibraryA, 
            pNameAddress, 
            0, 
            NULL);

        if (hInject == NULL)
            break;

        if (hThread != INVALID_HANDLE_VALUE && hThread != NULL)
            (void)ResumeThread(hThread);

        /* wait for load complete */
        (void)WaitForSingleObject(hInject, INFINITE);

        ret = 0;
    } while (0);

    VirtualFreeEx(hProcess, pNameAddress, 0, MEM_RELEASE);
    CloseHandle(hInject);

    return ret;
}

static int WSAAPI __stdcall MySend(
    __in  SOCKET s,
    __in  const char *buf,
    __in  int len,
    __in  int flags)
{
    if (gOrigSend)
    {
        WRITE_LOG_INFO("Intercept send success!");

        return gOrigSend(
            s,
            buf,
            len,
            flags);
    }

    return 0;
}

static int WSAAPI __stdcall MyWSASend(
    __in   SOCKET s,
    __in   LPWSABUF lpBuffers,
    __in   DWORD dwBufferCount,
    __out  LPDWORD lpNumberOfBytesSent,
    __in   DWORD dwFlags,
    __in   LPWSAOVERLAPPED lpOverlapped,
    __in   LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    if (gOrigWSASend)
    {
        WRITE_LOG_INFO("Intercept WSASend success!");

        return gOrigWSASend(
            s,
            lpBuffers,
            dwBufferCount,
            lpNumberOfBytesSent,
            dwFlags,
            lpOverlapped,
            lpCompletionRoutine);
    }

    return 0;
}
 
static int WSAAPI __stdcall MyWSASendTo(
    __in   SOCKET s,
    __in   LPWSABUF lpBuffers,
    __in   DWORD dwBufferCount,
    __out  LPDWORD lpNumberOfBytesSent,
    __in   DWORD dwFlags,
    __in   const struct sockaddr *lpTo,
    __in   int iToLen,
    __in   LPWSAOVERLAPPED lpOverlapped,
    __in   LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    if (gOrigWSASendTo)
    {
        WRITE_LOG_INFO("Intercept WSASendTo success!");

        return gOrigWSASendTo(
            s, 
            lpBuffers, 
            dwBufferCount, 
            lpNumberOfBytesSent, 
            dwFlags, 
            lpTo, 
            iToLen, 
            lpOverlapped, 
            lpCompletionRoutine);
    }

    return 0;
}

static BOOL WINAPI MyCreateProcessW(
    __in_opt     LPCWSTR lpApplicationName,
    __inout_opt  LPWSTR lpCommandLine,
    __in_opt     LPSECURITY_ATTRIBUTES lpProcessAttributes,
    __in_opt     LPSECURITY_ATTRIBUTES lpThreadAttributes,
    __in         BOOL bInheritHandles,
    __in         DWORD dwCreationFlags,
    __in_opt     LPVOID lpEnvironment,
    __in_opt     LPCWSTR lpCurrentDirectory,
    __in         LPSTARTUPINFOW lpStartupInfo,
    __out        LPPROCESS_INFORMATION lpProcessInformation)
{
    BOOL ret = FALSE;

    if (gOrigCreateProcessW)
    {
        WRITE_LOG_INFO("Intercept CreateProcessW success!");

        ret = gOrigCreateProcessW(
            lpApplicationName,
            lpCommandLine,
            lpProcessAttributes,
            lpThreadAttributes,
            bInheritHandles,
            dwCreationFlags | CREATE_SUSPENDED,
            lpEnvironment,
            lpCurrentDirectory,
            lpStartupInfo,
            lpProcessInformation);

        if (ret != FALSE)
        {
            if (InjectSuspendedProcess(
                lpProcessInformation->hProcess, 
                lpProcessInformation->hThread))
            {
                WRITE_LOG_INFO("InjectSuspendedProcess failed!");
            }
            else
            {
                WRITE_LOG_INFO("InjectSuspendedProcess success!");
            }
        }
    }

    return ret;
}

static BOOL WINAPI MyCreateProcessA(
    __in_opt     LPCSTR lpApplicationName,
    __inout_opt  LPSTR lpCommandLine,
    __in_opt     LPSECURITY_ATTRIBUTES lpProcessAttributes,
    __in_opt     LPSECURITY_ATTRIBUTES lpThreadAttributes,
    __in         BOOL bInheritHandles,
    __in         DWORD dwCreationFlags,
    __in_opt     LPVOID lpEnvironment,
    __in_opt     LPCSTR lpCurrentDirectory,
    __in         LPSTARTUPINFOA lpStartupInfo,
    __out        LPPROCESS_INFORMATION lpProcessInformation)
{
    BOOL ret = FALSE;

    if (gOrigCreateProcessA)
    {
        WRITE_LOG_INFO("Intercept CreateProcessA success!");
        
        ret = gOrigCreateProcessA(
            lpApplicationName,
            lpCommandLine,
            lpProcessAttributes,
            lpThreadAttributes,
            bInheritHandles,
            dwCreationFlags | CREATE_SUSPENDED,
            lpEnvironment,
            lpCurrentDirectory,
            lpStartupInfo,
            lpProcessInformation);

        if (ret != FALSE)
        {
            if (InjectSuspendedProcess(
                lpProcessInformation->hProcess, 
                lpProcessInformation->hThread))
            {
                WRITE_LOG_INFO("InjectSuspendedProcess failed!");
            }
            else
            {
                WRITE_LOG_INFO("InjectSuspendedProcess success!");
            }
        }
    }

    return ret;
}

static BOOL WINAPI MyCreateProcessAsUserW(
    __in_opt     HANDLE hToken,
    __in_opt     LPCWSTR lpApplicationName,
    __inout_opt  LPWSTR lpCommandLine,
    __in_opt     LPSECURITY_ATTRIBUTES lpProcessAttributes,
    __in_opt     LPSECURITY_ATTRIBUTES lpThreadAttributes,
    __in         BOOL bInheritHandles,
    __in         DWORD dwCreationFlags,
    __in_opt     LPVOID lpEnvironment,
    __in_opt     LPCWSTR lpCurrentDirectory,
    __in         LPSTARTUPINFO lpStartupInfo,
    __out        LPPROCESS_INFORMATION lpProcessInformation)
{
    BOOL ret = FALSE;

    if (gOrigCreateProcessAsUserW)
    {
        WRITE_LOG_INFO("Intercept CreateProcessAsUserW success!");

        ret = gOrigCreateProcessAsUserW(
            hToken,
            lpApplicationName,
            lpCommandLine,
            lpProcessAttributes,
            lpThreadAttributes,
            bInheritHandles,
            dwCreationFlags | CREATE_SUSPENDED,
            lpEnvironment,
            lpCurrentDirectory,
            lpStartupInfo,
            lpProcessInformation);

        if (ret != FALSE)
        {
            if (InjectSuspendedProcess(
                lpProcessInformation->hProcess, 
                lpProcessInformation->hThread))
            {
                WRITE_LOG_INFO("InjectSuspendedProcess failed!");
            }
            else
            {
                WRITE_LOG_INFO("InjectSuspendedProcess success!");
            }
        }
    }

    return ret;
}

static BOOL WINAPI MyCreateProcessAsUserA(
    __in_opt     HANDLE hToken,
    __in_opt     LPCSTR lpApplicationName,
    __inout_opt  LPSTR lpCommandLine,
    __in_opt     LPSECURITY_ATTRIBUTES lpProcessAttributes,
    __in_opt     LPSECURITY_ATTRIBUTES lpThreadAttributes,
    __in         BOOL bInheritHandles,
    __in         DWORD dwCreationFlags,
    __in_opt     LPVOID lpEnvironment,
    __in_opt     LPCSTR lpCurrentDirectory,
    __in         LPSTARTUPINFO lpStartupInfo,
    __out        LPPROCESS_INFORMATION lpProcessInformation)
{
    BOOL ret = FALSE;

    if (gOrigCreateProcessAsUserA)
    {
        WRITE_LOG_INFO("Intercept CreateProcessAsUserA success!");

        ret = gOrigCreateProcessAsUserA(
            hToken,
            lpApplicationName,
            lpCommandLine,
            lpProcessAttributes,
            lpThreadAttributes,
            bInheritHandles,
            dwCreationFlags | CREATE_SUSPENDED,
            lpEnvironment,
            lpCurrentDirectory,
            lpStartupInfo,
            lpProcessInformation);

        if (ret != FALSE)
        {
            if (InjectSuspendedProcess(
                lpProcessInformation->hProcess, 
                lpProcessInformation->hThread))
            {
                WRITE_LOG_INFO("InjectSuspendedProcess failed!");
            }
            else
            {
                WRITE_LOG_INFO("InjectSuspendedProcess success!");
            }
        }
    }

    return ret;
}

static BOOL WINAPI MyCreateProcessWithLogonW(
    __in         LPCWSTR lpUsername,
    __in_opt     LPCWSTR lpDomain,
    __in         LPCWSTR lpPassword,
    __in         DWORD dwLogonFlags,
    __in_opt     LPCWSTR lpApplicationName,
    __inout_opt  LPWSTR lpCommandLine,
    __in         DWORD dwCreationFlags,
    __in_opt     LPVOID lpEnvironment,
    __in_opt     LPCWSTR lpCurrentDirectory,
    __in         LPSTARTUPINFOW lpStartupInfo,
    __out        LPPROCESS_INFORMATION lpProcessInfo)
{
    BOOL ret = FALSE;

    if (gOrigCreateProcessWithLogonW)
    {
        WRITE_LOG_INFO("Intercept CreateProcessWithLogonW success!");

        ret = gOrigCreateProcessWithLogonW(
            lpUsername,
            lpDomain,
            lpPassword,
            dwLogonFlags,
            lpApplicationName,
            lpCommandLine,
            dwCreationFlags | CREATE_SUSPENDED,
            lpEnvironment,
            lpCurrentDirectory,
            lpStartupInfo,
            lpProcessInfo);

        if (ret != FALSE)
        {
            if (InjectSuspendedProcess(
                lpProcessInfo->hProcess, 
                lpProcessInfo->hThread))
            {
                WRITE_LOG_INFO("InjectSuspendedProcess failed!");
            }
            else
            {
                WRITE_LOG_INFO("InjectSuspendedProcess success!");
            }
        }
    }

    return ret;
}

static BOOL WINAPI MyCreateProcessWithTokenW(
    __in         HANDLE hToken,
    __in         DWORD dwLogonFlags,
    __in_opt     LPCWSTR lpApplicationName,
    __inout_opt  LPWSTR lpCommandLine,
    __in         DWORD dwCreationFlags,
    __in_opt     LPVOID lpEnvironment,
    __in_opt     LPCWSTR lpCurrentDirectory,
    __in         LPSTARTUPINFOW lpStartupInfo,
    __out        LPPROCESS_INFORMATION lpProcessInfo)
{
    BOOL ret = FALSE;

    if (gOrigCreateProcessWithTokenW)
    {
        WRITE_LOG_INFO("Intercept CreateProcessWithTokenW success!");

        ret = gOrigCreateProcessWithTokenW(
            hToken,
            dwLogonFlags,
            lpApplicationName,
            lpCommandLine,
            dwCreationFlags | CREATE_SUSPENDED,
            lpEnvironment,
            lpCurrentDirectory,
            lpStartupInfo,
            lpProcessInfo);

        if (ret != FALSE)
        {
            if (InjectSuspendedProcess(
                lpProcessInfo->hProcess, 
                lpProcessInfo->hThread))
            {
                WRITE_LOG_INFO("InjectSuspendedProcess failed!");
            }
            else
            {
                WRITE_LOG_INFO("InjectSuspendedProcess success!");
            }
        }
    }

    return ret;
}

static void *GetFuncPatchedAddr(const void *pProc)
{
    void *ret = NULL;

    const BYTE *pLongJump = ((const BYTE *)pProc - 5);          // offset: -5, len: BYTE    
    const DWORD *pLongJumpAdr = ((const DWORD *)pProc - 1);     // offset: -4, len: DWORD
    const WORD *pJumpBack = (const WORD *)pProc;                // offset: 0, len: WORD

    /* only process unpatched function */
    if ((0x90 == *pLongJump) &&                                 // old value: 1 nop
        /* 0x90909090 */
        /* here is the pProc's entry */
        (0xff8b == *pJumpBack))                                 // old value: mov edi,edi
    {
        return ((BYTE *)pProc) + 2;
    }

    return NULL;
}

static int HotPatch(void *pOldProc, const void *pNewProc, void **ppOrigFn)
{
    int ret = -1;

    DWORD dwOldProtect = 0;

    BYTE *pLongJump = ((BYTE *)pOldProc - 5);                   // offset: -5, len: BYTE
    DWORD *pLongJumpAdr = ((DWORD *)pOldProc - 1);              // offset: -4, len: DWORD
    WORD *pJumpBack = (WORD *)pOldProc;                         // offset: 0, len: WORD

    if (!VirtualProtect(pLongJump, 7, PAGE_EXECUTE_WRITECOPY, &dwOldProtect))
    {
        return -1;
    }

    if ((0x90 == *pLongJump) &&                                 // old value: 1 nop
        /* 0x90909090 */
        /* here is the pOldProc's entry */
        (0xFF8B == *pJumpBack))                                 // old value: mov edi,edi
    {
        *pLongJump = 0xE9;                                      // long jmp    
        *pLongJumpAdr = ((DWORD)pNewProc) - ((DWORD)pOldProc);  // pNewProc offset
        *pJumpBack = 0xF9EB;                                    // short jump back 7(back 5, plus 2 for this jump)

        if (ppOrigFn)
            *ppOrigFn = ((BYTE *)pOldProc) + 2;

        ret = 0;
    }

    if (!VirtualProtect(pLongJump, 7, dwOldProtect, &dwOldProtect))
    {
        return -1;
    }

    return ret;
}

static int HotUnpatch(void *pOldProc)
{
    int ret = -1;

    DWORD dwOldProtect = 0;

    BYTE *pLongJump = ((BYTE *)pOldProc - 5);                   // offset: -5, len: BYTE
    WORD *pJumpBack = (WORD *)pOldProc;                         // offset: 0, len: WORD

    if (!VirtualProtect(pLongJump, 7, PAGE_EXECUTE_WRITECOPY, &dwOldProtect))
    {
        return -1;
    }

    if (0xF9EB == *pJumpBack)
    {
        *pLongJump = 0x90;
        *pJumpBack = 0xFF8B;

        ret = 0;
    }

    if (!VirtualProtect(pLongJump, 7, dwOldProtect, &dwOldProtect))
    {
        return -1;
    }

    return ret;
}

static void UnHook()
{
    int success = 0;

    do
    {
        void *pAddr = NULL;

        if (!(pAddr = GetProcAddress(GetModuleHandleA("Ws2_32.dll"), "send")))
            break;
        if (HotUnpatch(pAddr))
            break;
        gOrigSend = NULL;

        if (!(pAddr = GetProcAddress(GetModuleHandleA("Ws2_32.dll"), "WSASend")))
            break;
        if (HotUnpatch(pAddr))
            break;
        gOrigWSASend = NULL;

        if (!(pAddr = GetProcAddress(GetModuleHandleA("Ws2_32.dll"), "WSASendTo")))
            break;
        if (HotUnpatch(pAddr))
            break;
        gOrigWSASendTo = NULL;

        if (!(pAddr = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "CreateProcessW")))
            break;
        if (HotUnpatch(pAddr))
            break;
        gOrigCreateProcessW = NULL;

        if (!(pAddr = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "CreateProcessA")))
            break;
        if (HotUnpatch(pAddr))
            break;
        gOrigCreateProcessA = NULL;

        if (!(pAddr = GetProcAddress(GetModuleHandleA("Advapi32.dll"), "CreateProcessAsUserW")))
            break;
        if (HotUnpatch(pAddr))
            break;
        gOrigCreateProcessAsUserW = NULL;

        if (!(pAddr = GetProcAddress(GetModuleHandleA("Advapi32.dll"), "CreateProcessAsUserA")))
            break;
        if (HotUnpatch(pAddr))
            break;
        gOrigCreateProcessAsUserA = NULL;

        if (!(pAddr = GetProcAddress(GetModuleHandleA("Advapi32.dll"), "CreateProcessWithLogonW")))
            break;
        if (HotUnpatch(pAddr))
            break;
        gOrigCreateProcessWithLogonW = NULL;

        if (!(pAddr = GetProcAddress(GetModuleHandleA("Advapi32.dll"), "CreateProcessWithTokenW")))
            break;
        if (HotUnpatch(pAddr))
            break;
        gOrigCreateProcessWithTokenW = NULL;

        success = 1;
    } while (0);

    if (success)
        WRITE_LOG_INFO("UnHook success!");
    else
        WRITE_LOG_INFO("UnHook failed!");
}

static BOOL Hook()
{
    BOOL success = FALSE;

    do
    {
        void *pAddr = NULL;

        if (!(pAddr = GetProcAddress(GetModuleHandleA("Ws2_32.dll"), "send")))
            break;
        if (!(gOrigSend = (PSEND)GetFuncPatchedAddr(pAddr)))
            break;
        if (HotPatch(pAddr, MySend, NULL))
            break;

        if (!(pAddr = GetProcAddress(GetModuleHandleA("Ws2_32.dll"), "WSASend")))
            break;
        if (!(gOrigWSASend = (PWSASEND)GetFuncPatchedAddr(pAddr)))
            break;
        if (HotPatch(pAddr, MyWSASend, NULL))
            break;

        if (!(pAddr = GetProcAddress(GetModuleHandleA("Ws2_32.dll"), "WSASendTo")))
            break;
        if (!(gOrigWSASendTo = (PWSASENDTO)GetFuncPatchedAddr(pAddr)))
            break;
        if (HotPatch(pAddr, MyWSASendTo, NULL))
            break;

        if (!(pAddr = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "CreateProcessW")))
            break;
        if (!(gOrigCreateProcessW = (PCREATEPROCESSW)GetFuncPatchedAddr(pAddr)))
            break;
        if (HotPatch(pAddr, MyCreateProcessW, NULL))
            break;

        if (!(pAddr = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "CreateProcessA")))
            break;
        if (!(gOrigCreateProcessA = (PCREATEPROCESSA)GetFuncPatchedAddr(pAddr)))
            break;
        if (HotPatch(pAddr, MyCreateProcessA, NULL))
            break;

        if (!(pAddr = GetProcAddress(GetModuleHandleA("Advapi32.dll"), "CreateProcessAsUserW")))
            break;
        if (!(gOrigCreateProcessAsUserW = (PCREATEPROCESSASUSERW)GetFuncPatchedAddr(pAddr)))
            break;
        if (HotPatch(pAddr, MyCreateProcessA, NULL))
            break;

        if (!(pAddr = GetProcAddress(GetModuleHandleA("Advapi32.dll"), "CreateProcessAsUserA")))
            break;
        if (!(gOrigCreateProcessAsUserA = (PCREATEPROCESSASUSERA)GetFuncPatchedAddr(pAddr)))
            break;
        if (HotPatch(pAddr, MyCreateProcessA, NULL))
            break;

        if (!(pAddr = GetProcAddress(GetModuleHandleA("Advapi32.dll"), "CreateProcessWithLogonW")))
            break;
        if (!(gOrigCreateProcessWithLogonW = (PCREATEPROCESSWITHLOGONW)GetFuncPatchedAddr(pAddr)))
            break;
        if (HotPatch(pAddr, MyCreateProcessA, NULL))
            break;

        if (!(pAddr = GetProcAddress(GetModuleHandleA("Advapi32.dll"), "CreateProcessWithTokenW")))
            break;
        if (!(gOrigCreateProcessWithTokenW = (PCREATEPROCESSWITHTOKENW)GetFuncPatchedAddr(pAddr)))
            break;
        if (HotPatch(pAddr, MyCreateProcessA, NULL))
            break;

        success = TRUE;
    } while (0);

    if (!success)
    {
        UnHook();
    }

    if (success)
        WRITE_LOG_INFO("Hook success!");
    else
        WRITE_LOG_INFO("Hook failed!");

    return success;
}

static int UpdateSelfPath(HMODULE hModule)
{
    DWORD len = GetModuleFileNameA(hModule, gSelfPath, sizeof(gSelfPath));
 
    if (len == sizeof(gSelfPath) || len == 0)
        return -1;
    else
        return 0;
}

DLL_IMPORT int Inject(DWORD dwProcessId)
{
    int ret = -1;

    HANDLE hVictim = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);

    if (hVictim != NULL)
    {
        /* don't need to resume thread */
        ret = InjectSuspendedProcess(hVictim, INVALID_HANDLE_VALUE);
    }

    CloseHandle(hVictim);

    return ret;
}

static BOOL Attach(HINSTANCE hInst)
{
    BOOL ret = FALSE;

    if (UpdateSelfPath(hInst))
    {
        return FALSE;
    }

    OPEN_LOG_FILE(gSelfPath);

    ret = Hook();

    return ret;
}

BOOL APIENTRY DllMain(HINSTANCE hInst, DWORD dwReason, LPVOID lpReserved)
{
    switch(dwReason)
    {
        case DLL_PROCESS_ATTACH:
            /* if DLL is loaded by LoadLibrary */
            //if (!lpReserved)
            //{
                (void)Attach(hInst);
            //}
        default:
            break;
    }

    return TRUE;
}
