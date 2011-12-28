#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Advapi32.lib")

#define BUILDING_DLL 1

#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include <winsock2.h>
#include <WS2tcpip.h>               ///< Be sure to link to ws2_32.lib.
#include <NTSecAPI.h>               ///< Be sure to link to Advapi32.lib.
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

static PSEND        gOrigSend       = NULL;
static PWSASEND     gOrigWSASend    = NULL;
static PWSASENDTO   gOrigWSASendTo  = NULL;

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
        // Get Kernel32.dll->LoadLibraryA address.
        LPTHREAD_START_ROUTINE lpfLoadLibraryA = 
            (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA");

        if (lpfLoadLibraryA == NULL)
            break;

        // Malloc a space in hVictim to store DLL name.
        pNameAddress = VirtualAllocEx(
            hProcess, 
            NULL, 
            strlen(gSelfPath) + 1, 
            MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);

        if (pNameAddress == NULL)
            break;

        // Write DLL name to pNameAddress.
        if(!WriteProcessMemory(hProcess, pNameAddress, gSelfPath, strlen(gSelfPath) + 1, NULL))
            break;

        // Create a remote thread to load this dll.
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

        // Wait for load complete.
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
#ifdef _DEBUG
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
#else
    return SOCKET_ERROR;
#endif
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
#ifdef _DEBUG
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
#else
    return SOCKET_ERROR;
#endif
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
#ifdef _DEBUG
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
#else
    return SOCKET_ERROR;
#endif
}

static BOOL WINAPI __stdcall MyCreateProcessW(
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
        const BOOL bNeedResume = !(dwCreationFlags & CREATE_SUSPENDED);

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
            const HANDLE hResumeThread = bNeedResume ? lpProcessInformation->hThread : NULL;

            if (InjectSuspendedProcess(
                lpProcessInformation->hProcess, 
                hResumeThread))
            {
                WRITE_LOG_INFO("InjectSuspendedProcess failed, resume thread id = 0x%0X.", hResumeThread);
            }
            else
            {
                WRITE_LOG_INFO("InjectSuspendedProcess success!");
            }
        }
    }

    return ret;
}

static BOOL WINAPI __stdcall MyCreateProcessA(
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
        const BOOL bNeedResume = !(dwCreationFlags & CREATE_SUSPENDED);

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
            const HANDLE hResumeThread = bNeedResume ? lpProcessInformation->hThread : NULL;

            if (InjectSuspendedProcess(
                lpProcessInformation->hProcess, 
                hResumeThread))
            {
                WRITE_LOG_INFO("InjectSuspendedProcess failed, resume thread id = 0x%0X.", hResumeThread);
            }
            else
            {
                WRITE_LOG_INFO("InjectSuspendedProcess success!");
            }
        }
    }

    return ret;
}

static BOOL WINAPI __stdcall MyCreateProcessAsUserW(
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
        const BOOL bNeedResume = !(dwCreationFlags & CREATE_SUSPENDED);

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
            const HANDLE hResumeThread = bNeedResume ? lpProcessInformation->hThread : NULL;

            if (InjectSuspendedProcess(
                lpProcessInformation->hProcess, 
                hResumeThread))
            {
                WRITE_LOG_INFO("InjectSuspendedProcess failed, resume thread id = 0x%0X.", hResumeThread);
            }
            else
            {
                WRITE_LOG_INFO("InjectSuspendedProcess success!");
            }
        }
    }

    return ret;
}

static BOOL WINAPI __stdcall MyCreateProcessAsUserA(
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
        const BOOL bNeedResume = !(dwCreationFlags & CREATE_SUSPENDED);

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
            const HANDLE hResumeThread = bNeedResume ? lpProcessInformation->hThread : NULL;

            if (InjectSuspendedProcess(
                lpProcessInformation->hProcess, 
                hResumeThread))
            {
                WRITE_LOG_INFO("InjectSuspendedProcess failed, resume thread id = 0x%0X.", hResumeThread);
            }
            else
            {
                WRITE_LOG_INFO("InjectSuspendedProcess success!");
            }
        }
    }

    return ret;
}

static BOOL WINAPI __stdcall MyCreateProcessWithLogonW(
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
        const BOOL bNeedResume = !(dwCreationFlags & CREATE_SUSPENDED);

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
            const HANDLE hResumeThread = bNeedResume ? lpProcessInfo->hThread : NULL;

            if (InjectSuspendedProcess(
                lpProcessInfo->hProcess, 
                hResumeThread))
            {
                WRITE_LOG_INFO("InjectSuspendedProcess failed, resume thread id = 0x%0X.", hResumeThread);
            }
            else
            {
                WRITE_LOG_INFO("InjectSuspendedProcess success!");
            }
        }
    }

    return ret;
}

static BOOL WINAPI __stdcall MyCreateProcessWithTokenW(
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
        const BOOL bNeedResume = !(dwCreationFlags & CREATE_SUSPENDED);

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
            const HANDLE hResumeThread = bNeedResume ? lpProcessInfo->hThread : NULL;

            if (InjectSuspendedProcess(
                lpProcessInfo->hProcess, 
                hResumeThread))
            {
                WRITE_LOG_INFO("InjectSuspendedProcess failed, resume thread id = 0x%0X.", hResumeThread);
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
    const DWORD *pLongJumpAddr = ((const DWORD *)pProc - 1);    // offset: -4, len: DWORD
    const WORD *pJumpBack = (const WORD *)pProc;                // offset: 0, len: WORD

    if (0xFF8B == *pJumpBack &&                                 // instruction: mov edi, edi
        ((0x90 == *pLongJump && 0x90909090 == *pLongJumpAddr) ||// unpatched value (5 nop)
        0xE9 == *pLongJump))                                    // patched value (long jump + target addr)
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
    DWORD *pLongJumpAddr = ((DWORD *)pOldProc - 1);             // offset: -4, len: DWORD
    WORD *pJumpBack = (WORD *)pOldProc;                         // offset: 0, len: WORD

    if (!VirtualProtect(pLongJump, 7, PAGE_EXECUTE_WRITECOPY, &dwOldProtect))
    {
        return -1;
    }

    if (0xFF8B == *pJumpBack &&                                 // instruction: mov edi, edi
        ((0x90 == *pLongJump && 0x90909090 == *pLongJumpAddr) ||// unpatched value (5 nop)
        0xE9 == *pLongJump))                                    // patched value (long jump + target addr)
    {
        *pLongJump = 0xE9;                                      // long jmp    
        *pLongJumpAddr = ((DWORD)pNewProc) - ((DWORD)pOldProc); // pNewProc offset
        *pJumpBack = 0xF9EB;                                    // short jump back 7(back 5, plus 2 for this jump)

        if (ppOrigFn)
        {
            *ppOrigFn = ((BYTE *)pOldProc) + 2;
        }

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

    WORD *pJumpBack = (WORD *)pOldProc;                         // offset: 0, len: WORD

    if (!VirtualProtect(pJumpBack, 2, PAGE_EXECUTE_WRITECOPY, &dwOldProtect))
    {
        return -1;
    }

    if (0xF9EB == *pJumpBack)
    {
        *pJumpBack = 0xFF8B;

        ret = 0;
    }

    if (!VirtualProtect(pJumpBack, 2, dwOldProtect, &dwOldProtect))
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

        if (!(pAddr = GetProcAddress(GetModuleHandleA("Ws2_32.dll"), "WSASend")))
            break;
        if (HotUnpatch(pAddr))
            break;

        if (!(pAddr = GetProcAddress(GetModuleHandleA("Ws2_32.dll"), "WSASendTo")))
            break;
        if (HotUnpatch(pAddr))
            break;

        if (!(pAddr = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "CreateProcessW")))
            break;
        if (HotUnpatch(pAddr))
            break;

        if (!(pAddr = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "CreateProcessA")))
            break;
        if (HotUnpatch(pAddr))
            break;

        if (!(pAddr = GetProcAddress(GetModuleHandleA("Advapi32.dll"), "CreateProcessAsUserW")))
            break;
        if (HotUnpatch(pAddr))
            break;

        if (!(pAddr = GetProcAddress(GetModuleHandleA("Advapi32.dll"), "CreateProcessAsUserA")))
            break;
        if (HotUnpatch(pAddr))
            break;

        if (!(pAddr = GetProcAddress(GetModuleHandleA("Advapi32.dll"), "CreateProcessWithLogonW")))
            break;
        if (HotUnpatch(pAddr))
            break;

        if (!(pAddr = GetProcAddress(GetModuleHandleA("Advapi32.dll"), "CreateProcessWithTokenW")))
            break;
        if (HotUnpatch(pAddr))
            break;

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
        if (HotPatch(pAddr, MyCreateProcessAsUserW, NULL))
            break;

        if (!(pAddr = GetProcAddress(GetModuleHandleA("Advapi32.dll"), "CreateProcessAsUserA")))
            break;
        if (!(gOrigCreateProcessAsUserA = (PCREATEPROCESSASUSERA)GetFuncPatchedAddr(pAddr)))
            break;
        if (HotPatch(pAddr, MyCreateProcessAsUserA, NULL))
            break;

        if (!(pAddr = GetProcAddress(GetModuleHandleA("Advapi32.dll"), "CreateProcessWithLogonW")))
            break;
        if (!(gOrigCreateProcessWithLogonW = (PCREATEPROCESSWITHLOGONW)GetFuncPatchedAddr(pAddr)))
            break;
        if (HotPatch(pAddr, MyCreateProcessWithLogonW, NULL))
            break;

        if (!(pAddr = GetProcAddress(GetModuleHandleA("Advapi32.dll"), "CreateProcessWithTokenW")))
            break;
        if (!(gOrigCreateProcessWithTokenW = (PCREATEPROCESSWITHTOKENW)GetFuncPatchedAddr(pAddr)))
            break;
        if (HotPatch(pAddr, MyCreateProcessWithTokenW, NULL))
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
    // gSelfPath will be this dll's full path including terminating null character.
    DWORD len = GetModuleFileNameA(hModule, gSelfPath, sizeof(gSelfPath));

    if (len == sizeof(gSelfPath) /* overflow */|| len == 0 /* error */)
        return -1;
    else
        return 0;
}

DLL_IMPORT BOOL LaunchW(const wchar_t *pszTargetFullPath, wchar_t *pszTargetCmd)
{
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));

    si.cb = sizeof(si);

    return CreateProcessW(pszTargetFullPath,
        pszTargetCmd,
        NULL,
        NULL,
        FALSE,
        0,
        NULL,
        NULL,
        &si,
        &pi);
}

DLL_IMPORT BOOL LaunchA(const char *pszTargetFullPath, char *pszTargetCmd)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));

    si.cb = sizeof(si);

    return CreateProcessA(pszTargetFullPath,
        pszTargetCmd,
        NULL,
        NULL,
        FALSE,
        0,
        NULL,
        NULL,
        &si,
        &pi);
}

DLL_IMPORT int Inject(DWORD dwProcessId)
{
    int ret = -1;

    HANDLE hVictim = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);

    if (hVictim != NULL)
    {
        // Don't need to resume thread.
        ret = InjectSuspendedProcess(hVictim, INVALID_HANDLE_VALUE);
    }

    CloseHandle(hVictim);

    return ret;
}

static BOOL Attach(HINSTANCE hInst)
{
    BOOL ret = FALSE;

    // Be sure to link to ws2_32.lib.
    freeaddrinfo(NULL);

    // Be sure to link to Advapi32.lib.
    AuditFree(NULL);

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
        (void)Attach(hInst);
    default:
        break;
    }

    return TRUE;
}
