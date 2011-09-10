#ifndef LOG_FILE
#define LOG_FILE

#include <stdio.h>
#include <Windows.h>

#ifndef _DEBUG
    #define WRITE_LOG_INFO(info)
    #define OPEN_LOG_FILE(self)
#else
    #pragma comment(lib, "psapi.lib")
 
    #include <Psapi.h>

    static HANDLE hMutex = NULL;
    static HANDLE hLogFile = INVALID_HANDLE_VALUE;

    static void _GetLogFileHandle(const char *pSelfPath)
    {   
        char buffer[MAX_PATH];

        if (strlen(pSelfPath) != 0 && strcpy_s(buffer, MAX_PATH, pSelfPath) == 0)
        {
            char *end = buffer + strlen(buffer);

            while (end != buffer)
            {
                /* cut to the last '\' */
                if (*--end == '\\')
                {
                    *++end = '\0';
                    break;
                }
            }

            if (end != buffer && strcat_s(buffer, MAX_PATH, "log.txt") == 0)
            {
                hLogFile = CreateFileA(
                    buffer, 
                    FILE_APPEND_DATA,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL,
                    OPEN_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
                    NULL);
            }
        }
    }

    static void _WriteLogInfo(const char *info)
    {
        char buffer[1024];

        if (hMutex == NULL)                     
        {                                       
            hMutex = CreateMutexA(              
                NULL,                           
                FALSE,                          
                "__BIG_DADDY_LOG_MUTEX__");     
        }                 

        if (hMutex != NULL &&                   
            WaitForSingleObject(hMutex, INFINITE) == WAIT_OBJECT_0 && 
            hLogFile != INVALID_HANDLE_VALUE)   
        {                     
            DWORD dwBytesWritten = 0;  
            DWORD dwPid = GetCurrentProcessId();
            HANDLE hProcess = INVALID_HANDLE_VALUE;
            char name[20] = {0};

            hProcess = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE,
                dwPid);

            GetModuleBaseNameA(
                hProcess,
                NULL,
                name,
                sizeof(name));

            (void)sprintf_s(
                buffer, 
                sizeof(buffer), 
                "%6d->%-20s %s\r\n", 
                dwPid, 
                name,
                info);

            (void)WriteFile(                    
                hLogFile,                       
                buffer,                         
                (DWORD)strlen(buffer),
                &dwBytesWritten,                
                NULL); 
        }                                       

        (void)ReleaseMutex(hMutex);
    }

    #define WRITE_LOG_INFO(info)                    \
        _WriteLogInfo(info)


    #define OPEN_LOG_FILE(self)                     \
        _GetLogFileHandle(self)

#endif
#endif