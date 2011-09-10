#pragma comment(lib, "psapi.lib")

#include "stdafx.h"
#include "ColorPrint.h"
#include "DynamicNetworkBlocker.h"

using namespace std;

struct AlphabetSorter
{
    bool operator() (const PROCESSENTRY32 &lhs, const PROCESSENTRY32 &rhs) const
    {
        return lexicographical_compare(
            lhs.szExeFile, lhs.szExeFile + strlen(lhs.szExeFile),
            rhs.szExeFile, rhs.szExeFile + strlen(rhs.szExeFile), compare);
    }

private:
    static bool compare(char lhs, char rhs)
    {
        return tolower(lhs) < tolower(rhs);
    }
};

bool PrintProcessList()
{
    bool success = false;

    HANDLE hProcessSnap = INVALID_HANDLE_VALUE;

    do 
    {
        vector<PROCESSENTRY32> list;

        hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if (hProcessSnap == INVALID_HANDLE_VALUE)
            break;

        PROCESSENTRY32 pe32;

        /* set the size of the structure before using it */
        pe32.dwSize = sizeof(PROCESSENTRY32);

        /* retrieve information about the first process */
        if(!Process32First(hProcessSnap, &pe32))
            break;

        /* now walk the snapshot of processes */
        do 
        {
            list.push_back(pe32);
        } while (Process32Next(hProcessSnap, &pe32));

        sort(list.begin(), list.end(), AlphabetSorter());

        ColorPrintf(WHITE, "%10s", "PID");
        ColorPrintf(WHITE, "\t%s\n", "ProcessName");

        for (vector<PROCESSENTRY32>::const_iterator itPE32 = list.begin();
            itPE32 != list.end();
            ++itPE32)
        {
            ColorPrintf(AQUA, "%10d", itPE32->th32ProcessID);
            ColorPrintf(YELLOW, "\t%s\n", itPE32->szExeFile);
        }

        success = true;
    } while (0);

    CloseHandle(hProcessSnap);

    return success;
}

int main(int argc, char *argv[])
{
    if (PrintProcessList())
    {
        DWORD dwProcessId;
        
        cin >> dwProcessId;
        Inject(dwProcessId);
    }

    _getch();

    return 0;
}


