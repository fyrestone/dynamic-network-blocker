#ifndef BIG_DADDY_H
#define BIG_DADDY_H

#include <WinDef.h>

#if BUILDING_DLL
    #define DLL_IMPORT __declspec (dllexport)
#else
    #define DLL_IMPORT __declspec (dllimport)
#endif

#ifdef __cplusplus
    extern "C" 
    {
#endif

DLL_IMPORT int Inject(DWORD dwProcessId);

#ifdef __cplusplus
    }
#endif

#endif
