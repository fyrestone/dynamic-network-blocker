// Launcher.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "DynamicNetworkBlocker.h"


int APIENTRY wWinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPWSTR    lpCmdLine,
                     int       nCmdShow)
{
    LPWSTR *argv;
    int argc;

    argv = CommandLineToArgvW(GetCommandLineW(), &argc);

    if ((argc == 2/* without cmd */ || argc == 3/* with cmd */) && argv != NULL)
    {
        LaunchW(argv[1], argv[2]);
    }

    LocalFree(argv);

    return 0;
}

