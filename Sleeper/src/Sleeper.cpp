#define _WIN32_WINNT 0x06000000 // For Mingw

#include <windows.h>

extern "C" {
    #include "beacon.h"
}

#define BOF_REDECLARE(mod, func) extern "C" __declspec(dllimport) decltype(func) mod ## $ ## func 
#define BOF_LOCAL(mod, func) decltype(func) * func = mod ## $ ## func

BOF_REDECLARE(KERNEL32, SetThreadExecutionState);

extern "C" void go(char* args, int alen) {
    BOF_LOCAL(KERNEL32, SetThreadExecutionState);
    
    int res;
    datap  parser;
    int command;

    BeaconDataParse(&parser, args, alen);
    command = BeaconDataInt(&parser) | ES_CONTINUOUS;

    res = SetThreadExecutionState( command );
    BeaconPrintf(CALLBACK_OUTPUT, "Set the SetThreadExecutionState to 0x%x (previous setting was 0x%x)\n", command, res);
}