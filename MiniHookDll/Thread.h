#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include "MiniHook-Dll.h"
#include "Trampoline.h"
#define INITIAL_THREAD_CAPACITY 128
typedef struct _THREAD_INFORMATION_
{
	DWORD*      ThreadEntry;    //所有线程ID
	UINT        MaximumLength;
	UINT        Length;
}THREAD_INFORMATION, *PTHREAD_INFORMATION;

VOID SeThreadFreeze(PTHREAD_INFORMATION ThreadInfo, UINT Item, UINT Action);
VOID SeThreadUnfreeze(PTHREAD_INFORMATION ThreadInfo);
void SeProcessThreadIPs(HANDLE ThreadHandle, UINT Item, UINT Action);
DWORD_PTR SeFindOldIP(PHOOK_ENTRY HookEntry, DWORD_PTR Ip);
DWORD_PTR SeFindNewIP(PHOOK_ENTRY HookEntry, DWORD_PTR Ip);