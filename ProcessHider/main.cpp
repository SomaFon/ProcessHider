// Test.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include<tchar.h>
#include <Windows.h>
#include <TlHelp32.h>
#include<iostream>
using namespace std;


int _tmain(int argc, TCHAR* argv[])
{
	// ����DLL����ȡ���
	HMODULE hDll = ::LoadLibrary("MiniHookDll.dll");
	if (NULL == hDll)
	{
		_tprintf("%s error[%d]\n", "LoadLibrary", ::GetLastError());
	}
	_tprintf("Load Library OK.\n");

	// ����ȫ�ֹ���
	typedef HHOOK(*typedef_SetHook)();
	typedef_SetHook SetHook = (typedef_SetHook)::GetProcAddress(hDll, "SetHook");
	if (NULL == SetHook)
	{
		printf("GetProcAddress Error[%d]\n", ::GetLastError());
	}
	HHOOK hHook = SetHook();
	if (NULL == hHook)
	{
		printf("%s error[%d]\n", "SetWindowsHookEx", ::GetLastError());
	}
	printf("Set Windows Hook OK.\n");
	system("pause");
	// ж��ȫ�ֹ���
	typedef BOOL(*typedef_UnsetHook)(HHOOK);
	typedef_UnsetHook UnsetHook = (typedef_UnsetHook)::GetProcAddress(hDll, "UnsetHook");
	if (NULL == UnsetHook)
	{
		printf("GetProcAddress Error[%d]\n", ::GetLastError());
	}
	if (FALSE == UnsetHook(hHook))
	{
		printf("%s error[%d]\n", "UnhookWindowsHookE", ::GetLastError());
	}
	printf("Unhook Windows Hook OK.\n");
	// ж��DLL
	::FreeLibrary(hDll);

	system("pause");
	return 0;
}

