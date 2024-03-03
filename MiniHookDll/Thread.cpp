#include"stdafx.h"
#include "Thread.h"

extern
HANDLE __HeapHandle;
extern
HOOK_INFORMATION __Hooks;
VOID SeScanEnumerateThreads(PTHREAD_INFORMATION ThreadInfo)
{
	HANDLE SnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (SnapshotHandle != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 ThreadEntry32;
		ThreadEntry32.dwSize = sizeof(THREADENTRY32);
		if (Thread32First(SnapshotHandle, &ThreadEntry32))
		{
			do
			{
				if (ThreadEntry32.dwSize >= (FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(DWORD))
					&& ThreadEntry32.th32OwnerProcessID == GetCurrentProcessId()
					&& ThreadEntry32.th32ThreadID != GetCurrentThreadId())
				{
					if (ThreadInfo->ThreadEntry == NULL)
					{
						ThreadInfo->MaximumLength = INITIAL_THREAD_CAPACITY;
						ThreadInfo->ThreadEntry
							= (LPDWORD)HeapAlloc(__HeapHandle, 0, ThreadInfo->MaximumLength * sizeof(DWORD));
						if (ThreadInfo->ThreadEntry == NULL)
							break;
					}
					else if (ThreadInfo->Length >= ThreadInfo->MaximumLength)
					{
						LPDWORD v1 = (LPDWORD)HeapReAlloc(
							__HeapHandle, 0, ThreadInfo->ThreadEntry, (ThreadInfo->MaximumLength * 2) * sizeof(DWORD));
						if (v1 == NULL)
							break;

						ThreadInfo->MaximumLength *= 2;
						ThreadInfo->ThreadEntry = v1;
					}
					else
					{

					}
					ThreadInfo->ThreadEntry[ThreadInfo->Length++] = ThreadEntry32.th32ThreadID;
				}

				ThreadEntry32.dwSize = sizeof(THREADENTRY32);
			} while (Thread32Next(SnapshotHandle, &ThreadEntry32));
		}
		CloseHandle(SnapshotHandle);
	}
}
VOID SeThreadFreeze(PTHREAD_INFORMATION ThreadInfo, UINT Item, UINT Action)
{
	ThreadInfo->ThreadEntry = NULL;
	ThreadInfo->MaximumLength = 0;
	ThreadInfo->Length = 0;
	SeScanEnumerateThreads(ThreadInfo);

	if (ThreadInfo->ThreadEntry != NULL)
	{
		UINT i;
		for (i = 0; i < ThreadInfo->Length; ++i)
		{
			HANDLE ThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, ThreadInfo->ThreadEntry[i]);
			if (ThreadHandle != NULL)
			{
				SuspendThread(ThreadHandle);
				SeProcessThreadIPs(ThreadHandle, Item, Action);
				CloseHandle(ThreadHandle);
			}
		}
	}
}

//-------------------------------------------------------------------------
VOID Unfreeze(PTHREAD_INFORMATION ThreadInfo)
{
/*	if (pThreads->pItems != NULL)
	{
		UINT i;
		for (i = 0; i < pThreads->size; ++i)
		{
			HANDLE hThread = OpenThread(THREAD_ACCESS, FALSE, pThreads->pItems[i]);
			if (hThread != NULL)
			{
				ResumeThread(hThread);
				CloseHandle(hThread);
			}
		}

		HeapFree(g_hHeap, 0, pThreads->pItems);
	}*/
}


void SeProcessThreadIPs(HANDLE ThreadHandle, UINT Item, UINT Action)
{
	// If the thread suspended in the overwritten area,
	// move IP to the proper address.

	CONTEXT Context;
#if defined(_M_X64) || defined(__x86_64__)
	DWORD64 *Ip = &Context.Rip;
#else

	//把指令指针寄存器的地址赋过来
	DWORD   *Ip = &Context.Eip;
#endif
	UINT ItemCount;

	Context.ContextFlags = CONTEXT_CONTROL;
	if (!GetThreadContext(ThreadHandle, &Context))
		return;
	//如果针对全部hook 那我们的pos从0开始
	if (Item == ALL_HOOKS)  //
	{
		Item = 0;
		ItemCount = __Hooks.Length;
	}
	//如果并不是针对全部 那我们把count置为pos+1（因为后面有循环 也就是为了只循环一次）
	else
	{
		ItemCount = Item + 1;
	}

	for (; Item < ItemCount; ++Item)
	{
		PHOOK_ENTRY HookEntry = &__Hooks.HookEntry[Item];
		BOOL        IsEnable;
		DWORD_PTR   v1;

		switch (Action)
		{
		case ACTION_DISABLE:
			IsEnable = FALSE;
			break;

		case ACTION_ENABLE:
			IsEnable = TRUE;
			break;

		default: // ACTION_APPLY_QUEUED
			//enable = pHook->queueEnable;
			break;
		}
		//如果我们想要的操作和当前hook的可用状态相符 那我们就继续循环
		if (HookEntry->IsEnabled == IsEnable)
			continue;
		//这两条指令是说我们可能正在执行目标函数 而目标函数可能被改了也可能没改 我们要根据我们想要的操作对其线程背景文进行修改
		if (IsEnable)
			v1 = SeFindNewIP(HookEntry, *Ip);  //Hook
		else
			v1 = SeFindOldIP(HookEntry, *Ip);  //UnHook
		//如果ip（指令指针）的值不为0 我们把指令地址给（解一次星号）之前保存寄存器地址的变量 （就是说变量里面保存的地址 我们把地址放到了变量保存的地址里面）
		if (v1 != 0)
		{
			*Ip = v1;
			//把背景文设回去 指令指针不一样了
			SetThreadContext(ThreadHandle, &Context);
		}
	}
}


DWORD_PTR SeFindNewIP(PHOOK_ENTRY HookEntry, DWORD_PTR Ip)  
{
	UINT i;
	for (i = 0; i < HookEntry->Index; ++i)
	{
		if (Ip == ((DWORD_PTR)HookEntry->TargetFunctionAddress + HookEntry->OldIPs[i]))
			return (DWORD_PTR)HookEntry->MemorySlot + HookEntry->NewIPs[i];
	}

	return 0;
}
DWORD_PTR SeFindOldIP(PHOOK_ENTRY HookEntry, DWORD_PTR Ip)
{
	UINT i;
	//如果我们用了热补丁并且指令地址等于目标函数地址往上挪五个字节（就是函数上面我们打补丁的地方） 就返回目标函数地址
	if (HookEntry->PatchAbove && Ip == ((DWORD_PTR)HookEntry->TargetFunctionAddress - sizeof(JMP_REL)))
		return (DWORD_PTR)HookEntry->TargetFunctionAddress;


	//否则就看指令地址是否和跳板函数指令地址相等
	for (i = 0; i < HookEntry->Index; ++i)
	{
		if (Ip == ((DWORD_PTR)HookEntry->MemorySlot + HookEntry->NewIPs[i]))
			return (DWORD_PTR)HookEntry->TargetFunctionAddress + HookEntry->OldIPs[i];
	}

#if defined(_M_X64) || defined(__x86_64__)
	// Check relay function.
//	if (ip == (DWORD_PTR)pHook->pDetour)
//		return (DWORD_PTR)pHook->pTarget;
#endif

	return 0;
}

VOID SeThreadUnfreeze(PTHREAD_INFORMATION ThreadInfo)
{
	if (ThreadInfo->ThreadEntry != NULL)
	{
		UINT i;
		for (i = 0; i < ThreadInfo->Length; ++i)
		{
			HANDLE ThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, ThreadInfo->ThreadEntry[i]);
			if (ThreadHandle != NULL)
			{
				ResumeThread(ThreadHandle);
				CloseHandle(ThreadHandle);
			}
		}

		HeapFree(__HeapHandle, 0, ThreadInfo->ThreadEntry);
	}
}