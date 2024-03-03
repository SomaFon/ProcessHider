#include "stdafx.h"
#include "MiniHook-Dll.h"
#include "Buffer.h"
#include "Trampoline.h"
#include "Thread.h"

volatile LONG __IsLocked = FALSE;
HANDLE   __HeapHandle = NULL;
HOOK_INFORMATION __Hooks;
NTSTATUS WINAPI SeInitialize(VOID)
{
	NTSTATUS Status = STATUS_SUCCESS;

	SeEnterSpinLock();
	
	if (__HeapHandle == NULL)
	{
		
		__HeapHandle = HeapCreate(0,
			0,    //�ύ PAGE_SIZE
			0);   //If dwMaximumSize is 0, the heap can grow in size.�Զ�����
		if (__HeapHandle != NULL)
		{
			//
			//����
			//
		}
		else
		{
			Status = STATUS_ERROR_MEMORY_ALLOCATE;
		}
	}
	else
	{
		Status = STATUS_ERROR_ALREADY_INITIALIZED;
	}

	SeLeaveSpinLock();

	return Status;
}
NTSTATUS WINAPI SeUninitialize(VOID)
{
	NTSTATUS Status = STATUS_SUCCESS;
	SeEnterSpinLock();

	if (__HeapHandle != NULL)
	{
		Status = SeDisableAllHooks(FALSE);
		if (Status == STATUS_SUCCESS)
		{
			SeUninitializeBuffer();

			HeapFree(__HeapHandle, 0, __Hooks.HookEntry);
			HeapDestroy(__HeapHandle);

			__HeapHandle = NULL;
			__Hooks.HookEntry = NULL;
			__Hooks.MaximumLength = 0;
			__Hooks.Length = 0;
		}
	}
	else
	{
		Status = STATUS_ERROR_NOT_INITIALIZED;
	}

	SeLeaveSpinLock();
	return Status;
}
//
NTSTATUS WINAPI SeCreateHook(LPVOID TargetFunctionAddress, LPVOID FakeFunctionAddress, LPVOID *OriginalFunctionAddress)
{
	NTSTATUS Status = STATUS_SUCCESS;

	SeEnterSpinLock();

	if (__HeapHandle != NULL)   //ʹ���Զ���Heap
	{
		//�ж�һ����ַ�Ƿ���ִ�д���
		if (SeIsExecutableAddress(TargetFunctionAddress) && SeIsExecutableAddress(FakeFunctionAddress))
		{
			
			
			UINT Item = SeFindHookEntry(TargetFunctionAddress);   //����Target�Ƿ��Ѿ��� Hook�������Hook�������������ڵ�λ��
			if (Item == STATUS_NOT_FOUND)
			{
				//����Hook
				//MemorySlot --��32�ֽ�
				LPVOID MemorySlot = SeAllocateBuffer(TargetFunctionAddress); //����һ���ڴ���������Trampoline 
				
				
				if (MemorySlot != NULL)
				{
					TRAMPOLINE Trampoline;
					Trampoline.TargetFunctionAddress = TargetFunctionAddress;    //Sub_1
					Trampoline.FakeFunctionAddress = FakeFunctionAddress;        //FakeSub_1
					Trampoline.MemorySlot = MemorySlot;      //MemorySlot
	
					if (SeCreateTrampoline(&Trampoline))
					{
						PHOOK_ENTRY HookEntry = SeAddHookEntry(); //���һ��HookInfo��Ϣ 
						if (HookEntry != NULL)
						{
							HookEntry->TargetFunctionAddress = Trampoline.TargetFunctionAddress;
#if defined(_M_X64) || defined(__x86_64__)
							HookEntry->FakeFunctionAddress = Trampoline.Relay;
#else
							HookEntry->FakeFunctionAddress = Trampoline.FakeFunctionAddress;
#endif
							HookEntry->MemorySlot = Trampoline.MemorySlot;
							HookEntry->PatchAbove = Trampoline.PatchAbove;
							HookEntry->IsEnabled   = FALSE;
						//	pHook->queueEnable = FALSE;
							HookEntry->Index = Trampoline.Index;
							memcpy(HookEntry->OldIPs, Trampoline.OldIPs, ARRAYSIZE(Trampoline.OldIPs));
							memcpy(HookEntry->NewIPs, Trampoline.NewIPs, ARRAYSIZE(Trampoline.NewIPs));

							// Back up the target function.

							if (Trampoline.PatchAbove)    //�Ȳ���  
							{
								//Asm_10 
								/*
								   db 90h
								   db 90h
								   db 90h
								   db 90h
								   db 90h

								   mov edi,edi
								*/

								memcpy(
									HookEntry->Backup,
									(LPBYTE)TargetFunctionAddress - sizeof(JMP_REL),
									sizeof(JMP_REL) + sizeof(JMP_REL_SHORT));
							}
							else
							{
								//�洢Դ��������������
								memcpy(HookEntry->Backup, TargetFunctionAddress, sizeof(JMP_REL));
							}
							
							if (OriginalFunctionAddress != NULL)
								*OriginalFunctionAddress = HookEntry->MemorySlot;
						}
						else
						{
							Status = STATUS_ERROR_MEMORY_ALLOCATE;
						}	
					}
					else
					{
						Status = STATUS_ERROR_UNSUPPORTED_FUNCTION;
					}
					if (Status != STATUS_SUCCESS)
					{
						SeFreeBuffer(MemorySlot);
					}
				}
				else
				{
					Status = STATUS_ERROR_MEMORY_ALLOCATE;
				}
			}
			else
			{
				Status = STATUS_ERROR_ALREADY_CREATED;
			}
		}
		else
		{
			Status = STATUS_ERROR_NOT_EXECUTABLE;
		}
	}
	else
	{
		Status = STATUS_ERROR_NOT_INITIALIZED;
	}
	SeLeaveSpinLock();
	return Status;
}
NTSTATUS WINAPI SeCreateHookApi(
	LPCWSTR ModuleImageName, LPCSTR FunctionName, LPVOID FakeFunctionAddress,
	LPVOID *Original, LPVOID *TargetFunctionAddress)
{
	HMODULE ModuleBase;
	LPVOID  v1;

	ModuleBase = GetModuleHandleW(ModuleImageName);
	if (ModuleBase == NULL)
		return STATUS_ERROR_MODULE_NOT_FOUND;

	v1 = (LPVOID)GetProcAddress(ModuleBase, FunctionName);
	if (v1 == NULL)
		return STATUS_ERROR_FUNCTION_NOT_FOUND;

	if (TargetFunctionAddress != NULL)
		*TargetFunctionAddress = v1;

	return SeCreateHook(v1, FakeFunctionAddress, Original);
}
NTSTATUS WINAPI SeEnableHook(LPVOID TargetFunctionAddress)
{
	NTSTATUS Status = STATUS_SUCCESS;

	SeEnterSpinLock();

	if (__HeapHandle != NULL)
	{
		if (TargetFunctionAddress == ALL_HOOKS)
		{
			Status = SeEnableAllHooks(TRUE);
		}
		else
		{
			THREAD_INFORMATION ThreadInfo;
			UINT Item = SeFindHookEntry(TargetFunctionAddress);
			if (Item != STATUS_NOT_FOUND)
			{
				if (__Hooks.HookEntry[Item].IsEnabled != TRUE)
				{
					//��������������߳�
					SeThreadFreeze(&ThreadInfo, Item, ACTION_ENABLE);

					Status = SeMiniHook_911(Item, TRUE);

					SeThreadUnfreeze(&ThreadInfo);
				}
				else
				{
					//���MinHook�Ѿ���ʼ������statusΪMH_ERROR_ENABLED������Ϊ
					Status = STATUS_ERROR_ENABLED;
				}
			}
			else
			{
				Status = STATUS_ERROR_NOT_CREATED;
			}
		}
	}
	else
	{
		Status = STATUS_ERROR_NOT_INITIALIZED;
	}

	SeLeaveSpinLock();

	return Status;
}
NTSTATUS WINAPI SeDisableHook(LPVOID TargetFunctionAddress)
{

	NTSTATUS Status = STATUS_SUCCESS;

	SeEnterSpinLock();

	if (__HeapHandle != NULL)
	{
		if (TargetFunctionAddress == ALL_HOOKS)
		{
			//дShellCode E9/EB   enable���Բ�Ϊ���HOOK����Ϊ  enable = true
			Status = SeDisableAllHooks(FALSE);
		}
		else
		{
			THREAD_INFORMATION ThreadInfo;
			UINT Item = SeFindHookEntry(TargetFunctionAddress);
			if (Item != STATUS_NOT_FOUND)
			{
				if (__Hooks.HookEntry[Item].IsEnabled != FALSE)
				{
					SeThreadFreeze(&ThreadInfo, Item, ACTION_DISABLE);


					Status = SeMiniHook_911(Item, FALSE);

					SeThreadUnfreeze(&ThreadInfo);
				}
				else
				{
					//���MinHook�Ѿ���ʼ������statusΪMH_ERROR_ENABLED������Ϊ
					Status = STATUS_ERROR_NOT_CREATED;
				}
			}
			else
			{
				Status = STATUS_ERROR_NOT_CREATED;
			}
		}
	}
	else
	{
		Status = STATUS_ERROR_NOT_INITIALIZED;
	}

	SeLeaveSpinLock();
	return STATUS_SUCCESS;
}
NTSTATUS SeEnableAllHooks(BOOL IsEnable)
{
	NTSTATUS Status = STATUS_SUCCESS;
	UINT i, First = STATUS_NOT_FOUND;

	for (i = 0; i < __Hooks.Length; ++i)
	{
		if (__Hooks.HookEntry[i].IsEnabled != IsEnable)
		{
			First = i;
			break;
		}
	}
	if (First != STATUS_NOT_FOUND)
	{
		THREAD_INFORMATION ThreadInfo;
		SeThreadFreeze(&ThreadInfo, ALL_HOOKS, IsEnable ? ACTION_ENABLE : ACTION_DISABLE);

		for (i = First; i < __Hooks.Length; ++i)
		{
			if (__Hooks.HookEntry[i].IsEnabled != IsEnable)
			{
				Status = SeMiniHook_911(i, IsEnable);
				if (Status != STATUS_SUCCESS)
					break;
			}
		}

		SeThreadUnfreeze(&ThreadInfo);
	}

	return Status;
}
NTSTATUS SeDisableAllHooks(BOOL IsEnable)
{
	NTSTATUS Status = STATUS_SUCCESS;
	UINT i, First = STATUS_NOT_FOUND;

	for (i = 0; i < __Hooks.Length; ++i)
	{
		if (__Hooks.HookEntry[i].IsEnabled != IsEnable)
		{
			First = i;
			break;
		}
	}
	if (First != STATUS_NOT_FOUND)
	{
		THREAD_INFORMATION ThreadInfo;
		SeThreadFreeze(&ThreadInfo, ALL_HOOKS, IsEnable ? ACTION_ENABLE : ACTION_DISABLE);

		for (i = First; i < __Hooks.Length; ++i)
		{
			if (__Hooks.HookEntry[i].IsEnabled != IsEnable)
			{
				Status = SeMiniHook_911(i, IsEnable);
				if (Status != STATUS_SUCCESS)
					break;
			}
		}

		SeThreadUnfreeze(&ThreadInfo);
	}

	return Status;
}
NTSTATUS WINAPI SeRemoveHook(LPVOID TargetFunctionAddress)
{
	NTSTATUS Status = STATUS_SUCCESS;

	SeEnterSpinLock();

	if (__HeapHandle != NULL)
	{
		UINT Item = SeFindHookEntry(TargetFunctionAddress);
		if (Item != STATUS_NOT_FOUND)
		{
			if (__Hooks.HookEntry[Item].IsEnabled)
			{
				THREAD_INFORMATION ThreadInfo;
				SeThreadFreeze(&ThreadInfo, Item, ACTION_DISABLE);

				Status = SeMiniHook_911(Item, FALSE);

				SeThreadUnfreeze(&ThreadInfo);
			}

			if (Status == STATUS_SUCCESS)
			{
				SeFreeBuffer(__Hooks.HookEntry[Item].MemorySlot);
				SeDeleteHookEntry(Item);
			}
		}
		else
		{
			Status = STATUS_ERROR_NOT_CREATED;
		}
	}
	else
	{
		Status = STATUS_ERROR_NOT_INITIALIZED;
	}

	SeLeaveSpinLock();

	return Status;
}
const char * WINAPI SeStatusToString(NTSTATUS Status)
{
#define MH_ST2STR(x)    \
    case x:             \
        return #x;

	switch (Status) {
		    MH_ST2STR(STATUS_UNSUCCESSFUL)
			MH_ST2STR(STATUS_SUCCESS)
			MH_ST2STR(STATUS_ERROR_ALREADY_INITIALIZED)
			MH_ST2STR(STATUS_ERROR_NOT_INITIALIZED)
			MH_ST2STR(STATUS_ERROR_ALREADY_CREATED)
			MH_ST2STR(STATUS_ERROR_NOT_CREATED)
			MH_ST2STR(STATUS_ERROR_ENABLED)
			MH_ST2STR(STATUS_ERROR_DISABLED)
			MH_ST2STR(STATUS_ERROR_NOT_EXECUTABLE)
			MH_ST2STR(STATUS_ERROR_UNSUPPORTED_FUNCTION)
			MH_ST2STR(STATUS_ERROR_MEMORY_ALLOCATE)
			MH_ST2STR(STATUS_ERROR_MEMORY_PROTECT)
			MH_ST2STR(STATUS_ERROR_MODULE_NOT_FOUND)
			MH_ST2STR(STATUS_ERROR_FUNCTION_NOT_FOUND)
	}

#undef MH_ST2STR

	return "(Unknown)";
}
/***********************************************************************
 
 * ���Ϻ�����Ϊ��̬�⵼������

***********************************************************************/
VOID SeLeaveSpinLock(VOID)
{
	InterlockedExchange(&__IsLocked, FALSE);
}
VOID SeEnterSpinLock(VOID)
{
    SIZE_T SpinCount = 0;

    // Wait until the flag is FALSE.
	/*
	LONG InterlockedCompareExchange(
									  _Inout_ LONG volatile *Destination ,
									  _In_    LONG          Exchange ,
									  _In_    LONG          Comparand
									);
��Ŀ�����������1������ָ����ڴ��е�������һ��ֵ����3�������Ƚϣ������ȣ�
������һ��ֵ����2��������Ŀ�����������1������ָ����ڴ��е�����������
����ֵ�� Destination ָ��ĳ�ʼֵ��

�������������������ڴ�ģ���������������ͬʱ�����ڴ棬�Ӷ�ʵ�ֶദ���������µ��̻߳���

*/

    while (InterlockedCompareExchange(&__IsLocked, TRUE, FALSE) != FALSE)
    {
        if (SpinCount < 32)
            Sleep(0);
        else
            Sleep(1);

        SpinCount++;
    }
}
UINT SeFindHookEntry(LPVOID FunctionAddress)
{
	UINT i;
	for (i = 0; i < __Hooks.Length; ++i)  //���Լ������ݽṹ�еĺ������бȽ�
	{
		if ((ULONG_PTR)FunctionAddress == (ULONG_PTR)__Hooks.HookEntry[i].TargetFunctionAddress)
			return i;
	}
	return STATUS_NOT_FOUND;
}
PHOOK_ENTRY SeAddHookEntry()
{
	if (__Hooks.HookEntry == NULL)
	{
		__Hooks.MaximumLength = INITIAL_HOOK_CAPACITY;
		__Hooks.HookEntry = (PHOOK_ENTRY)HeapAlloc(
			__HeapHandle, 0, __Hooks.MaximumLength * sizeof(HOOK_ENTRY));
		if (__Hooks.HookEntry == NULL)
			return NULL;
	}
	else if (__Hooks.Length >= __Hooks.MaximumLength)
	{
		PHOOK_ENTRY HookEntry = (PHOOK_ENTRY)HeapReAlloc(
			__HeapHandle, 0, __Hooks.HookEntry, (__Hooks.MaximumLength * 2) * sizeof(HOOK_ENTRY));
		if (HookEntry == NULL)
			return NULL;

		__Hooks.MaximumLength *= 2;
		__Hooks.HookEntry = HookEntry;
	}
	else
	{

	}

	return &__Hooks.HookEntry[__Hooks.Length++];
}
BOOL SeIsExecutableAddress(LPVOID VirtualAddress)
{

	BOOL IsOk = FALSE;
	MEMORY_BASIC_INFORMATION MemoryBasicInfo = { 0 };
	VirtualQuery(VirtualAddress, &MemoryBasicInfo, sizeof(MEMORY_BASIC_INFORMATION));
	if ((MemoryBasicInfo.State == MEM_COMMIT && (MemoryBasicInfo.Protect & PAGE_EXECUTE_FLAGS)))
	{
		IsOk = TRUE;
	}
	return IsOk;
}
NTSTATUS SeMiniHook_911(UINT Item, BOOL IsEnable)   
{
	PHOOK_ENTRY HookEntry = &__Hooks.HookEntry[Item];
	DWORD  OldProtect;
	SIZE_T PatchDataLength = sizeof(JMP_REL);
	LPBYTE PatchData = (LPBYTE)HookEntry->TargetFunctionAddress;
	if (HookEntry->PatchAbove)
	{
		PatchData -= sizeof(JMP_REL);
		PatchDataLength += sizeof(JMP_REL_SHORT);
	}
	if (!VirtualProtect(PatchData, PatchDataLength, PAGE_EXECUTE_READWRITE, &OldProtect))
		return STATUS_ERROR_MEMORY_PROTECT;
	if (IsEnable)  //Hook
	{
		//SHELLCODE
		PJMP_REL jmp = (PJMP_REL)PatchData;
		jmp->Opcode = 0xE9;
		jmp->Operand = (UINT32)((LPBYTE)HookEntry->FakeFunctionAddress - (PatchData + sizeof(JMP_REL)));

		//   
		if (HookEntry->PatchAbove)
		{
			PJMP_REL_SHORT jmpshort = (PJMP_REL_SHORT)HookEntry->TargetFunctionAddress;
			jmpshort->opcode = 0xEB;
			jmpshort->operand = (UINT8)(0 - (sizeof(JMP_REL_SHORT) + sizeof(JMP_REL)));

			//��ǰλ���������׵�ַ��ת
			/*
			
			Asm_10  PROC
			008A1F7A E9 A3 F1 FF FF       jmp         FakeSub_10 (08A1122h)
			008A1F7F EB F9                jmp         Asm_10 (08A1F7Ah)
			C3	
			*/



			//
			//V1 = TargetFunctionAddress;  CC CC CC CC CC MOV EDI,EDI C3



		}
	}
	else       //Unhook
	{
		if (HookEntry->PatchAbove) 
		{
			//0x90 0x90 0x90 0x90 0x90 mov edi,edi
			memcpy(PatchData, HookEntry->Backup, sizeof(JMP_REL) + sizeof(JMP_REL_SHORT));
		}
	
		else
		{
			memcpy(PatchData, HookEntry->Backup, sizeof(JMP_REL));
		}
			
	}
	VirtualProtect(PatchData, PatchDataLength, OldProtect, &OldProtect);
	// Just-in-case measure.
	FlushInstructionCache(GetCurrentProcess(), PatchData, PatchDataLength);

	HookEntry->IsEnabled = IsEnable;
//	HookEntry->queueEnable = enable;

	return STATUS_SUCCESS;
}
void SeDeleteHookEntry(UINT Item)
{
	if (Item < __Hooks.Length - 1)
		__Hooks.HookEntry[Item] = __Hooks.HookEntry[__Hooks.Length - 1];

	__Hooks.Length--;

	if (__Hooks.MaximumLength / 2 >= INITIAL_HOOK_CAPACITY && __Hooks.MaximumLength / 2 >= __Hooks.Length)
	{
		PHOOK_ENTRY HookEntry = (PHOOK_ENTRY)HeapReAlloc(
			__HeapHandle, 0, __Hooks.HookEntry, (__Hooks.MaximumLength / 2) * sizeof(HOOK_ENTRY));
		if (HookEntry == NULL)
			return;

		__Hooks.MaximumLength /= 2;
		__Hooks.HookEntry = HookEntry;
	}
}



