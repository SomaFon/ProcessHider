#pragma once
#include <windows.h>
#include <Winternl.h>    
#include <ntstatus.h>

typedef enum
{
	STATUS_ERROR_UNKNOWN = -1,
	STATUS_ERROR_SUCCESS = 0,
	STATUS_ERROR_ALREADY_INITIALIZED,
	STATUS_ERROR_NOT_INITIALIZED,
	STATUS_ERROR_ALREADY_CREATED,
	STATUS_ERROR_NOT_CREATED,
	STATUS_ERROR_ENABLED,
	STATUS_ERROR_DISABLED,
	STATUS_ERROR_NOT_EXECUTABLE,
	STATUS_ERROR_UNSUPPORTED_FUNCTION,
	STATUS_ERROR_MEMORY_ALLOCATE,
	STATUS_ERROR_MEMORY_PROTECT,
	STATUS_ERROR_MODULE_NOT_FOUND,
	STATUS_ERROR_FUNCTION_NOT_FOUND
};

#define PAGE_EXECUTE_FLAGS \
    (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

#define  ALL_HOOKS    NULL
#define  INITIAL_HOOK_CAPACITY 32
#define  ACTION_DISABLE      0
#define  ACTION_ENABLE       1


// Hook information.
typedef struct _HOOK_ENTRY
{
	LPVOID TargetFunctionAddress;        
	LPVOID FakeFunctionAddress;           
	LPVOID MemorySlot;        
	UINT8  Backup[8];           //恢复Hook使用的存放原先数据

	UINT8  PatchAbove : 1;     // Uses the hot patch area.   位域：1位
	UINT8  IsEnabled  : 1;     // Enabled.
//	UINT8  queueEnable : 1;     // Queued for enabling/disabling when != isEnabled.

	UINT   Index : 4;            // Count of the instruction boundaries.?？?
	UINT8  OldIPs[8];           // Instruction boundaries of the target function.???
	UINT8  NewIPs[8];           // Instruction boundaries of the trampoline function ???
} HOOK_ENTRY, *PHOOK_ENTRY;     //44字节


typedef struct _HOOK_INFORMATION_
{
	PHOOK_ENTRY HookEntry;         
	UINT        MaximumLength;    
	UINT        Length;          
}HOOK_INFORMATION,*PHOOK_INFORMATION;


_declspec(dllexport)
NTSTATUS WINAPI SeInitialize(VOID);
_declspec(dllexport)
NTSTATUS WINAPI SeUninitialize(VOID);
_declspec(dllexport)
NTSTATUS WINAPI SeCreateHook(LPVOID TargetFunctionAddress, LPVOID FakeFunctionAddress, LPVOID *OriginalFunctionAddress);
_declspec(dllexport)
NTSTATUS WINAPI SeCreateHookApi(
	LPCWSTR ModuleImageName, LPCSTR FunctionName, LPVOID FakeFunctionAddress,
	LPVOID *Original, OPTIONAL LPVOID *TargetFunctionAddress = NULL);
_declspec(dllexport)
NTSTATUS WINAPI SeEnableHook(LPVOID TargetFunctionAddress);
_declspec(dllexport)
NTSTATUS WINAPI SeDisableHook(LPVOID TargetFunctionAddress);
_declspec(dllexport)
NTSTATUS WINAPI SeRemoveHook(LPVOID TargetFunctionAddress);
_declspec(dllexport)
const char * WINAPI SeStatusToString(NTSTATUS Status);





VOID SeEnterSpinLock(VOID);
VOID SeLeaveSpinLock(VOID);
BOOL SeIsExecutableAddress(LPVOID VirtualAddress);
UINT SeFindHookEntry(LPVOID FunctionAddress);
PHOOK_ENTRY SeAddHookEntry();
NTSTATUS SeMiniHook_911(UINT Item, BOOL IsEnable);
NTSTATUS SeEnableAllHooks(BOOL IsEnable);
NTSTATUS SeDisableAllHooks(BOOL IsEnable);
void SeDeleteHookEntry(UINT Item);