#pragma once
#include <windows.h>
#include <iostream>

using namespace std;
#define MEMORY_BLOCK_SIZE 0x1000
#if defined(_M_X64) || defined(__x86_64__)
#define MEMORY_SLOT_SIZE 64
#else
#define MEMORY_SLOT_SIZE 32
#endif

// Max range for seeking a memory block. (= 1024MB)
#define MAX_MEMORY_RANGE 0x40000000

typedef struct _MEMORY_SLOT
{
	union
	{
		struct _MEMORY_SLOT *Flink;  //4  /8
		UINT8 BufferData[MEMORY_SLOT_SIZE]; //64
	};
} MEMORY_SLOT, *PMEMORY_SLOT;  //32×Ö½Ú

typedef struct _MEMORY_BLOCK
{
	_MEMORY_BLOCK* Flink;
	PMEMORY_SLOT   FreeMemorySlotHead;         // First element of the free slot list.
	UINT UsedCount;
} MEMORY_BLOCK, *PMEMORY_BLOCK; //12×Ö½Ú


LPVOID SeAllocateBuffer(LPVOID FunctionAddress);
VOID SeFreeBuffer(LPVOID VirtualAddress);
PMEMORY_BLOCK SeGetMemoryBlock(LPVOID FunctionAddress);
VOID SeUninitializeBuffer(VOID);

#if defined(_M_X64) || defined(__x86_64__)
LPVOID SeFindNextFreeRegion(LPVOID VirtualAddress, LPVOID MaxAddress, DWORD AllocationGranularity);
LPVOID SeFindPreviousFreeRegion(LPVOID VirtualAddress, LPVOID MiniAddress, DWORD AllocationGranularity);
#endif



