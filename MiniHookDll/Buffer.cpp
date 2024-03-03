#include"stdafx.h"
#include "Buffer.h"

PMEMORY_BLOCK __MemoryBlocks = NULL;
LPVOID SeAllocateBuffer(LPVOID FunctionAddress)  //TargetFunctionAddress
{
	//x86 将memoryblock大结构体初始化，将0x1000内存使用完，在里面申请很多个memoryslot，
	//全部放入以freememoryslothead为头结点的链表中
	PMEMORY_BLOCK MemoryBlock = SeGetMemoryBlock(FunctionAddress);
	if (MemoryBlock == NULL)
	{
		return NULL;
	}
	PMEMORY_SLOT  MemorySlot = NULL;   //初始化使用

	//从以freememoryslothead为头结点的链表中取出一块memoryslot以供使用
	// Remove an unused slot from the list.
	MemorySlot = MemoryBlock->FreeMemorySlotHead;
	MemoryBlock->FreeMemorySlotHead = MemorySlot->Flink;
	MemoryBlock->UsedCount++;   //
#ifdef _DEBUG
	// Fill the slot with INT3 for debugging.
	memset(MemorySlot, 0xCC, sizeof(MEMORY_SLOT));
#endif
	return MemorySlot;
}



PMEMORY_BLOCK SeGetMemoryBlock(LPVOID FunctionAddress) //0x1000
{
	PMEMORY_BLOCK MemoryBlock = NULL;
#if defined(_M_X64) || defined(__x86_64__)
	ULONG_PTR MiniAddress;
	ULONG_PTR MaxAddress;

	SYSTEM_INFO SystemInfo;
	GetSystemInfo(&SystemInfo);
	//获得指向应用程序和动态链接库 (DLL) 可访问的最低内存地址的指针。
	MiniAddress = (ULONG_PTR)SystemInfo.lpMinimumApplicationAddress;  
	//获得应用程序和 DLL 可访问的最高内存地址
	MaxAddress = (ULONG_PTR)SystemInfo.lpMaximumApplicationAddress;   //进程空间的范围(Ring3)

	//可以分配虚拟内存的起始地址的粒度
	int v1 = SystemInfo.dwAllocationGranularity;
	

	// pOrigin ± 512MB
	if ((ULONG_PTR)FunctionAddress > MAX_MEMORY_RANGE && MiniAddress < (ULONG_PTR)FunctionAddress - MAX_MEMORY_RANGE)
		MiniAddress = (ULONG_PTR)FunctionAddress - MAX_MEMORY_RANGE;   //大于64K  

	if (MaxAddress > (ULONG_PTR)FunctionAddress + MAX_MEMORY_RANGE)
		MaxAddress = (ULONG_PTR)FunctionAddress + MAX_MEMORY_RANGE;

	// Make room for MEMORY_BLOCK_SIZE bytes.
	MaxAddress -= MEMORY_BLOCK_SIZE - 1;
#endif
	// Look the registered blocks for a reachable one.
	for (MemoryBlock = __MemoryBlocks; MemoryBlock != NULL; MemoryBlock = MemoryBlock->Flink)
	{
#if defined(_M_X64) || defined(__x86_64__)
		// Ignore the blocks too far.
		if ((ULONG_PTR)MemoryBlock < MiniAddress || (ULONG_PTR)MemoryBlock >= MaxAddress)
			continue;
#endif
		// The block has at least one unused slot.
		if (MemoryBlock->FreeMemorySlotHead != NULL)  //判断大结构体中有无32个字节的小结构如果有返回  
			return MemoryBlock;
	}
#if defined(_M_X64) || defined(__x86_64__)
	// Alloc a new block above if not found.
	{
		LPVOID v1 = FunctionAddress;
		while ((ULONG_PTR)v1 >= MiniAddress)
		{
			v1 = SeFindPreviousFreeRegion(v1, (LPVOID)MiniAddress, SystemInfo.dwAllocationGranularity);
			if (v1 == NULL)
				break;


			MemoryBlock = (PMEMORY_BLOCK)VirtualAlloc(
				v1, MEMORY_BLOCK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (MemoryBlock != NULL)
				break;
		}
	}
	// Alloc a new block below if not found.
	if (MemoryBlock == NULL)
	{
		LPVOID v1= FunctionAddress;
		while ((ULONG_PTR)v1 <= MaxAddress)
		{
			v1 = SeFindNextFreeRegion(v1, (LPVOID)MaxAddress, SystemInfo.dwAllocationGranularity);
			if (v1 == NULL)
				break;
			MemoryBlock = (PMEMORY_BLOCK)VirtualAlloc(
				v1, MEMORY_BLOCK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (MemoryBlock != NULL)
				break;
		}
	}
#else
	// In x86 mode, a memory block can be placed anywhere.
	MemoryBlock = (PMEMORY_BLOCK)VirtualAlloc(
		NULL, MEMORY_BLOCK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
#endif
	if (MemoryBlock != NULL)
	{
		//Build a linked list of all the slots.
		//MEMORY_SLOT是32字节 结构体   中间空余32 - 12 =  20字节
		PMEMORY_SLOT MemorySlot = (PMEMORY_SLOT)MemoryBlock + 1;
		MemoryBlock->FreeMemorySlotHead = NULL;
		MemoryBlock->UsedCount = 0;
		do
		{
			MemorySlot->Flink = MemoryBlock->FreeMemorySlotHead;
			MemoryBlock->FreeMemorySlotHead = MemorySlot;
			MemorySlot++;
		} while ((ULONG_PTR)MemorySlot - (ULONG_PTR)MemoryBlock <= MEMORY_BLOCK_SIZE - MEMORY_SLOT_SIZE);
		//while循环  将0x1000内存用完
		MemoryBlock->Flink = __MemoryBlocks;
		__MemoryBlocks = MemoryBlock;
	}
	return MemoryBlock;
}
VOID SeFreeBuffer(LPVOID VirtualAddress)
{
	PMEMORY_BLOCK v1 = __MemoryBlocks;
	PMEMORY_BLOCK PreviousBlock = NULL;
	ULONG_PTR TargetBlock = ((ULONG_PTR)VirtualAddress / MEMORY_BLOCK_SIZE) * MEMORY_BLOCK_SIZE;

	while (v1 != NULL)
	{
		if ((ULONG_PTR)v1 == TargetBlock)
		{
			PMEMORY_SLOT MemorySlot = (PMEMORY_SLOT)VirtualAddress;
#ifdef _DEBUG
			// Clear the released slot for debugging.
			memset(MemorySlot, 0x00, sizeof(MEMORY_SLOT));
#endif
			// Restore the released slot to the list.
			MemorySlot->Flink = v1-> FreeMemorySlotHead;
			v1->FreeMemorySlotHead = MemorySlot;
			v1->UsedCount--;

			// Free if unused.
			if (v1->UsedCount == 0)
			{
				if (PreviousBlock)
					PreviousBlock->Flink = v1->Flink;
				else
					__MemoryBlocks = v1->Flink;

				VirtualFree(v1, 0, MEM_RELEASE);
			}

			break;
		}

		PreviousBlock = v1;
		v1 = v1->Flink;
	}
}
VOID SeUninitializeBuffer(VOID)
{
	PMEMORY_BLOCK MemoryBlock = __MemoryBlocks;
	__MemoryBlocks = NULL;

	while (MemoryBlock)
	{
		PMEMORY_BLOCK v1 = MemoryBlock->Flink;
		VirtualFree(MemoryBlock, 0, MEM_RELEASE);
		MemoryBlock = v1;
	}
}


//-------------------------------------------------------------------------
#if defined(_M_X64) || defined(__x86_64__)
LPVOID SeFindNextFreeRegion(LPVOID VirtualAddress, LPVOID MaxAddress, DWORD AllocationGranularity)
{
	ULONG_PTR v1 = (ULONG_PTR)VirtualAddress;

	// Round down to the allocation granularity.   0x10000
	v1 -= v1 % AllocationGranularity;

	// Start from the next allocation granularity multiply.
	//获得目标函数所在页面基地址
	v1 += AllocationGranularity;

	while (v1 <= (ULONG_PTR)MaxAddress)
	{
		MEMORY_BASIC_INFORMATION MemoryBasicInfo;
		//查询目标页面的范围信息
		if (VirtualQuery((LPVOID)v1, &MemoryBasicInfo, sizeof(MemoryBasicInfo)) == 0)
			break;
		//表示调用进程无法访问的空闲页面并且可以分配
		if (MemoryBasicInfo.State == MEM_FREE)
			return (LPVOID)v1;
		//从基地址开始的区域的大小，其中所有页面具有相同的属性
		v1 = (ULONG_PTR)MemoryBasicInfo.BaseAddress + MemoryBasicInfo.RegionSize;

		// Round up to the next allocation granularity.
		v1 += AllocationGranularity - 1;
		v1 -= v1 % AllocationGranularity;
	}
	return NULL;
}



//Sub_1  
LPVOID SeFindPreviousFreeRegion(LPVOID VirtualAddress, LPVOID MiniAddress, DWORD AllocationGranularity)
{
	ULONG_PTR v1 = (ULONG_PTR)VirtualAddress;  

	// Round down to the allocation granularity.
	v1 -= v1 % AllocationGranularity;

	// Start from the previous allocation granularity multiply.
	v1 -= AllocationGranularity;

	while (v1 >= (ULONG_PTR)MiniAddress)
	{
		MEMORY_BASIC_INFORMATION MemoryBasicInfo;
		if (VirtualQuery((LPVOID)v1, &MemoryBasicInfo, sizeof(MEMORY_BASIC_INFORMATION)) == 0)
			break;

		if (MemoryBasicInfo.State == MEM_FREE)
			return (LPVOID)v1;

		if ((ULONG_PTR)MemoryBasicInfo.AllocationBase < AllocationGranularity)
			break;

		v1 = (ULONG_PTR)MemoryBasicInfo.AllocationBase - AllocationGranularity;
	}

	return NULL;
}



#endif

