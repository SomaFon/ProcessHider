#pragma once
#include <windows.h>
#include "Buffer.h"

#if defined(_M_X64) || defined(__x86_64__)
#include "hde/hde64.h"
typedef hde64s HDE;
#define HDE_DISASM(code, hde) hde64_disasm(code, hde)
#else
#include "hde/hde32.h"
typedef hde32s HDE;
#define HDE_DISASM(code, hde) hde32_disasm(code, hde)
#endif




/************************************************************************/
/*                                                                      */
/************************************************************************/

#pragma pack(1)
typedef struct _TRAMPOLINE
{
	LPVOID TargetFunctionAddress;      
	LPVOID FakeFunctionAddress;        
	LPVOID MemorySlot;                   // MemorySlot 32字节

#if defined(_M_X64) || defined(__x86_64__)
	LPVOID Relay;           // [Out] Address of the relay function.   原函数 到 Fake函数的中转站 
#endif
	BOOL   PatchAbove;      // [Out] Should use the hot patch area?  //Patch  --->补丁   //0xA 0xB
	UINT   Index;           // [Out] Number of the instruction boundaries.
	UINT8  OldIPs[8];       // [Out] Instruction boundaries of the target function.      //恢复
	UINT8  NewIPs[8];       // [Out] Instruction boundaries of the trampoline function.  //Hook
} TRAMPOLINE, *PTRAMPOLINE;



#pragma pack(1)
typedef struct _JMP_REL_SHORT
{
	UINT8  opcode;      // EB xx: JMP +2+xx
	UINT8  operand;
} JMP_REL_SHORT, *PJMP_REL_SHORT;


#pragma pack(1)
typedef struct _JMP_REL
{
	UINT8  Opcode;      // E9/E8 xxxxxxxx: JMP/CALL +5+xxxxxxxx
	UINT32 Operand;     // Relative destination address   相对偏移
} JMP_REL, *PJMP_REL,CALL_REL,*PCALL_REL;

#pragma pack(1)
typedef struct _JCC_REL
{
	UINT8  Opcode0;     // 0F8* xxxxxxxx: J** +6+xxxxxxxx
	UINT8  Opcode1;
	UINT32 Operand;     // Relative destination address
} JCC_REL;

/***********************************************************************

* x64使用的结构体                                                                    

***********************************************************************/

#pragma pack(1)
typedef struct _JMP_ABS
{
	UINT8  Opcode0;     // FF25 00000000: JMP [+6]
	UINT8  Opcode1;     
	UINT32 Dummy;
	UINT64 Address;     // Absolute destination address
} JMP_ABS, *PJMP_ABS;

#pragma pack(1)
typedef struct _CALL_ABS
{
	UINT8  Opcode0;     // FF15 00000002: CALL [+6]
	UINT8  Opcode1;
	UINT32 Dummy0;
	UINT8  Dummy1;      // EB 08:         JMP +10
	UINT8  Dummy2;
	UINT64 Address;     // Absolute destination address
} CALL_ABS;

#pragma pack(1)
typedef struct _JCC_ABS
{
	UINT8  Opcode;      // 7* 0E:         J** +16
	UINT8  Dummy0;
	UINT8  Dummy1;      // FF25 00000000: JMP [+6]
	UINT8  Dummy2;
	UINT32 Dummy3;
	UINT64 Address;     // Absolute destination address
} JCC_ABS;




#if defined(_M_X64) || defined(__x86_64__)
#define TRAMPOLINE_MAX_SIZE (MEMORY_SLOT_SIZE - sizeof(JMP_ABS))
#else
#define TRAMPOLINE_MAX_SIZE MEMORY_SLOT_SIZE
#endif


/************************************************************************/
/*                                                                      */
/************************************************************************/

BOOL SeCreateTrampoline(PTRAMPOLINE Trampoline);
BOOL IsCodePadding(LPBYTE VirtualAddress, UINT CodeLength);


