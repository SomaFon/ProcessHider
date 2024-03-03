#include"stdafx.h"
#include "Trampoline.h"
#include <intrin.h>
#include "MiniHook-Dll.h"

BOOL SeCreateTrampoline(PTRAMPOLINE Trampoline)
{
	
#if defined(_M_X64) || defined(__x86_64__)
	CALL_ABS call = {
		0xFF, 0x15, 0x00000002, // FF15 00000002: CALL [RIP+8]
		0xEB, 0x08,             // EB 08:         JMP +10
		0x0000000000000000ULL   // Absolute destination address
	};
	JMP_ABS jmp = {
		0xFF, 0x25, 0x00000000, // FF25 00000000: JMP [RIP+6]
		0x0000000000000000ULL   // Absolute destination address
	};
	JCC_ABS jcc = {
		0x70, 0x0E,             // 7* 0E:         J** +16
		0xFF, 0x25, 0x00000000, // FF25 00000000: JMP [RIP+6]
		0x0000000000000000ULL   // Absolute destination address
	};
#else
	CALL_REL call = {
		0xE8,                   // E8 xxxxxxxx: CALL +5 + xxxxxxxx  Push Eip    Jmp    Ret
		0x00000000              // Relative destination address
	};
	JMP_REL jmp = {
		0xE9,                   // E9 xxxxxxxx: JMP +5+xxxxxxxx                   
		0x00000000              // Relative destination address
	};
	JCC_REL jcc = {
		0x0F, 0x80,             // 0F8* xxxxxxxx: J** +6+xxxxxxxx
		0x00000000              // Relative destination address
	};

#endif

	UINT8     OldPosition = 0;      //TargetFunctionAddress
	UINT8     NewPosition = 0;      //MemorySlot
	ULONG_PTR JmpDestination = 0;     // Destination address of an internal jump.
	BOOL      IsLoop = FALSE;  // Is the function completed?
#if defined(_M_X64) || defined(__x86_64__)
	UINT8     v5[16];
#endif

	Trampoline->PatchAbove = FALSE;
	Trampoline->Index = 0;
	ZeroMemory(Trampoline->MemorySlot, 32);
	do
	{
	
		HDE       hde;   
		UINT      CopyDataLength;
		LPVOID    CopyData;
		//对于出现的相对偏移地址，在跳板中都要给出新的相对地址
		/* 32位 MessageBox
		74CA8B80 8B FF                mov         edi,edi
		74CA8B82 55                   push        ebp
		74CA8B83 8B EC                mov         ebp,esp
		74CA8B85 6A 00                push        0
		74CA8B87 FF 75 14             push        dword ptr [ebp+14h]
		74CA8B8A FF 75 10             push        dword ptr [ebp+10h]
		74CA8B8D FF 75 0C             push        dword ptr [ebp+0Ch]
		74CA8B90 FF 75 08             push        dword ptr [ebp+8]
		74CA8B93 E8 F8 FC FF FF       call        _MessageBoxExW@20 (74CA8890h)



		64位 MessageBox
		00007FF97B4485A0 48 83 EC 38          sub         rsp,38h
		00007FF97B4485A4 45 33 DB             xor         r11d,r11d
		00007FF97B4485A7 44 39 1D 7A 33 03 00 cmp         dword ptr [gfEMIEnable (07FF97B47B928h)],r11d
		00007FF97B4485AE 74 2E                je          MessageBoxW+3Eh (07FF97B4485DEh)
		00007FF97B4485B0 65 48 8B 04 25 30 00 00 00 mov         rax,qword ptr gs:[30h]
		00007FF97B4485B9 4C 8B 50 48          mov         r10,qword ptr [rax+48h]
		00007FF97B4485BD 33 C0                xor         eax,eax
		00007FF97B4485BF F0 4C 0F B1 15 98 44 03 00 lock cmpxchg qword ptr [gdwEMIThreadID (07FF97B47CA60h)],r10
		00007FF97B4485C8 4C 8B 15 99 44 03 00 mov         r10,qword ptr [gpReturnAddr (07FF97B47CA68h)]
		00007FF97B4485CF 41 8D 43 01          lea         eax,[r11+1]
		00007FF97B4485D3 4C 0F 44 D0          cmove       r10,rax
		00007FF97B4485D7 4C 89 15 8A 44 03 00 mov         qword ptr [gpReturnAddr (07FF97B47CA68h)],r10
		00007FF97B4485DE 83 4C 24 28 FF       or          dword ptr [rsp+28h],0FFFFFFFFh
		00007FF97B4485E3 66 44 89 5C 24 20    mov         word ptr [rsp+20h],r11w
		00007FF97B4485E9 E8 A2 FE FF FF       call        MessageBoxTimeoutW (07FF97B448490h)
		00007FF97B4485EE 48 83 C4 38          add         rsp,38h




		*/

		ULONG_PTR OldInstance = (ULONG_PTR)Trampoline->TargetFunctionAddress + OldPosition;
		ULONG_PTR NewInstance = (ULONG_PTR)Trampoline->MemorySlot + NewPosition;
		//指令长度
		
		CopyDataLength = HDE_DISASM((LPVOID)OldInstance, &hde);   //当前一条指令的长度

		if (hde.flags & F_ERROR)
			return FALSE;

		CopyData = (LPVOID)OldInstance;
		if (OldPosition >= sizeof(JMP_REL))    
		{
			// The trampoline function is long enough.

#if defined(_M_X64) || defined(__x86_64__)
		
			//OldInstance = 00007FF97B4485A7;
			jmp.Address = OldInstance;
#else        
			//OldInstance = 74CA8B85

			//目标 = 源 + Offset + 5
			//Offset = 目标 - (源 + 5) 
			jmp.Operand = (UINT32)(OldInstance - (NewInstance  + sizeof(jmp)));   //计算跳转到目标的偏移

#endif
			CopyData = &jmp;
			CopyDataLength = sizeof(jmp);

			IsLoop = TRUE;
		}
#if defined(_M_X64) || defined(__x86_64__)
		else if ((hde.modrm & 0xC7) == 0x05)   //这里不知道啥情况
		{
			// [disp32] 或[rip + disp32]寻址
			// Instructions using RIP relative addressing. (ModR/M = 00???101B)
			// Modify the RIP relative address.
			PUINT32 RelativeAddress;

			// Avoid using memcpy to reduce the footprint.
#ifndef _MSC_VER
			memcpy(v5, (LPBYTE)OldInstance, CopyDataLength);
#else
			__movsb(v5, (LPBYTE)OldInstance, CopyDataLength);
#endif
			CopyData = v5;

			// Relative address is stored at (instruction length - immediate value length - 4).
			RelativeAddress = (PUINT32)(v5 + hde.len - ((hde.flags & 0x3C) >> 2) - 4);
			*RelativeAddress
				= (UINT32)((OldInstance + hde.len + (INT32)hde.disp.disp32) - (NewInstance + hde.len));

			// Complete the function if JMP (FF /4).
			if (hde.opcode == 0xFF && hde.modrm_reg == 4)
				IsLoop = TRUE;
		}
#endif
		else if (hde.opcode == 0xE8)   //Hook链
		{
			// Direct relative CALL 

			ULONG_PTR Destination = OldInstance + hde.len + (INT32)hde.imm.imm32;   //
#if defined(_M_X64) || defined(__x86_64__)
			call.Address = Destination;
#else
			//计算源地址和Trampoline之间的偏移值
			call.Operand = (UINT32)(Destination - (NewInstance + sizeof(call)));
#endif
			//CopyData  被拷贝到Trampoline中保存的内容
			CopyData = &call;
			CopyDataLength = sizeof(call);
		}
		else if ((hde.opcode & 0xFD) == 0xE9)    //F   1111    D   1101    
		{										 //E   1110    9   1001      
			                                     //E   1110    B   1011
	
			// Direct relative JMP (EB or E9)
			ULONG_PTR Destination = OldInstance + hde.len; //

			/*
			0xDE  EB 00 
			0xE0  xor  eax,eax
			*/

			if (hde.opcode == 0xEB) // isShort jmp
				Destination += (INT8)hde.imm.imm8;
			else
				Destination += (INT32)hde.imm.imm32;

			// Simply copy an internal jump.
			if ((ULONG_PTR)Trampoline->TargetFunctionAddress <= Destination
				&& Destination < ((ULONG_PTR)Trampoline->TargetFunctionAddress + sizeof(JMP_REL)))
			{
				//比较越界
				/*			
			Asm_5  PROC
					jmp Label1
				Lable2:
					xor eax,eax
					Loop Lable2
					mov eax,-5
					ret
				Label1:
					mov ecx,2
					jmp Lable2

			Asm_5 ENDP			
				*/
				if (JmpDestination < Destination)
					JmpDestination = Destination;   
			}
			else
			{
		
#if defined(_M_X64) || defined(__x86_64__)
		
				jmp.Address = Destination;
#else

				//
				jmp.Operand = (UINT32)(Destination - (NewInstance + sizeof(jmp)));
#endif
				 CopyData = &jmp;
				 CopyDataLength = sizeof(jmp);

				// Exit the function If it is not in the branch
				IsLoop = (OldInstance >= JmpDestination);  
			}
		}
		else if ((hde.opcode & 0xF0) == 0x70
			|| (hde.opcode & 0xFC) == 0xE0
			|| (hde.opcode2 & 0xF0) == 0x80)                         
		{

			/*  
			& 0xF0
			0x70 jo		后有一个字节的偏移
			0x71 jno    后有一个字节的偏移
			0x72 jb     后有一个字节的偏移
			..
			..
			0x7F jg     后有一个字节的偏移
		
			& 0xFC 		
			0xE0 loopne 后有一个字节的偏移
			0xE1 
			0xE2
			0xE3
			*/

			// Direct relative Jcc
			ULONG_PTR Destination = OldInstance + hde.len;

			if ((hde.opcode & 0xF0) == 0x70      // Jcc
				|| (hde.opcode & 0xFC) == 0xE0)  // LOOPNZ/LOOPZ/LOOP/JECXZ
				Destination += (INT8)hde.imm.imm8;
			else
				Destination += (INT32)hde.imm.imm32;

			// Simply copy an internal jump.
			if ((ULONG_PTR)Trampoline->TargetFunctionAddress <= Destination
				&& Destination < ((ULONG_PTR)Trampoline->TargetFunctionAddress + sizeof(JMP_REL)))
			{
				if (JmpDestination < Destination)
					JmpDestination = Destination;
			}
			else if ((hde.opcode & 0xFC) == 0xE0)
			{
				// LOOPNZ/LOOPZ/LOOP/JCXZ/JECXZ to the outside are not supported.  
				return FALSE;
			}
			else
			{
				UINT8 v1 = ((hde.opcode != 0x0F ? hde.opcode : hde.opcode2) & 0x0F);
#if defined(_M_X64) || defined(__x86_64__)
				// Invert the condition in x64 mode to simplify the conditional jump logic.
			
				
				jcc.Opcode = 0x71 ^ v1;
				jcc.Address = Destination;
#else
				jcc.Opcode1 = 0x80 | v1;
				jcc.Operand = (UINT32)(Destination - (NewInstance + sizeof(jcc)));
#endif
				CopyData = &jcc;
				CopyDataLength = sizeof(jcc);
			}
		}
		else if ((hde.opcode & 0xFE) == 0xC2)
		{
			// RET (C2 or C3)

			// Complete the function if not in a branch.
			IsLoop = (OldInstance >= JmpDestination);   
		}

		// Can't alter the instruction length in a branch.
		if (OldInstance < JmpDestination && CopyDataLength != hde.len)
			return FALSE;

		// Trampoline function is too large.
		if ((NewPosition + CopyDataLength) > TRAMPOLINE_MAX_SIZE)
			return FALSE;

		// Trampoline function has too many instructions.
		if (Trampoline->Index >= ARRAYSIZE(Trampoline->OldIPs))
			return FALSE;

		Trampoline->OldIPs[Trampoline->Index] = OldPosition;//OldIps保存原函数每条指令的偏移值（Index为指令索引）
		Trampoline->NewIPs[Trampoline->Index] = NewPosition;//NewIps保存MemorySlot中前面写入的每条原函数指令的偏移值 
		Trampoline->Index++;

		// Avoid using memcpy to reduce the footprint.
#ifndef _MSC_VER
		memcpy((LPBYTE)Trampoline->MemorySlot + NewPosition, CopyData, CopyDataLength);
#else
		__movsb((LPBYTE)Trampoline->MemorySlot + NewPosition, (const unsigned char*)CopyData, CopyDataLength);
#endif

		
		NewPosition += CopyDataLength;
		OldPosition += hde.len;
	} while (!IsLoop);

	// Is there enough place for a long jump?
	//是否有足够的位置长跳转
	if (OldPosition < sizeof(JMP_REL)
		&& !IsCodePadding((LPBYTE)Trampoline->TargetFunctionAddress + OldPosition, sizeof(JMP_REL) - OldPosition))
	{

		// Is there enough place for a short jump?
		//没有有足够的位置长跳转，那是否有足够的位置短跳转?
	    if (OldPosition < sizeof(JMP_REL_SHORT)
			&& !IsCodePadding((LPBYTE)Trampoline->TargetFunctionAddress + OldPosition, sizeof(JMP_REL_SHORT) - OldPosition))
		{
			return FALSE;
		}
		//只能写短跳转，使用热补丁
		// Can we place the long jump above the function?
		//热补丁：目标地址之前地址是否可执行?
		if (!SeIsExecutableAddress((LPBYTE)Trampoline->TargetFunctionAddress - sizeof(JMP_REL)))
			return FALSE;
		//目标地址之前是否是可被覆盖的空白
		if (!IsCodePadding((LPBYTE)Trampoline->TargetFunctionAddress - sizeof(JMP_REL), sizeof(JMP_REL)))
			return FALSE;
		//标志可以热补丁
		Trampoline->PatchAbove = TRUE;
	}

#if defined(_M_X64) || defined(__x86_64__)
	// Create a relay function.
	jmp.Address = (ULONG_PTR)Trampoline->FakeFunctionAddress;

	Trampoline->Relay = (LPBYTE)Trampoline->MemorySlot + NewPosition;
	memcpy(Trampoline->Relay, &jmp, sizeof(jmp));
#endif


	/*
	MemorySlot 在MessageBox 附近
	48 83 ec 38 45 33 db 
	ff 25 00 00 00 00 a7 85 44 7b f9 7f 00 00  MessageBox的7个字节之后
    ff 25 00 00 00 00 6b 13 a6 01 f7 7f 00 00  FakeMessageBox
	
	*/
	return TRUE;

		
}

BOOL IsCodePadding(LPBYTE VirtualAddress, UINT CodeLength)
{
	//0x8b 0xFF
	UINT i;

	if (VirtualAddress[0] != 0x00 && VirtualAddress[0] != 0x90 && VirtualAddress[0] != 0xCC)
		return FALSE;

	for (i = 1; i < CodeLength; ++i)
	{
		if (VirtualAddress[i] != VirtualAddress[0])
			return FALSE;
	}
	return TRUE;
}



