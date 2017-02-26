#pragma optimize("", off)

/*
@image  : CaptainHook
@author : shmuelyr
*****************************************************************
******** linker command line needed the following tags **********
****** /D "CAPSTONE_HAS_X86" /D "CAPSTONE_USE_SYS_DYN_MEM" ******
*****************************************************************
*/

#include "CaptainHook.h"

/*
*
CaptainHook constructor just init internal inf
------------------------------------------------
*/
CaptainHook::CaptainHook() {

	this->uiInternalCounter = 0;
	this->pVectorHandle = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)HardwareBreakPointManager);
	if (!this->pVectorHandle) {

		// add operation
	}
}

/*
*
~CaptainHook destructor remove all your hooks
------------------------------------------------
*/
CaptainHook::~CaptainHook() {

 	RemoveVectoredExceptionHandler(this->pVectorHandle);

	for each (HOOK_INF Function in this->FunctionList) {

		if ((Function.pOriginalFunction != 0) && (Function.pEmulatedFunction)) {

			memcpy(
				(void *)Function.pOriginalFunction,
				(void *)Function.pEmulatedFunction,
				Function.uiHookSize);

			VirtualFree(
				Function.pEmulatedFunction,
				Function.uiGlobalSize,
				MEM_DECOMMIT);
		}
	}
	this->FunctionList.~vector();
	this->DisabledPGHookList.~vector();
	g_VectorHandlerList.~vector();
}

/*
*
* @param1: point to source function that will hook
* @param2: point to dest finction that whill chain to source
------------------------------------------------
AddInlineHook instert inline hook without HookId
*/
unsigned int CaptainHook::AddInlineHook(void **ppvSrc, void *pvDst) {

	unsigned int uiId;
	return this->AddInlineHook(ppvSrc, pvDst, &uiId);
}

/*
*
* @param1: point to source function that will hook
* @param2: point to dest finction that whill chain to source
------------------------------------------------
AddPageGuardHook set memory protection on the first line(whole page..) and build a hook without HookId
*/
unsigned int CaptainHook::AddPageGuardHook(void **ppvSrc, void *pvDst) {

	unsigned int uiHookId;
	return AddPageGuardHook(ppvSrc, pvDst, &uiHookId);
}

/*
*
* @param1: point to source function that will hook
* @param2: point to dest finction that whill chain to source
* @param3: point to HookId (unsigned int type)
------------------------------------------------
AddInlineHook instert inline hook and give you back an HookId
*/
unsigned int CaptainHook::AddInlineHook(void **ppvSrc, void *pvDst, unsigned int *puiHookId) {

	HOOK_INF HookInf;
	unsigned long ulOldProtect;
	unsigned int uiSizeOfStolenOpcode;

	if (bVerifyUserPointer(ppvSrc, pvDst)) return CH_USER_POINTER_ERR;

	uiSizeOfStolenOpcode = CalcAlignedSizeForHook(*ppvSrc, JMP_HOOKTYPE_LEN);

	if (uiSizeOfStolenOpcode == ERR_CANNOT_RESOLVE_ASM) {

		return CH_CAPSTONE_ASM_ERR;
	}
	else if (uiSizeOfStolenOpcode == 0) {

		return 0;
	}

	HookInf.uiId = this->uiInternalCounter;
	HookInf.uiHookSize = uiSizeOfStolenOpcode;
	HookInf.pDestFunction = (unsigned char *)pvDst;
	HookInf.pOriginalFunction = (unsigned char *)*ppvSrc;
	HookInf.uiGlobalSize = uiSizeOfStolenOpcode + JMP_TRAMPOLINE_LEN;
	HookInf.pEmulatedFunction = (unsigned char *)VirtualAlloc(NULL, HookInf.uiGlobalSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (VirtualProtect(*ppvSrc, uiSizeOfStolenOpcode, PAGE_EXECUTE_READWRITE, &ulOldProtect) == 0) {

		VirtualFree(HookInf.pEmulatedFunction, HookInf.uiGlobalSize, MEM_DECOMMIT);
		return CH_VIRTUALPROTECT_ERR;
	}
	if (HookInf.pEmulatedFunction == 0) return CH_ALLOC_ERR;
	memcpy(HookInf.pEmulatedFunction, *ppvSrc, uiSizeOfStolenOpcode);

	*puiHookId = HookInf.uiId;
	this->uiInternalCounter++;
	this->FunctionList.push_back(HookInf);

#if defined(_M_X64) || defined(__amd64__)

	BuildX64Hook(&HookInf);
#elif _WIN32

	BuildX86Hook(&HookInf);
#endif


	// redirect template function to emulated code.
	*(addr *)ppvSrc = (addr)HookInf.pEmulatedFunction;
	if (FlushInstructionCache(GetCurrentProcess(), *ppvSrc, uiSizeOfStolenOpcode)) return CH_SUCCESS;
	else return GetLastError();
}

/*
*
* @param1: point to source function that will hook
* @param2: point to dest finction that whill chain to source
------------------------------------------------
AddPageGuardHook set memory protection on the first line(whole page..) build a hook and give you back an HookId
*/
unsigned int CaptainHook::AddPageGuardHook(void **ppvSrc, void *pvDst, unsigned int *puiHookId) {

	unsigned long ulOldProtect;
	VECTOREXCPTION_RESOLVED HookInf;

	if (bVerifyUserPointer(ppvSrc, pvDst)) return CH_USER_POINTER_ERR;
	if (this->pVectorHandle == NULL) return CH_VECTOR_HANDLE_ERR;

	HookInf.uiHookId = this->uiInternalCounter;
	HookInf.pfnOriginalFunction = (addr)*ppvSrc;
	HookInf.pfnHookedFunction = (addr)pvDst;

	g_VectorHandlerList.push_back(HookInf);

	if (!VirtualProtect(*ppvSrc, 4, PAGE_GUARD | PAGE_EXECUTE_READWRITE, &ulOldProtect)) {

		g_VectorHandlerList.pop_back();
		return CH_VPROTECT_ERR;
	}
	this->uiInternalCounter++;
	return CH_SUCCESS;
}

/*

*/
unsigned int CaptainHook::DisableHook(unsigned int uiHookId) {

	for each(HOOK_INF Function in this->FunctionList) {

		if (Function.uiId == uiHookId) {

			memcpy(
				(void *)Function.pOriginalFunction,
				(void *)Function.pEmulatedFunction,
				Function.uiHookSize);
			
			return 0;
		}
	}

	for (
		unsigned int uiIndex = 0; uiIndex < g_VectorHandlerList.size(); uiIndex++) {

		if (g_VectorHandlerList[uiIndex].uiHookId == uiHookId) {

			this->DisabledPGHookList.push_back(g_VectorHandlerList[uiIndex]);
			g_VectorHandlerList.erase(g_VectorHandlerList.begin() + uiIndex);
		}
	}
}

/*

*/
unsigned int CaptainHook::EnableHook(unsigned int uiHookId) {

	for each(HOOK_INF Function in this->FunctionList) {

		if (Function.uiId == uiHookId) {

			memcpy(
				(void *)Function.pEmulatedFunction,
				(void *)Function.pOriginalFunction,
				Function.uiHookSize);

			return 0;
		}
	}

	for (
		unsigned int uiIndex = 0; uiIndex < this->DisabledPGHookList.size(); uiIndex++) {

		if (this->DisabledPGHookList[uiIndex].uiHookId == uiHookId) {

			g_VectorHandlerList.push_back(this->DisabledPGHookList[uiIndex]);
			this->DisabledPGHookList.erase(this->DisabledPGHookList.begin() + uiIndex);
		}
	}
}

/*
*
* @param1: point to source function that will hook
* @param2: point to dest finction that whill chain to source
------------------------------------------------
this function just verify if userpointer is valid or not
*/
unsigned int CaptainHook::bVerifyUserPointer(void **ppvSrc, void *pvDst) {

	unsigned char ucTester;
	__try {

		ucTester = *(unsigned char *)ppvSrc;
		ucTester = *(unsigned char *)pvDst;
	}
	__except (TRUE) {

		return CH_USER_POINTER_ERR;
	}
	return CH_SUCCESS;
}

/*
*
* @param1: point to source function that will hook
* @param2: hook type
------------------------------------------------
CalcAlignedSizeForHook return how many opcode should steal
*/
unsigned int CaptainHook::CalcAlignedSizeForHook(void *pvSrc, unsigned int uiHookLen) {

	csh cshHandle;
	cs_insn *pInsn;
	unsigned int uiCount;
	unsigned int uiByteCounter;

	uiByteCounter = 0;
	if (cs_open(CS_ARCH_X86, ARCH_MODE, &cshHandle) != CS_ERR_OK) {

		return ERR_CANNOT_RESOLVE_ASM;
	}
	uiCount = (unsigned int)cs_disasm(cshHandle, (unsigned char *)pvSrc, 0x50, 0x100, 0, &pInsn);
	if (uiCount > 0) {

		unsigned char *pucBytes = pInsn->bytes;
		for (unsigned int uiIndex = 0; uiIndex < uiCount; uiIndex++) {

			if (pucBytes[uiIndex] == 0xeb) { // jmp

				/* right now this flow isnt handled */
				cs_free(pInsn, uiCount);
				cs_close(&cshHandle);
				return 0;
			}
			else if ((pucBytes[uiIndex] >= 0x70) && (pucBytes[uiIndex] <= 0x7f)) { // !jz/nz/g/ng etc.

				/* right now this flow isnt handled */
				cs_free(pInsn, uiCount);
				cs_close(&cshHandle);
				return 0;
			}
			else {

				uiByteCounter += pInsn[uiIndex].size;
				if (uiByteCounter >= uiHookLen) {

					cs_free(pInsn, uiCount);
					cs_close(&cshHandle);
					return uiByteCounter;
				}
			}
		}
	}
	else {

		cs_close(&cshHandle);
		return ERR_CANNOT_RESOLVE_ASM;
	}
}

/*
*
* @param1: point to HOOK_INF strunt contains information about your hook
------------------------------------------------
BuildX86Hook just build x86 inline hook
*/
unsigned int CaptainHook::BuildX86Hook(HOOK_INF *pFunction) {

	// build trampoline from hookchain to real code.
	*((unsigned char *)pFunction->pEmulatedFunction + pFunction->uiHookSize) = LONG_JMP;
	*((unsigned int *)((unsigned char *)pFunction->pEmulatedFunction + pFunction->uiHookSize + 1)) = (unsigned int)pFunction->pOriginalFunction - (unsigned int)pFunction->pEmulatedFunction - 5;

	// build trampoline from real code to hook function.
	*(unsigned char *)pFunction->pOriginalFunction = LONG_JMP;
	*((unsigned int *)((unsigned char *)pFunction->pOriginalFunction + 1)) = (unsigned int)pFunction->pDestFunction - (unsigned int)pFunction->pOriginalFunction - 5;


	return CH_SUCCESS;
}

/*
*
* @param1: point to HOOK_INF strunt contains information about your hook
------------------------------------------------
BuildX86Hook just build x64 inline hook
*/
unsigned int CaptainHook::BuildX64Hook(HOOK_INF *pFunction) {

	/*
	* hook type for x64:
	* push 0
	* mov dword ptr ds:[rsp], (pvDst 0xffffffff)
	* mov dword ptr ds:[rsp + 4], (pvDst >> 0x20)
	* ret
	*/

	// build trampoline from hookchain to real code.
	*(unsigned short *)(pFunction->pEmulatedFunction + pFunction->uiHookSize) = PUSH_0;
	*(unsigned short *)(pFunction->pEmulatedFunction + pFunction->uiHookSize + 2) = MOV_RSP & 0xffff;
	*(unsigned char *)(pFunction->pEmulatedFunction + pFunction->uiHookSize + 4) = MOV_RSP >> 0x10;
	*(unsigned int *)(pFunction->pEmulatedFunction + pFunction->uiHookSize + 5) = (unsigned int)(((unsigned long long)pFunction->pOriginalFunction + pFunction->uiHookSize) & 0xffffffff);
	*(unsigned int *)(pFunction->pEmulatedFunction + pFunction->uiHookSize + 9) = MOV_RSP4;
	*(unsigned int *)(pFunction->pEmulatedFunction + pFunction->uiHookSize + 13) = (unsigned int)(((unsigned long long)pFunction->pOriginalFunction + pFunction->uiHookSize) >> 0x20);
	*(unsigned char *)(pFunction->pEmulatedFunction + pFunction->uiHookSize + 17) = RET;

	// build trampoline from real code to hook function.
	*(unsigned short *)((unsigned char *)pFunction->pOriginalFunction) = PUSH_0;
	*(unsigned short *)((unsigned char *)pFunction->pOriginalFunction + 2) = MOV_RSP & 0xffff;
	*((unsigned char *)pFunction->pOriginalFunction + 4) = MOV_RSP >> 0x10;
	*(unsigned int *)((unsigned char *)pFunction->pOriginalFunction + 5) = (unsigned int)(((unsigned long long)(unsigned char *)pFunction->pDestFunction) & 0xffffffff);
	*(unsigned int *)((unsigned char *)pFunction->pOriginalFunction + 9) = MOV_RSP4;
	*(unsigned int *)((unsigned char *)pFunction->pOriginalFunction + 13) = (unsigned int)(((unsigned long long)(unsigned char *)pFunction->pDestFunction) >> 0x20);
	*(unsigned char *)((unsigned char *)pFunction->pOriginalFunction + 17) = RET;

	return CH_SUCCESS;
}
