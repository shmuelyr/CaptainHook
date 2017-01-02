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
@param1: point to source function that will hook
@param2: point to dest finction that whill chain to source
@param3: hook type : long_jmp for currently time
------------------------------------------------
TODO : build realable trampoline, and give the user to choice when call to source function.
TODO : build smart engine to enable hot patch on jmp instruction [with all conditional jmp
	   (if the hook locate on jmp instruction - for example on memset function)
	   * fix the jmp destinention.
	   * scan the currnet function for reference to stolen jmp and fix the destinention.
TODO : Finish AnalyzeStartOfCodeForSafePatch function.
*/
CaptainHook::CaptainHook() {

	this->uiFuncitonChainCounter = 0;
	this->uiFuncitonChainSize = 10;
	this->pVectorHandle = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)HardwareBreakPointManager);
	if (!this->pVectorHandle) {

		// add operation
	}
	if (this->uiFuncitonChainSize > sizeof(FUNCTION_CHAIN) * this->uiFuncitonChainSize) {

		// add operation
	}
	
	this->pFunctionChain = (PFUNCTION_CHAIN)VirtualAlloc(0, sizeof(FUNCTION_CHAIN) * this->uiFuncitonChainSize, MEM_COMMIT, PAGE_READWRITE);
	if (!this->pFunctionChain) {

		// add operation
	}
	
}

CaptainHook::~CaptainHook() {

	
	RemoveVectoredExceptionHandler(this->pVectorHandle);

	for (unsigned int uiIndex = 0; uiIndex < this->uiFuncitonChainCounter; uiIndex++) {

		if ((this->pFunctionChain[this->uiFuncitonChainCounter].pOriginalFunction) &&
			(this->pFunctionChain[this->uiFuncitonChainCounter].pEmulatedFunction)) {

			memcpy(
				(void *)this->pFunctionChain[this->uiFuncitonChainCounter].pOriginalFunction,
				(void *)this->pFunctionChain[this->uiFuncitonChainCounter].pEmulatedFunction,
				this->pFunctionChain[this->uiFuncitonChainCounter].uiHookSize);

			VirtualFree(
				this->pFunctionChain[this->uiFuncitonChainCounter].pEmulatedFunction,
				this->pFunctionChain[this->uiFuncitonChainCounter].uiGlobalSize,
				MEM_RELEASE);
		}
	}
	VirtualFree(
		this->pFunctionChain,
		sizeof(FUNCTION_CHAIN) * this->uiFuncitonChainSize,
		MEM_RELEASE);
}

unsigned int CaptainHook::AddInlineHook(void **ppvSrc, void *pvDst) {

	unsigned long ulOldProtect;
	unsigned int uiSizeOfStolenOpcode;

	if (bSafeInitAndVerifyUserPointer(ppvSrc, pvDst) == ERR_ERROR) return CH_USER_POINTER_ERR;
	if (this->uiFuncitonChainCounter >= this->uiFuncitonChainSize) return 1;
	
	GetAddressForSafeHook(JMP_HOOKTYPE_LEN);

	uiSizeOfStolenOpcode = GetAlignedOpcodeForHook(JMP_HOOKTYPE_LEN);

	if (uiSizeOfStolenOpcode == ERR_CANNOT_RESOLVE_ASM) {

		return CH_CAPSTONE_ASM_ERR;
	}
	this->pFunctionChain[this->uiFuncitonChainCounter].uiHookSize = uiSizeOfStolenOpcode;
	this->pFunctionChain[this->uiFuncitonChainCounter].pOriginalFunction = (unsigned char *)this->pvSrc;
	this->pFunctionChain[this->uiFuncitonChainCounter].uiGlobalSize = uiSizeOfStolenOpcode + JMP_TRAMPOLINE_LEN;
	this->pFunctionChain[this->uiFuncitonChainCounter].pEmulatedFunction = (unsigned char *)VirtualAlloc(NULL, this->pFunctionChain[this->uiFuncitonChainCounter].uiGlobalSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (this->pFunctionChain[this->uiFuncitonChainCounter].pEmulatedFunction == 0) return Ch_ALLOC_ERR;
	if (VirtualProtect(this->pvSrc, uiSizeOfStolenOpcode, PAGE_EXECUTE_READWRITE, &ulOldProtect) == 0) return CH_VIRTUALPROTECT_ERR;
	memcpy(this->pFunctionChain[this->uiFuncitonChainCounter].pEmulatedFunction, this->pvSrc, uiSizeOfStolenOpcode);


#if defined(_M_X64) || defined(__amd64__)

	BuildX64Hook(uiSizeOfStolenOpcode);
#elif _WIN32

	BuildX86Hook(uiSizeOfStolenOpcode);
#endif


	// redirect template function to emulated code.
	*(addr *)this->pvTargetTemplate = (addr)pFunctionChain[uiFuncitonChainCounter].pEmulatedFunction;
	this->uiFuncitonChainCounter++;
	if (FlushInstructionCache(GetCurrentProcess(), this->pvSrc, uiSizeOfStolenOpcode)) return CH_SUCCESS;
	else return GetLastError();
}

unsigned int CaptainHook::AddPageGuardHook(void **ppvSrc, void *pvDst) {

	unsigned long ulOldProtect;
	unsigned int uiSizeOfStolenOpcode;
	
	if (bSafeInitAndVerifyUserPointer(ppvSrc, pvDst) == ERR_ERROR) return CH_USER_POINTER_ERR;
	if (g_uiVectorHandlerChainSize >= g_uiVectorHandlerMaxChainSize) return Ch_MAX_GUARDPAGE_ERR;
	if (this->pVectorHandle == NULL) return CH_VECTOR_HANDLE_ERR;

	g_VectorHandlerChain[g_uiVectorHandlerChainSize].pfnOriginalFunction = (addr)this->pvSrc;
	g_VectorHandlerChain[g_uiVectorHandlerChainSize].pfnHookedFunction = (addr)this->pvDst;
	
	uiSizeOfStolenOpcode = GetAlignedOpcodeForHook(PG_HOOKTYPE_LEN);
	if (uiSizeOfStolenOpcode == ERR_CANNOT_RESOLVE_ASM) {

		return CH_CAPSTONE_ASM_ERR;
	}
	this->pFunctionChain[this->uiFuncitonChainCounter].uiGlobalSize = uiSizeOfStolenOpcode + JMP_TRAMPOLINE_LEN;
	this->pFunctionChain[this->uiFuncitonChainCounter].pEmulatedFunction = (unsigned char *)VirtualAlloc(NULL, this->pFunctionChain[this->uiFuncitonChainCounter].uiGlobalSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (this->pFunctionChain[this->uiFuncitonChainCounter].pEmulatedFunction == 0) {

		g_VectorHandlerChain[g_uiVectorHandlerChainSize].pfnOriginalFunction = NULL;
		g_VectorHandlerChain[g_uiVectorHandlerChainSize].pfnHookedFunction = NULL;
		return Ch_ALLOC_ERR;
	}
	memcpy(this->pFunctionChain[this->uiFuncitonChainCounter].pEmulatedFunction, this->pvSrc, uiSizeOfStolenOpcode);

	*(addr *)this->pvTargetTemplate = (addr)pFunctionChain[uiFuncitonChainCounter].pEmulatedFunction;
	*((unsigned char *)this->pFunctionChain[this->uiFuncitonChainCounter].pEmulatedFunction + uiSizeOfStolenOpcode) = LONG_JMP;
	*((addr *)((unsigned char *)this->pFunctionChain[this->uiFuncitonChainCounter].pEmulatedFunction + uiSizeOfStolenOpcode + 1)) = (addr)this->pvSrc - (addr)this->pFunctionChain[this->uiFuncitonChainCounter].pEmulatedFunction - 5;


	if (!VirtualProtect(this->pvSrc, 4, PAGE_GUARD | PAGE_EXECUTE_READWRITE, &ulOldProtect)) {

		g_VectorHandlerChain[g_uiVectorHandlerChainSize].pfnOriginalFunction = NULL;
		g_VectorHandlerChain[g_uiVectorHandlerChainSize].pfnHookedFunction = NULL;
		return CH_VPROTECT_ERR;
	}
	InterlockedIncrement(&g_uiVectorHandlerChainSize);
	return CH_SUCCESS;
}

unsigned int CaptainHook::bSafeInitAndVerifyUserPointer(void **ppvSrc, void *pvDst) {

	unsigned char ucTester;
	__try {

		ucTester = *(unsigned char *)ppvSrc;
		ucTester = *(unsigned char *)pvDst;
	}
	__except (TRUE) {

		return CH_USER_POINTER_ERR;
	}
	this->pvTargetTemplate = ppvSrc;
	this->pvSrc = *ppvSrc;
	this->pvDst = pvDst;

	return CH_SUCCESS;
}

unsigned int CaptainHook::GetAlignedOpcodeForHook(unsigned int uiHookLen) {

	csh cshHandle;
	cs_insn *pInsn;
	unsigned int uiIndex;
	unsigned int uiCount;
	unsigned int uiSizeOfStolenOpcode;

	uiSizeOfStolenOpcode = 0;
	if (cs_open(CS_ARCH_X86, ARCH_MODE, &cshHandle) != CS_ERR_OK) {

		return ERR_CANNOT_RESOLVE_ASM;
	}
	uiCount = (unsigned int)cs_disasm(cshHandle, (unsigned char *)this->pvSrc, 0x50, 0x100, 0, &pInsn);
	if (uiCount > 0) {

		uiIndex = 0;
		while ((uiHookLen > uiSizeOfStolenOpcode) && (uiCount >= uiIndex)) {

			uiSizeOfStolenOpcode += pInsn[uiIndex++].size;
		}
	}
	else return ERR_CANNOT_RESOLVE_ASM;

	return uiSizeOfStolenOpcode;
}

unsigned int CaptainHook::GetAddressForSafeHook(unsigned int uiHookLen) {

	/*
	* this routine analyze the code flow and detect redirect to another function
	* this code work with AnalyzeStartOfCodeForSafePatch
	*/
	csh cshHandle;
	cs_insn *pInsn;
	unsigned int uiCount;
	unsigned int uiByteCounter;

	if (cs_open(CS_ARCH_X86, ARCH_MODE, &cshHandle) != CS_ERR_OK) {

		return ERR_CANNOT_RESOLVE_ASM;
	}
	uiCount = (unsigned int)cs_disasm(cshHandle, (unsigned char *)this->pvSrc, 0x50, 0x100, 0, &pInsn);
	if (uiCount >= uiHookLen) {

		uiByteCounter = 0;
		for (unsigned int uiIndex = 0; uiIndex < uiCount; uiIndex++) {

			char *pszInstStr = pInsn[uiIndex].mnemonic;
			if (pszInstStr[0] != *(unsigned char *)"j") {

				uiByteCounter += pInsn[uiIndex].size;
				if (uiByteCounter >= uiHookLen) {

					return 0;
				}
			}
			else {

			}
		}
	}
	return 0;
}

unsigned int CaptainHook::AnalyzeStartOfCodeForSafePatch(cs_insn *pInsn, unsigned int uiCount, unsigned int uiHookLen) {

	/*
	* this routine analyzes the code, and updates pvSrc for safe hook. for example:
	*	| kernel32.GetProcAddress     : mov r8,qword ptr ss:[rsp]
	*	| kernel32.GetProcAddress + 4 : jmp qword ptr ds:[<&GetProcAddressForCaller>]
	* in this situation hot patch destroy the function, cause GetProcAddress redirect to GetProcAddressForCaller.
	* in this situation this routine fix the source function to GetProcAddressForCaller. 
	*/
	for (unsigned int uiIndex = 0; uiIndex < uiCount; uiIndex++) {

		while (
			(uiIndex > uiHookLen) ||
			(pInsn[uiIndex].mnemonic[0] != *(char *)"j") || /*--detect jmp  instuction--*/
			(pInsn[uiIndex].mnemonic[0] != *(char *)"c")    /*--detect call instuction--*/
			) {

			uiIndex++;
		}
	}
	return 0;
}

unsigned int CaptainHook::BuildX86Hook(unsigned int uiSizeOfStolenOpcode) {

	// build trampoline from hookchain to real code.
	*((unsigned char *)this->pFunctionChain[this->uiFuncitonChainCounter].pEmulatedFunction + uiSizeOfStolenOpcode) = LONG_JMP;
	*((addr *)((unsigned char *)this->pFunctionChain[this->uiFuncitonChainCounter].pEmulatedFunction + uiSizeOfStolenOpcode + 1)) = (addr)this->pvSrc - (addr)this->pFunctionChain[this->uiFuncitonChainCounter].pEmulatedFunction - 5;

	// build trampoline from real code to hook function.
	*(unsigned char *)this->pvSrc = LONG_JMP;
	*((addr *)((unsigned char *)this->pvSrc + 1)) = (addr)this->pvDst - (addr)this->pvSrc - 5;


	return CH_SUCCESS;
}

unsigned int CaptainHook::BuildX64Hook(unsigned int uiSizeOfStolenOpcode) {

	/*
	* hook type for x64:
	* push 0
	* mov dword ptr ds:[rsp], (pvDst 0xffffffff)
	* mov dword ptr ds:[rsp + 4], (pvDst >> 0x20)
	* ret
	*/

	// build trampoline from hookchain to real code.
	*(unsigned short *)(this->pFunctionChain[this->uiFuncitonChainCounter].pEmulatedFunction + uiSizeOfStolenOpcode) = PUSH_0;
	*(unsigned short *)(this->pFunctionChain[this->uiFuncitonChainCounter].pEmulatedFunction + uiSizeOfStolenOpcode + 2) = MOV_RSP & 0xffff;
	*(this->pFunctionChain[this->uiFuncitonChainCounter].pEmulatedFunction + uiSizeOfStolenOpcode + 4) = MOV_RSP >> 0x10;
	*(unsigned int *)(this->pFunctionChain[this->uiFuncitonChainCounter].pEmulatedFunction + uiSizeOfStolenOpcode + 5) = (unsigned int)(((addr)this->pvSrc + uiSizeOfStolenOpcode) & 0xffffffff);
	*(unsigned int *)(this->pFunctionChain[this->uiFuncitonChainCounter].pEmulatedFunction + uiSizeOfStolenOpcode + 9) = MOV_RSP4;
	*(unsigned int *)(this->pFunctionChain[this->uiFuncitonChainCounter].pEmulatedFunction + uiSizeOfStolenOpcode + 13) = (unsigned int)(((addr)this->pvSrc + uiSizeOfStolenOpcode) >> 0x20);
	*(unsigned char *)(this->pFunctionChain[this->uiFuncitonChainCounter].pEmulatedFunction + uiSizeOfStolenOpcode + 17) = RET;

	// build trampoline from real code to hook function.
	*(unsigned short *)((unsigned char *)this->pvSrc) = PUSH_0;
	*(unsigned short *)((unsigned char *)this->pvSrc + 2) = MOV_RSP & 0xffff;
	*((unsigned char *)this->pvSrc + 4) = MOV_RSP >> 0x10;
	*(unsigned int *)((unsigned char *)this->pvSrc + 5) = (unsigned int)(((addr)(unsigned char *)this->pvDst) & 0xffffffff);
	*(unsigned int *)((unsigned char *)this->pvSrc + 9) = MOV_RSP4;
	*(unsigned int *)((unsigned char *)this->pvSrc + 13) = (unsigned int)(((addr)(unsigned char *)this->pvDst) >> 0x20);
	*(unsigned char *)((unsigned char *)this->pvSrc + 17) = RET;

	return CH_SUCCESS;
}
