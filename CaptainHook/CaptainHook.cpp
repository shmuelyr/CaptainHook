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
CaptainHook::CaptainHook(void **ppvSrc, void *pvDst, unsigned short nHookType) {

	unsigned int uiSizeOfStolenOpcode;
	unsigned long ulOldProtect;

	if (bSafeInitAndVerifyUserPointer(ppvSrc, pvDst) == ERR_ERROR) return;

	if (InitializeHookType(nHookType) == ERR_ERROR) return;

	GetAddressForSafeHook();

	uiSizeOfStolenOpcode = GetAlignedOpcodeForHook();

	if (uiSizeOfStolenOpcode == ERR_CANNOT_RESOLVE_ASM) {

		printf("disassembly parser fail\n");
		return;
	}
	this->HookChain.nSize = uiSizeOfStolenOpcode + HookLen::JMP_HOOKTYPE_LEN;
	VirtualProtect(this->pvSrc, uiSizeOfStolenOpcode, PAGE_EXECUTE_READWRITE, &ulOldProtect);
	this->HookChain.pMem = (unsigned char *)VirtualAlloc(NULL, this->HookChain.nSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(this->HookChain.pMem, this->pvSrc, uiSizeOfStolenOpcode);

#if defined(_M_X64) || defined(__amd64__)
	
	BuildX64Hook(uiSizeOfStolenOpcode, nHookType);
#elif _WIN32

	BuildX86Hook(uiSizeOfStolenOpcode, nHookType);
#endif

	// redirect template function to emulated code.
	*(addr *)this->pvTargetTemplate = (addr)HookChain.pMem;
	FlushInstructionCache(GetCurrentProcess(), this->pvSrc, uiSizeOfStolenOpcode);

}

CaptainHook::~CaptainHook() {

	memcpy(this->pvSrc, this->HookChain.pMem, this->HookChain.nSize - HookLen::JMP_HOOKTYPE_LEN);
	VirtualFree(this->HookChain.pMem, this->HookChain.nSize, MEM_DECOMMIT);
}

unsigned int CaptainHook::bSafeInitAndVerifyUserPointer(void **ppvSrc, void *pvDst) {

	unsigned char ucTester;
	__try {

		ucTester = *(unsigned char *)ppvSrc;
		ucTester = *(unsigned char *)pvDst;
	}
	__except (TRUE) {

		return ERR_ERROR;
	}
	this->pvTargetTemplate = ppvSrc;
	this->pvSrc = *ppvSrc;
	this->pvDst = pvDst;

	return ERR_SUCCESS;
}

unsigned int CaptainHook::GetAlignedOpcodeForHook() {

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
		while ((this->nHookLen > uiSizeOfStolenOpcode) && (uiCount >= uiIndex)) {

			uiSizeOfStolenOpcode += pInsn[uiIndex++].size;
		}
	}
	else return ERR_CANNOT_RESOLVE_ASM;

	return uiSizeOfStolenOpcode;
}

signed int CaptainHook::InitializeHookType(unsigned short nHookType) {

	switch (nHookType) {

	case HookType::JMP_TYPE:
		this->nHookLen = HookLen::JMP_HOOKTYPE_LEN;
		break;
	default:
		return HOOK_TYPE_NOT_SUPPORTED;
	}
	return ERR_SUCCESS;
}

signed int CaptainHook::GetAddressForSafeHook() {

	/*
	* this routine analyze the code flow and detect redirect  to another function
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
	if (uiCount >= this->nHookLen) {

		uiByteCounter = 0;
		for (unsigned int uiIndex = 0; uiIndex < uiCount; uiIndex++) {

			char *pszInstStr = pInsn[uiIndex].mnemonic;
			if ((pszInstStr[0] != *(unsigned char *)"j") || (pszInstStr[0] != *(char *)"c")) {

				uiByteCounter += pInsn[uiIndex].size;
				if (uiByteCounter >= this->nHookLen) {

					return 0;
				}
			}
			else {

			}
		}
	}
	return 0;
}

unsigned int CaptainHook::AnalyzeStartOfCodeForSafePatch(cs_insn *pInsn, unsigned int uiCount) {

	/*
	* this routin analyze the code, and update pvSrc for safe hook. for example:
	*	| kernel32.GetProcAddress     : mov r8,qword ptr ss:[rsp]
	*	| kernel32.GetProcAddress + 4 : jmp qword ptr ds:[<&GetProcAddressForCaller>]
	* in this situation hot patch destroy the function, cause GetProcAddress redirect to GetProcAddressForCaller.
	* in this situation this routine fix the source function to GetProcAddressForCaller. 
	*/
	for (unsigned int uiIndex = 0; uiIndex < uiCount; uiIndex++) {

		while (
			(uiIndex > this->nHookLen) ||
			(pInsn[uiIndex].mnemonic[0] != *(char *)"j") || /*--detect jmp  instuction--*/
			(pInsn[uiIndex].mnemonic[0] != *(char *)"c")    /*--detect call instuction--*/
			) {

			uiIndex++;
		}
	}
}

unsigned int CaptainHook::BuildX86Hook(unsigned int uiSizeOfStolenOpcode, unsigned short nHookType) {

	// build trampoline from hookchain to real code.
	*((unsigned char *)this->HookChain.pMem + uiSizeOfStolenOpcode) = LONG_JMP;
	*((addr *)((unsigned char *)this->HookChain.pMem + uiSizeOfStolenOpcode + 1)) = (addr)this->pvSrc - uiSizeOfStolenOpcode - ((addr)this->HookChain.pMem + uiSizeOfStolenOpcode) + 5;

	// build trampoline from real code to hook function.
	*(unsigned char *)this->pvSrc = LONG_JMP;
	*((addr *)((unsigned char *)this->pvSrc + 1)) = (addr)this->pvDst - (addr)this->pvSrc - 5;


	return 0;
}

unsigned int CaptainHook::BuildX64Hook(unsigned int uiSizeOfStolenOpcode, unsigned short nHookType) {

	/*
	* hook type for x64:
	* push 0
	* mov dword ptr ds:[rsp], (pvDst 0xffffffff)
	* mov dword ptr ds:[rsp + 4], (pvDst >> 0x20)
	* ret
	*/
	
	// build trampoline from hookchain to real code.
	*(unsigned short *)(this->HookChain.pMem + uiSizeOfStolenOpcode) = PUSH_0;
	*(unsigned short *)(this->HookChain.pMem + uiSizeOfStolenOpcode + 2) = MOV_RSP & 0xffff;
	*(this->HookChain.pMem + uiSizeOfStolenOpcode + 4) = MOV_RSP >> 0x10;
	*(unsigned int *)(this->HookChain.pMem + uiSizeOfStolenOpcode + 5) = (unsigned int)(((addr)this->pvSrc + uiSizeOfStolenOpcode) & 0xffffffff);
	*(unsigned int *)(this->HookChain.pMem + uiSizeOfStolenOpcode + 9) = MOV_RSP4;
	*(unsigned int *)(this->HookChain.pMem + uiSizeOfStolenOpcode + 13) = (unsigned int)(((addr)this->pvSrc + uiSizeOfStolenOpcode) >> 0x20);
	*(unsigned char *)(this->HookChain.pMem + uiSizeOfStolenOpcode + 17) = RET;

	// build trampoline from real code to hook function.
	*(unsigned short *)((unsigned char *)this->pvSrc) = PUSH_0;
	*(unsigned short *)((unsigned char *)this->pvSrc + 2) = MOV_RSP & 0xffff;
	*((unsigned char *)this->pvSrc + 4) = MOV_RSP >> 0x10;
	*(unsigned int *)((unsigned char *)this->pvSrc + 5) = (unsigned int)(((addr)(unsigned char *)this->pvDst) & 0xffffffff);
	*(unsigned int *)((unsigned char *)this->pvSrc + 9) = MOV_RSP4;
	*(unsigned int *)((unsigned char *)this->pvSrc + 13) = (unsigned int)(((addr)(unsigned char *)this->pvDst) >> 0x20);
	*(unsigned char *)((unsigned char *)this->pvSrc + 17) = RET;

	return 0;
}