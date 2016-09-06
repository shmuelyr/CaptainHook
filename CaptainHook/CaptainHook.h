#ifndef __CAPTAINHOOK_H__
#define __CAPTAINHOOK_H__

#include "Utils.h"

#ifdef __cplusplus
extern "C" {
#endif

	typedef struct _HOOK_CHAIN {

		unsigned char *pMem;
		unsigned int nSize;
	} HOOK_CHAIN, *PHOOK_CHAIN;

#pragma pack(1)
	class CaptainHook {

	private:
		void *pvSrc;
		void *pvDst;
		HOOK_CHAIN HookChain;
		void *pvTargetTemplate;
		unsigned short nHookLen;
		signed int CaptainHook::GetAddressForSafeHook();
		unsigned int CaptainHook::GetAlignedOpcodeForHook();
		signed int CaptainHook::InitializeHookType(unsigned short HookType);
		addr CaptainHook::CreateDistanceForLongJmpWithUpDirection(addr aFrom, addr aTo);		
		unsigned int CaptainHook::bSafeInitAndVerifyUserPointer(void **ppvSrc, void *pvDst);
		unsigned int CaptainHook::AnalyzeStartOfCodeForSafePatch(cs_insn *pInsn, unsigned int nCount);
		unsigned int CaptainHook::BuildX86Hook(unsigned int uiSizeOfStolenOpcode, unsigned short nHookType);
		unsigned int CaptainHook::BuildX64Hook(unsigned int uiSizeOfStolenOpcode, unsigned short nHookType);


	public:
		CaptainHook::CaptainHook(void **ppvSrc, void *pvDst, unsigned short HookType = 0);
		CaptainHook::~CaptainHook();
	};
#pragma pack()

#ifdef __cplusplus
}
#endif
#endif /* __CAPTAINHOOK_H__ */
