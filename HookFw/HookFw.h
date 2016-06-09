#ifndef __HOOKFW_H__
#define __HOOKFW_H__

#include "Utils.h"

#ifdef __cplusplus
extern "C" {
#endif

	typedef struct _HOOK_CHAIN {

		unsigned char *pMem;
		unsigned int nSize;
	} HOOK_CHAIN, *PHOOK_CHAIN;

#pragma pack(1)
	class HookFw {

	private:
		void *pvSrc;
		void *pvDst;
		HOOK_CHAIN HookChain;
		void *pvTargetTemplate;
		unsigned short nHookLen;
		signed int HookFw::GetAddressForSafeHook();
		unsigned int HookFw::GetAlignedOpcodeForHook();
		signed int HookFw::InitializeHookType(unsigned short HookType);
		addr HookFw::CreateDistanceForLongJmpWithUpDirection(addr aFrom, addr aTo);		
		unsigned int HookFw::bSafeInitAndVerifyUserPointer(void **ppvSrc, void *pvDst);
		unsigned int HookFw::AnalyzeStartOfCodeForSafePatch(cs_insn *pInsn, unsigned int nCount);
		unsigned int HookFw::BuildX86Hook(unsigned int uiSizeOfStolenOpcode, unsigned short nHookType);
		unsigned int HookFw::BuildX64Hook(unsigned int uiSizeOfStolenOpcode, unsigned short nHookType);


	public:
		HookFw::HookFw(void **ppvSrc, void *pvDst, unsigned short HookType = 0);
		HookFw::~HookFw();
	};
#pragma pack()

#ifdef __cplusplus
}
#endif
#endif /* __HOOKFW_H__ */