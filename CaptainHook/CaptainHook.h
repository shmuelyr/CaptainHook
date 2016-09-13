#ifndef __CAPTAINHOOK_H__
#define __CAPTAINHOOK_H__

#include "Utils.h"
#include "VectoredHandler.h"

#ifdef __cplusplus
extern "C" {
#endif

	typedef enum CH_ERROR {

		CH_SUCCESS,
		CH_USER_POINTER_ERR,
		CH_VECTOR_HANDLE_ERR,
		Ch_MAX_GUARDPAGE_ERR,
		CH_VPROTECT_ERR,
		CH_CAPSTONE_ASM_ERR,
		Ch_ALLOC_ERR,
		CH_VIRTUALPROTECT_ERR
	};
	typedef struct _FUNCTION_CHAIN {

		unsigned char *pOriginalFunction;
		unsigned char *pEmulatedFunction;
		unsigned int uiHookSize;
		unsigned int uiGlobalSize;
	} FUNCTION_CHAIN, *PFUNCTION_CHAIN;

#pragma pack(1)
	class CaptainHook {

	private:
		void *pvSrc;
		void *pvDst;
		
		void *pVectorHandle;
		void *pvTargetTemplate;
		PFUNCTION_CHAIN pFunctionChain;
		unsigned int uiFuncitonChainSize;
		unsigned int uiFuncitonChainCounter;
		unsigned int CaptainHook::GetAddressForSafeHook(unsigned int uiHookLen);
		unsigned int CaptainHook::GetAlignedOpcodeForHook(unsigned int uiHookLen);
		unsigned int CaptainHook::BuildX86Hook(unsigned int uiSizeOfStolenOpcode);
		unsigned int CaptainHook::BuildX64Hook(unsigned int uiSizeOfStolenOpcode);
		addr CaptainHook::CreateDistanceForLongJmpWithUpDirection(addr aFrom, addr aTo);		
		unsigned int CaptainHook::bSafeInitAndVerifyUserPointer(void **ppvSrc, void *pvDst);
		unsigned int CaptainHook::AnalyzeStartOfCodeForSafePatch(cs_insn *pInsn, unsigned int nCount, unsigned int uiHookLen);

	public:
		CaptainHook::CaptainHook();
		CaptainHook::~CaptainHook();
		unsigned int CaptainHook::AddInlineHook(void **ppvSrc, void *pvDst);
		unsigned int CaptainHook::AddPageGuardHook(void **ppvSrc, void *pvDst);

	};
#pragma pack()

#ifdef __cplusplus
}
#endif
#endif /* __CAPTAINHOOK_H__ */
