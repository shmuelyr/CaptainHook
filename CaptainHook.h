#ifndef __CAPTAINHOOK_H__
#define __CAPTAINHOOK_H__

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(1)
	class CaptainHook {
	
	private:
		void *pvSrc;
		void *pvDst;

		void *pVectorHandle;
		void *pvTargetTemplate;
		void *pFunctionChain;
		unsigned int uiFuncitonChainSize;
		unsigned int uiFuncitonChainCounter;
		unsigned int CaptainHook::GetAddressForSafeHook(unsigned int uiHookLen);
		unsigned int CaptainHook::GetAlignedOpcodeForHook(unsigned int uiHookLen);
		unsigned int CaptainHook::BuildX86Hook(unsigned int uiSizeOfStolenOpcode);
		unsigned int CaptainHook::BuildX64Hook(unsigned int uiSizeOfStolenOpcode);
		void *CaptainHook::CreateDistanceForLongJmpWithUpDirection(void *aFrom, void *aTo);
		unsigned int CaptainHook::bSafeInitAndVerifyUserPointer(void **ppvSrc, void *pvDst);
		unsigned int CaptainHook::AnalyzeStartOfCodeForSafePatch(void *pInsn, unsigned int nCount, unsigned int uiHookLen);
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
