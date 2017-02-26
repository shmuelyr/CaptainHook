#ifndef __CAPTAINHOOK_H__
#define __CAPTAINHOOK_H__

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
		CH_ALLOC_ERR,
		CH_VIRTUALPROTECT_ERR,
	};
	typedef struct _HOOK_INF {

		unsigned char *pOriginalFunction;
		unsigned char *pEmulatedFunction;
		unsigned char *pDestFunction;
		unsigned int uiHookSize;
		unsigned int uiId;
		unsigned int uiGlobalSize;
	} HOOK_INF, *PHOOK_INF;

#pragma pack(1)
	class CaptainHook {

	private:

		void *pVectorHandle;
		unsigned int uiInternalCounter;
		std::vector<HOOK_INF> FunctionList;
		std::vector<VECTOREXCPTION_RESOLVED> DisabledPGHookList;
		unsigned int CaptainHook::BuildX86Hook(HOOK_INF *pFunction);
		unsigned int CaptainHook::BuildX64Hook(HOOK_INF *pFunction);
		unsigned int CaptainHook::bVerifyUserPointer(void **ppvSrc, void *pvDst);
		unsigned int CaptainHook::CalcAlignedSizeForHook(void *pvSrc, unsigned int uiHookLen);

	public:
		CaptainHook::CaptainHook();
		CaptainHook::~CaptainHook();
		unsigned int CaptainHook::DisableHook(unsigned int uiHookId);
		unsigned int CaptainHook::EnableHook(unsigned int uiHookId);
		unsigned int CaptainHook::AddInlineHook(void **ppvSrc, void *pvDst);
		unsigned int CaptainHook::AddPageGuardHook(void **ppvSrc, void *pvDst);
		unsigned int CaptainHook::AddInlineHook(void **ppvSrc, void *pvDst, unsigned int *puiHookId);
		unsigned int CaptainHook::AddPageGuardHook(void **ppvSrc, void *pvDst, unsigned int *puiHookId);

	};
#pragma pack()

#ifdef __cplusplus
}
#endif
#endif /* __CAPTAINHOOK_H__ */
