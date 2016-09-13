#ifndef __CAPTAINHOOK_H__
#define __CAPTAINHOOK_H__

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(1)
	class CaptainHook {

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
