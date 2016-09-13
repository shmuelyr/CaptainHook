
#ifndef __VECTOREDHANDLER_H__
#define __VECTOREDHANDLER_H__

#include <Windows.h>
#include "Utils.h"

#ifdef __cplusplus
extern "C" {
#endif

	typedef struct _VECTOREXCPTION_RESOLVED {
		addr pfnOriginalFunction;
		addr pfnHookedFunction;

	} VECTOREXCPTION_RESOLVED, *PVECTOREXCPTION_RESOLVED;

	extern VECTOREXCPTION_RESOLVED g_VectorHandlerChain[256];
	extern unsigned int g_uiVectorHandlerMaxChainSize;
	extern unsigned int g_uiVectorHandlerChainSize;

	LONG PageGuardExceptionManager(PEXCEPTION_POINTERS pExceptionInfo);

#ifdef __cplusplus
}
#endif

#endif /* __VECTOREDHANDLER_H__ */
