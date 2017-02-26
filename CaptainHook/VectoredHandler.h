
#ifndef __VECTOREDHANDLER_H__
#define __VECTOREDHANDLER_H__

#include <Windows.h>
#include "Utils.h"

#ifdef __cplusplus
extern "C" {
#endif

	typedef struct _VECTOREXCPTION_RESOLVED {
		
		unsigned int uiHookId;
		addr pfnOriginalFunction;
		addr pfnHookedFunction;

	} VECTOREXCPTION_RESOLVED, *PVECTOREXCPTION_RESOLVED;

	extern std::vector<VECTOREXCPTION_RESOLVED> g_VectorHandlerList;
	
	long HardwareBreakPointManager(PEXCEPTION_POINTERS pExceptionInfo);

#ifdef __cplusplus
}
#endif

#endif /* __VECTOREDHANDLER_H__ */
