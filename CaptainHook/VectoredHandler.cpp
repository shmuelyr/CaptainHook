#include "VectoredHandler.h"

/*Init Global data*/

VECTOREXCPTION_RESOLVED g_VectorHandlerChain[256] = { 0 };
unsigned int g_uiVectorHandlerMaxChainSize = 256;
unsigned int g_uiVectorHandlerChainSize = 0;

LONG PageGuardExceptionManager(PEXCEPTION_POINTERS pExceptionInfo) {

	if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
		
#if defined(_M_X64) || defined(__amd64__)

		addr aCurrentLocation = pExceptionInfo->ContextRecord->Rip
#elif _WIN32

		addr aCurrentLocation = pExceptionInfo->ContextRecord->Eip;
#endif
		for (unsigned int uiIndex = 0; uiIndex < g_uiVectorHandlerChainSize; uiIndex++) {
			
			if (((addr)(g_VectorHandlerChain[uiIndex].pfnOriginalFunction) == aCurrentLocation) &&
				g_VectorHandlerChain[uiIndex].pfnHookedFunction) {

#if defined(_M_X64) || defined(__amd64__)

					pExceptionInfo->ContextRecord->Rip = g_VectorHandlerChain[uiIndex].pfnHookedFunction;
#elif _WIN32

					pExceptionInfo->ContextRecord->Eip = g_VectorHandlerChain[uiIndex].pfnHookedFunction;
#endif
					break;
				}
			}
		
		pExceptionInfo->ContextRecord->EFlags |= 0x100;
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) {

		unsigned long ulOldProtect;

		for (unsigned int uiIndex = 0; uiIndex < g_uiVectorHandlerChainSize; uiIndex++) {

			if (g_VectorHandlerChain[uiIndex].pfnOriginalFunction) {

				VirtualProtect((void *)g_VectorHandlerChain[uiIndex].pfnOriginalFunction, 4, PAGE_GUARD | PAGE_EXECUTE_READWRITE, &ulOldProtect);
			}
		}
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else return EXCEPTION_CONTINUE_SEARCH;
}

