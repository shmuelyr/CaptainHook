#include "VectoredHandler.h"

/*Init Global data*/
std::vector<VECTOREXCPTION_RESOLVED> g_VectorHandlerList;

long HardwareBreakPointManager(PEXCEPTION_POINTERS pExceptionInfo) {

	if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
		
#if defined(_M_X64) || defined(__amd64__)

		addr aCurrentLocation = pExceptionInfo->ContextRecord->Rip
#elif _WIN32

		addr aCurrentLocation = pExceptionInfo->ContextRecord->Eip;
#endif
		for each(VECTOREXCPTION_RESOLVED Function in g_VectorHandlerList) {

			if (((addr)(Function.pfnOriginalFunction) == aCurrentLocation) && Function.pfnHookedFunction) {

#if defined(_M_X64) || defined(__amd64__)

				pExceptionInfo->ContextRecord->Rip = Function.pfnHookedFunction;
#elif _WIN32

				pExceptionInfo->ContextRecord->Eip = Function.pfnHookedFunction;
#endif
				break;
			}
		}
		pExceptionInfo->ContextRecord->EFlags |= 0x100; // set trap flag
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) {

		unsigned long ulOldProtect;

		for each(VECTOREXCPTION_RESOLVED Function in g_VectorHandlerList) {

			if (Function.pfnOriginalFunction) {

				VirtualProtect((void *)Function.pfnOriginalFunction, 4, PAGE_GUARD | PAGE_EXECUTE_READWRITE, &ulOldProtect);
			}
		}
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else return EXCEPTION_CONTINUE_SEARCH;
}

