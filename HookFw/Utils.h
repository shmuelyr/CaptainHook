#ifndef __VARIABLES_H__
#define __VARIABLES_H__

#include <windows.h>
#include <stdio.h>
#include "capstone-3.0.4\include\capstone.h"

#define LONG_JMP 0xe9
#define PUSH_0   0x006a
#define MOV_RSP  0x2404c7
#define MOV_RSP4 0x042444c7
#define RET      0xc3

#define LEN_JMPABS   5
#define LEN_PUSH_RAX 1
#define LEN_MOVABS   10
#define LEN_JMP_RAX  2

#define ERR_SUCCESS 0
#define ERR_ERROR   1
#define ERR_CANNOT_RESOLVE_ASM 0xffffffff
#define HOOK_TYPE_NOT_SUPPORTED -2

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_M_X64) || defined(__amd64__)
	
	typedef unsigned long long addr;
	#define __addr__ "%ll"
	#define ARCH_MODE CS_MODE_64
#elif _WIN32
	
	typedef unsigned long addr;
	#define __addr__ "l"	
	#define ARCH_MODE CS_MODE_32
#endif

	enum HookLen{
#if defined(_M_X64) || defined(__amd64__)
	
		JMP_HOOKTYPE_LEN = 18,
#elif _WIN32
		
		JMP_HOOKTYPE_LEN = LEN_JMPABS,
#endif
	}; /* HookLen */

	enum HookType {

		JMP_TYPE = 0,
	};


#ifdef __cplusplus
}
#endif

#endif /*__VARIABLES_H__*/