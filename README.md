# CaptainHook (version 2.1 beta)

**this one isnt release, plz download from [here](https://github.com/shmuelyr/CaptainHook/releases)**

CaptainHook is a hook framework for x86/x64 arch, it's based on [capstone](https://github.com/aquynh/capstone) disassembler engine.
CaptainHook is easy to use, and very friendly.
The hook engine is much like MS Detours, so why to choose it?
* it supports x64 (Detours x64 is commerical - $10,000~).
* CaptainHook will know where to locate your hook in real time, the engine analyzes the code, and finds if small API redirection (Wow64 hook on kernelbase for example or some minimal JMP table redirection[particularly common in packed/protected code]) was occurred, and locate your hook in safe area.
* in the next release, CaptainHook will contain an engine for jmp/conditional jmp repair - if your hook corrupts sensitive code.

## whats new?
* Disable/Eneble hook at runtime, without remove them.
* some fix in the design of the code and the class.

code example:
```c++

#include "CaptainHook.h"
#pragma comment(lib, "CaptainHook.lib")

void (__fastcall *CH_OriginalFunction_1)(...) = OriginalFunction_1;
void (__stdcall  *CH_OriginalFunction_2)(...) = OriginalFunction_2;
void (__fastcall *CH_OriginalFunction_3)(...) = OriginalFunction_3;
void (__fastcall *CH_OriginalFunction_4)(...) = OriginalFunction_4;

int main() {

	unsigned int uiHookId1, uiHookId2;
    CaptainHook *pChook = new CaptainHook();
    if (!pChook) return 0;
    
	pChook->AddInlineHook(&(void *&)CH_OriginalFunction_1, HookedOriginalFunction_1);
	pChook->AddPageGuardHook(&(void *&)CH_OriginalFunction_2, HookedOriginalFunction_2);
    
	pChook->AddInlineHook(&(void *&)CH_OriginalFunction_3, HookedOriginalFunction_3, &uiHookId1);
	pChook->AddPageGuardHook(&(void *&)CH_OriginalFunction_4, HookedOriginalFunction_4, &uiHookId2);
	/*
	:
	*/
	pChook->DisableHook(uiHookId1);
	/*
	:
	*/
	pChook->EnableHook(uiHookId1);
	/*
	:
	*/
	pChook->~CaptainHook(); // this function clean all the hook(s).
    return 0;
}
```
CaptainHook.h for include is just [this](https://github.com/shmuelyr/CaptainHook/blob/master/CaptainHook/CaptainHook_for_include.h) file

### how to build?
```shell
> git clone --recursive https://github.com/shmuelyr/CaptainHook.git
> cd CaptainHook
> "C:\Program Files (x86)\Microsoft Visual Studio 12.0\Common7\Tools\vsvars32.bat"
> msbuild.exe
```

### in the next version:
* function that give you the power to disable/enable hook at runtime.
* IAT hooking, for dll function.
* hooking with hardware breakpoint.

### Full example:
```c++

#include <Windows.h>
#include "CaptainHook.h"

#pragma comment(lib, "CaptainHook.lib")

int(__stdcall *CH_OriginalMessageBoxA)
	(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) = MessageBoxA;
int __stdcall MyMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {

	return CH_OriginalMessageBoxA(hWnd, "HOOK", "HOOK", uType);
}

int WinMain(HINSTANCE hIns, HINSTANCE hPrev, LPSTR lpCmdLine, int cCmdShow) {
	
	unsigned int uiHookId;
	CaptainHook *pChook = new CaptainHook();
	pChook->AddPageGuardHook(&(void *&)CH_OriginalMessageBoxA, MyMessageBoxA, &uiHookId);
	MessageBoxA(NULL, "test", "test", MB_OK);
	pChook->DisableHook(uiHookId);
	MessageBoxA(NULL, "test", "test", MB_OK);
	pChook->EnableHook(uiHookId);
	MessageBoxA(NULL, "test", "test", MB_OK);
	return 0;
}
```


Happy Hooking!
