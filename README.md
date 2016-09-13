# CaptainHook (version 2.0 beta)

CaptainHook is a hook framework for x86/x64 arch, it's based on [capstone](https://github.com/aquynh/capstone) disassembler engine. CaptainHook is equipped with smart engine (TO FINISH).
CaptainHook is easy to use, and very friendly.
The hook engine is much like MS Detours, so why to choose it?
* it supports x64 (Detours x64 is commerical - $10,000~).
* CaptainHook will know where to locate your hook in real time, it analyzes the code, and finds if small API redirection (Wow64 hook on kernelbase for example, or on protector like VMP or Themida) was occurred, determine if there is a room for our hook.
* in the next release, CaptainHook will contain an engine for jmp/conditional jmp repair - if your hook corrupts sensitive code.

## whats new?
* the new version including page guard hook mechanism and allow you to hook function without really patch(!)
* some fix in the design of the code and the class.

code example:
```c++
#include "CaptainHook.h"
#pragma comment(lib, "CaptainHook.lib")

void (__fastcall *CH_OriginalFunction_1)(...) = OriginalFunction_1;
void (__stdcall  *CH_OriginalFunction_2)(...) = OriginalFunction_2;

int main() {

    CaptainHook *pChook = new CaptainHook();
    if (!pChook) return 0;
    
	pChook->AddInlineHook(&(void *&)CH_OriginalFunction_1, HookedOriginalFunction_1);
	pChook->AddPageGuardHook(&(void *&)CH_OriginalFunction_2, HookedOriginalFunction_2);
    
	pChook->~CaptainHook(); // this function clean all the hook(s).
    return 0;
}
```
#### in the next version:
* function that give you the power to disable/enable hook at runtime.
* IAT hooking, for dll function.
* hooking with hardware breakpoint.

### how to build?
```shell
> git clone --recursive https://github.com/shmuelyr/CaptainHook.git
> cd CaptainHook
> "C:\Program Files (x86)\Microsoft Visual Studio 12.0\Common7\Tools\vsvars32.bat"
> msbuild.exe
```

Happy Hooking!
