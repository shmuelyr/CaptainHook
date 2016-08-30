# CaptainHook

CaptainHook is a hook framework for x86/x64 arch, it's based on [capstone](https://github.com/aquynh/capstone) disassembler engine. CaptainHook is equipped with smart engine (TO FINISH).
CaptainHook is easy to use, and very friendly.
The hook engine is much like MS Detours, so why to choose it?
* it supports x64 (Detours x64 is commerical - $10,000~).
* CaptainHook will know where to locate your hook in real time, it analyzes the code, and finds if small API redirection (Wow64 hook on kernelbase for example, or on protector like VMP or Themida) was occurred.
* in the next release, CaptainHook will contain an engine for jmp/conditional jmp repair - if your hook corrupts sensitive code.
* in the next release, CaptainHook will contain more hook types, like PageGuard hooking etc...

code example:
```c++
#inclide "CaptainHook.h"

void (__fastcall *CH_OriginalFunction)(...) = OriginalFunction;

int main() {

    CaptainHook *pChook = new CaptainHook(&(void *&)CH_OriginalFunction, HookedOriginalFunction);
    Sleep(100);
    pChook->~CaptainHook();
    return 0;
}
```
TODO :
* Finish the smart engine to enable hot patching on jmp instruction - with all conditional jmp.
* Finish code analysis for function redirection (on x64 its very common).

Happy Hooking!
