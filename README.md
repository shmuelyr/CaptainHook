# CaptainHook

CaptainHook is a hooking framwork for x86/x64 arch, it's based on the [capstone](https://github.com/aquynh/capstone) disassembler engine. CaptainHook equipped with smart engine (TO FINISH).
CaptainHook is easy to use, and very friendly.
The hook engine is very similar too MS Detours, so why choose CaptainHook?
* it supports x64. (Detours x64 is commerical - $10,000~)
* CaptainHook will know where too locate your hook in real time, it analyzes the code, and finds if a small API redirection (Wow64 hook on kernelbase for example, or on protector like VMP or Themida) has occurred.
* in the next release, CaptainHook will contain an engine for jmp/conditional jmp repairing - if you hook corrupt, sensitive code.
* in the next release, CaptainHook will contain more hook types, like PageGuard hooking, etc.

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
* Finish the smart engine to enable hot patching on jmp instructions - with all conditional jmps
* Finish code analysis for function redirect (on x64 its very common)

Happy Hooking!
