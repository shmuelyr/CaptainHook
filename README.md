# CaptainHook

CaptainHook is hooking framwork for x86/x64 arch, it's based on [capstone](https://github.com/aquynh/capstone) disassembler engine. CaptainHook equipped with smart engine (TO FINISH).
CaptainHook is easy to using, and very freandly.
the hook engine is much like MS Detours, so why to choose it?
* its support x64 (Detours x64 is commerical - $10,000~)
* CaptainHook will know where to locate your hook in real time, its analyize the code, and find if small API redirection (Wow64 hook on kernelbase for example, or on protector like VMP or Themida) was occurred
* in the next release, CaptainHook will contain an engine for jmp/conditional jmp repair - if your hook corrupt sensitive code
* in the next release, CaptainHook will contain more hook type, like PageGuard hooking etc.

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
* Finish the smart engine to enable hot patch on jmp instruction - with all conditional jmp
* Finish code analysis for function redirect (on x64 its very common)

Happy Hooking!
