# HookFw

Hooking framwork is x86/x64 hooking lib, it's based on [capstone](https://github.com/aquynh/capstone) disassembler engine.
HookFw equipped with smart engine.

TODO : finish the smart engine to enable hot patch on jmp instruction - with all conditional jmp

TODO : Finish code analysis for function redirect (on x64 its very common)

Currently, HookType contain one type - jmp hook. in the next version i will add a PageGuard hook and more.
