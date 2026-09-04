# callme

ROP Emporium · callme · x86_64 · 5 Sep 2026

## The challenge

I have to call three functions — `callme_one`, `callme_two`, `callme_three` — in that order,
each with the same three arguments, from a stack overflow. It's ret2win with arguments, times
three. The new thing over split: three arguments means three registers, and three calls chained
back to back instead of one.

## Recon

    checksec callme       # NX enabled, No PIE, No canary

No PIE → fixed addresses, no leak. `info functions` gives me the PLT stubs `callme_one/two/three`
and two locals: `usefulFunction` and `usefulGadgets`. Disassembling:

- `pwnme` does `read(0, buf, 0x200)` into a 32-byte buffer at `[rbp-0x20]`. Unbounded overflow.
- `usefulGadgets` is exactly `pop rdi ; pop rsi ; pop rdx ; ret` at 0x40093c — one gadget that
  sets all three argument registers at once.
- `usefulFunction` shows a calling pattern... which turns out to be bait (see below).

## The vulnerability

`read` of 0x200 bytes into a 32-byte buffer. The return address is at 32 (buffer) + 8 (saved RBP)
= offset 40. Standard overflow — the challenge is the calling convention, not the bug.

## The exploit

Three args in x86_64 go in RDI, RSI, RDX (1st, 2nd, 3rd). Split only used RDI; here I set all
three with the one `pop rdi; pop rsi; pop rdx; ret` gadget. So one call is: gadget, then the
three values, then the function. I chain that three times, one → two → three:

    payload  = b"A"*40
    payload += p64(gadget) + p64(a1)+p64(a2)+p64(a3) + p64(callme_one)
    payload += p64(gadget) + p64(a1)+p64(a2)+p64(a3) + p64(callme_two)
    payload += p64(gadget) + p64(a1)+p64(a2)+p64(a3) + p64(callme_three)

The args are `0xdeadbeefdeadbeef`, `0xcafebabecafebabe`, `0xd00df00dd00df00d` (from the README).
I pulled the gadget with `elf.symbols["usefulGadgets"]` — it's defined in the binary, so `symbols`,
not `plt`; the `callme_*` are external, so those are `plt`. Full script in `exploit.py`. Flag dropped.

## What I tripped on

- `usefulFunction` is a decoy. It calls them three → two → one with args 4, 5, 6 — none of which is
  the answer. The real order is one → two → three and the real args are in the README. If you trust
  the decompilation over the instructions, it fails. The whole challenge is basically "do you read
  the binary or the brief."

## What I learned

- Passing multiple arguments in 64-bit ROP is just multiple registers — RDI, RSI, RDX in convention
  order — and one `pop rdi; pop rsi; pop rdx; ret` fills them in a single move.
- Chaining function calls is the same step repeated: set the registers, call, set the registers, call.
  A ROP chain of calls is just "set regs, call, repeat" — the calling convention *is* the API.
- `elf.plt` for external/libc functions, `elf.symbols` for anything defined in the binary. Same rule
  as split, now for a gadget symbol.
