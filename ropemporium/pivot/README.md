# pivot

ROP Emporium · pivot · x86_64 · 1 Oct 2026

## The challenge

Same shape as every ROP Emporium binary — overflow a buffer, control `rip` — except the overflow
here is deliberately too small to hold a real chain. `main` also `malloc`s a 16MB buffer and prints
a pointer into it before asking for anything. Win condition: `ret2win`, which lives inside a
separate shared library, `libpivot.so`, loaded at a randomized address.

## Recon

    checksec pivot          # NX enabled, No PIE, No canary, Partial RELRO (main binary only)

`pwnme` does two `read()` calls back to back. Reading the `edx` value set right before each call
in gdb shows the actual size limits: `0x100` (256 bytes) for the first, into the heap pointer just
printed; `0x40` (64 bytes) for the second, into a 32-byte local buffer. `main`'s own disassembly
confirms the printed pointer: `malloc(0x1000000)` then `+ 0xffff00`, passed straight into `pwnme`.

## The vulnerability

Standard stack buffer overflow on the second `read()` — offset 40 to the saved return address
(32-byte buffer + 8-byte saved `rbp`, both read directly off the `memset(buf, 0, 0x20)` and
`lea rax, [rbp-0x20]` in the disassembly). The actual problem isn't the overflow itself, it's the
budget: `0x40` total, so only 24 bytes/3 gadget slots survive the 40-byte pad — nowhere near enough
to resolve a GOT entry, dereference it, add an offset, and call it.

## The exploit

Two chains, sent in the order the program's two `read()` calls ask for them — which is backwards
from the order they execute in.

`chain2` (sent second, runs first) is the actual stack smash, and it does the minimum: load the
heap pointer into `rax` and swap it into `rsp`.

    chain2 = b"A"*40 + pop_rax + pivot_addr + xchg_rsp_rax

That's exactly 64 bytes — no room to spare. The `ret` baked into the `xchg` gadget is what does the
jump: once `rsp` points at the heap, that `ret` pops the first qword sitting there, landing in
`chain1`.

`chain1` (sent first, into the heap, sits passively until the pivot above reaches it) does the real
work:

    chain1 = foothold_plt + pop_rax + got_foothold + deref_rax + pop_rbp + offset_0x117 + add_rax_rbp + call_rax

Calling `foothold_function@plt` isn't about what the function does — it's the only way to force the
dynamic linker to resolve its real address and write it into its GOT slot (`0x601040`, found with
pwndbg's `got` command). Once that's resolved, dereferencing that slot gives `foothold_function`'s
real runtime address inside `libpivot.so`. `ret2win` sits a fixed `0x117` bytes further into the
same library (found earlier by diffing the two symbols' addresses), so adding that offset and
calling the result lands on `ret2win` regardless of where ASLR actually put the library this run.

## What I tripped on

- First draft of the plan put the `foothold_function@plt` call inside `chain2` instead of `chain1`.
  Totaling the bytes (`40 + 8*4 = 72`) against the real 64-byte ceiling on that `read()` is what
  caught it before it was ever run — moving the call into `chain1`, which has 256 bytes of room,
  fixed it.
- Assumed the heap pointer `pwnme` prints would be stable across runs since the main binary has no
  PIE. It isn't — that `malloc(0x1000000)` is large enough that glibc serves it straight from
  `mmap`, which is ASLR'd independently of the binary's own load address. Confirmed by running the
  binary directly (not under gdb, which disables ASLR by default) a few times and watching the
  printed address change. Parsed it fresh from the banner every run instead of hardcoding it.

## What I learned

- Gadget budget has to be checked against the actual `read()` size (the `edx` value at the call
  site), not just against the offset to `rip` — a gadget that doesn't fit the smaller buffer has to
  move to whichever one has the room.
- `rsp` is just a register, not a fixed memory region — the CPU always treats wherever `rsp` points
  as "the stack" for `push`/`pop`/`call`/`ret`. A stack pivot is nothing more than lying to that one
  register.
- Any address leaked at runtime (heap, stack, or a library base) has to be re-parsed from the
  program's own output every connection — gdb's default ASLR-off setting can make a randomized
  value look deceptively constant while debugging.