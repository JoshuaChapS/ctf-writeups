# write4

ROP Emporium · write4 · x86_64 · 30 Sep 2026

## The challenge

Same shape as callme — overflow, then call a function with an argument — but this time the
string I need to pass isn't sitting in the binary already. `print_file` wants a filename, and
nothing in write4 hands me "flag.txt" pre-made. I have to write it into memory myself before I
can point anything at it.

## Recon

    checksec write4       # NX enabled, No PIE, No canary, Partial RELRO

No PIE, no canary — same free pass as before. `info functions` gives me `print_file@plt` at
`0x400510`, a decoy `usefulFunction` (calls `print_file` on a hardcoded, useless string), and
`usefulGadgets`:

    mov QWORD PTR [r14], r15
    ret

One instruction, no chaining logic hidden in it — an arbitrary 8-byte write, if I can get an
address into `r14` and a value into `r15`. `usefulGadgets` doesn't hold the `pop`s for those,
though; those turned out to be inside `__libc_csu_init`: `pop r14; pop r15; ret` at `0x400690`,
and separately `pop rdi; ret` at `0x400693` for the final call.

## The vulnerability

Same stack overflow as every rung so far — unbounded read into a fixed buffer. Offset to the
return address is 40 (32 to saved `rbp`, +8), same number as callme, for the same structural
reason (standard `push rbp; mov rbp, rsp` frame).

## The exploit

The reasoning: I need `.bss` (writable, and fixed since there's no PIE) to hold my own copy of
"flag.txt", then call `print_file` pointed at it — arbitrary write, then a normal
ret2win-with-args call, chained together.

    payload  = b"A" * 40
    payload += p64(pop_r14_r15) + p64(bss_addr) + b"flag.txt" + p64(write_gadget)
    payload += p64(pop_rdi) + p64(bss_addr) + p64(print_file)

First line pops the destination (`.bss`) into `r14` and the raw 8 bytes of "flag.txt" into
`r15`; `write_gadget` performs the `mov` and lands cleanly back on `ret`. Second line reuses
the exact `pop rdi; ret` pattern from callme to set the argument, then jumps into `print_file`.
"flag.txt" is exactly 8 bytes, so this is one write, not a chain of them — a shorter string
would need more.

## What I tripped on

- Went hunting for the offset with `cyclic -l` in pwndbg on the captured `rbp` value and got
  back an offset around 28 million — obviously wrong for a stack buffer. pwndbg's `cyclic -l`
  defaults to an 8-byte lookup on a 64-bit target, but pwntools' `cyclic()` (no `context.arch`
  set) generates its pattern with a 4-byte period. Searching with only the first 4 bytes of the
  packed value (`cyclic_find(p64(value)[:4])`) gave the real answer: 32, so 40 to `rip`.
- Almost pointed my final call at `usefulFunction`'s address instead of `print_file@plt` — same
  trap as callme's decoy, different shape: this time it wasn't fake return values, it was a
  fake *target* sitting right next to the real one in the disassembly.

## What I learned

- An arbitrary-write primitive is just two gadgets working together: one that controls a memory
  write (`mov [reg], reg`), and `pop`s that load the address and the value into those exact
  registers. You're not looking for a string already in the binary — you're placing one
  yourself.
- `.bss` is the natural scratch space for this when there's no PIE: writable, and its address is
  fixed, so no leak needed.
- When packing with `cyclic()`/`cyclic_find()`, the pattern's period (4 vs 8 bytes) has to match
  on both ends — generation and lookup — or the offset is garbage, not just wrong.