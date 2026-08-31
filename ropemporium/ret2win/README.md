# ret2win

ROP Emporium · ret2win · x86_64 · 31 Aug 2026

## The challenge

There's a `ret2win()` that cats the flag, but nothing calls it. Overflow the buffer,
overwrite the saved return address with its address, done. First 64-bit one after the
picoCTF stack overflows, so the point was the x86_64 differences.

## Recon

    checksec ret2win     # NX enabled, No PIE, No canary

No PIE means fixed addresses — no leak needed. The binary tells me itself: "56 bytes into a
32 byte buffer." `ret2win` is at 0x400756.

## The vulnerability

`read()` with no bounds on a 32-byte buffer. The return address sits at 32 + 8 = offset 40.
The +8 is the saved RBP — 8 bytes in 64-bit, not 4.

## The exploit

    payload = b"A" * 40 + p64(elf.symbols["ret2win"])

`p64`, not `p32` — the other 64-bit change. Sent it, flag came back.

## What I tripped on

It printed the flag and then SIGSEGV'd, which looked like a fail until I read the order —
the flag already came out. `ret2win` cats the flag, then rets into the garbage after my
payload and dies. The crash is after the win, so it doesn't matter.

## What I learned

16-byte stack alignment, even though the binary let me skip it. `system()` uses `movaps`,
which faults if the stack isn't 16-aligned when it runs. Compiled code always is; a
hand-built ROP stack isn't, and mine landed right by luck. The fix when it doesn't: a bare
`ret` gadget before the win address burns 8 bytes and flips the alignment. But it's a
toggle — add it to an already-aligned stack and you break a working exploit. So try
without, add the `ret` only if `movaps` segfaults. split calls `system` too, so that's
where I'll probably meet it.
