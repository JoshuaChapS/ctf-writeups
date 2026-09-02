# split

ROP Emporium · split · x86_64 · 2 Sep 2026

## The challenge

There's a `system()` call sitting in the binary and the string `/bin/cat flag.txt`
sitting in `.data`, but nothing wires them together. I overflow the buffer and build a
ROP chain that drops that string's address into RDI and calls `system` myself. First rung
where I have to pass an *argument*, not just redirect control to a function that takes none.

## Recon

    checksec split      # NX enabled, No PIE, No canary

No PIE means fixed addresses, no leak needed. No canary means I can overflow straight to
the return address. NX is why it's ROP and not shellcode. `ROPgadget` hands me
`pop rdi ; ret` at 0x4007c3. The string lives in `.data` — pwntools finds it with
`elf.search(b"/bin/cat flag.txt")` -> 0x601060. `system` comes in through the PLT at
0x400560 (`elf.plt["system"]`, not `elf.symbols` — it's an external libc function, so the
binary only holds its PLT stub, not the function itself).

## The vulnerability

`read()` into a 32-byte buffer with no bounds. Return address is at offset 40 — 32 for the
buffer plus 8 for the saved RBP. Standard stack overflow. The twist is 64-bit calling
convention: the first argument goes in RDI, not on the stack.

## The exploit

I can't write a register with an overflow, only stack memory. So the bridge is
`pop rdi ; ret`: it pops a value off the stack into RDI, then `ret` jumps to whatever's
next on the stack. Lay the chain out and each `ret` reaches forward to the next slot:

    payload = b"A"*40 + p64(0x4007c3) + p64(cat_flag) + p64(system)

The overflow returns into `pop rdi ; ret`, `pop rdi` eats `cat_flag` off the stack into
RDI, its `ret` jumps to `system`, and `system` runs with RDI already pointing at the
string. The order is forced by the gadget, not chosen — `pop` reads slot +1, `ret` reads
slot +2, so the argument has to sit right after the gadget and `system` right after that.

First run: SIGSEGV *inside* `system`, the banner and "Thank you!" printed but no flag. That
was the `movaps` alignment — `system` uses a 16-byte-aligned SSE instruction and my
hand-built stack landed on 8, not 16. One bare `ret` before the chain burns 8 bytes and
flips it:

    ret     = p64(0x000000000040053e)      # bare `ret` gadget, ROPgadget | grep ': ret$'
    payload = b"A"*40 + ret + p64(0x4007c3) + p64(cat_flag) + p64(system)

Second run dropped the flag. Script's alongside this, `exploit.py`.

## What I tripped on

- The clean chain segfaulted with the banner already on screen, so for a second it looked
  like it half-worked. The tell was the flag: it never printed, so the crash was *inside*
  `system`, not after it — unlike ret2win, where the flag comes out and then it dies on the
  way back. No flag means you didn't reach the `cat`.
- I'd called this exact challenge as where `movaps` would finally bite, back in the ret2win
  writeup. It did. Nice to be right, less nice to still forget the `ret` on the first try.

## What I learned

- Passing an argument in 64-bit ROP is a register problem, not a stack one — you need a
  gadget to move the stack value into RDI. That's the whole rung. callme is this with three
  registers instead of one.
- The alignment `ret` is a toggle, not a ritual: it only helps if the stack was on 8. Add it
  to an already-aligned stack and you *break* a working exploit. Try clean first, add the
  `ret` only if `system` faults.
- A ROP chain is just addresses that each end in `ret`, each one handing control to the next
  thing you stacked. The gadget reads the stack forward as it runs — that's the whole trick.
