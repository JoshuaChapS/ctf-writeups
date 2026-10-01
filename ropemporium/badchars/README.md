# badchars

ROP Emporium · badchars · x86_64 · 30 Sep 2026

## The challenge

Same primitive as write4 — write "flag.txt" into memory, then call `print_file` — except four of
the eight characters I need ('a', 'g', '.', 'x') are explicitly declared as banned input bytes.
Anything containing one of those bytes gets filtered before it reaches the buffer, including the
string itself and any address built from those bytes.

## Recon

    checksec badchars      # NX enabled, No PIE, No canary, Partial RELRO

Running it directly: `badchars are: 'x', 'g', 'a', '.'` — exactly 4 of the 8 characters in
"flag.txt". `usefulGadgets` has four single-byte operations this time, not one:

    xor BYTE PTR [r15], r14b ; ret
    add BYTE PTR [r15], r14b ; ret
    sub BYTE PTR [r15], r14b ; ret
    mov QWORD PTR [r13+0x0], r12 ; ret

The `mov` is the actual write primitive (`r13` = address, `r12` = value — same role as write4's
gadget, different registers). `sub`/`add`/`xor` are single-byte in-place transforms.
`usefulFunction` is the same bait pattern as before, confirming `print_file@plt` at `0x400510`.

## The vulnerability

Same overflow as every rung. Offset to the return address: 40.

## The exploit

I can't write "flag.txt" directly — 4 of its 8 bytes are banned. Instead I write a placeholder
that shifts each banned byte up by 1 ('a'→'b', 'g'→'h', '.'→'/', 'x'→'y', giving "flbh/tyt"), none
of which collide with the ban list, then run `sub [addr], 1` on each of the 4 shifted positions
afterward to bring them back down to the real byte — all *after* the input filter has already
done its job.

    payload  = b"A" * 40
    payload += pop_r12_r13_r14_r15 + flag_placeholder + bss + p64(1) + bss_addr_a
    payload += mov_write + sub_gadget
    payload += pop_r14_r15 + p64(1) + bss_addr_g   + sub_gadget
    payload += pop_r14_r15 + p64(1) + bss_addr_dot + sub_gadget
    payload += pop_r14_r15 + p64(1) + bss_addr_x   + sub_gadget
    payload += pop_rdi + bss + print_file

The 4-register `pop r12/r13/r14/r15; ret` gadget does double duty: once to load the write
(`r12`/`r13`), and once per fix to load the key and address (`r14`/`r15`) — the extra registers
it also pops just get thrown-away values.

## What I tripped on

- The bad-character filter applies to *everything* in the input, including addresses — the
  challenge warns about this up front, worth taking literally.
- `.` has no uppercase form, which rules out the "flip the case bit" trick (XOR `0x20`) some
  badchars write-ups suggest — it leaves `.` unsolved since it's not a letter. Shifting by a
  constant with `add`/`sub` sidesteps that entirely: one key works for every byte, letter or not.
- Unresolved oddity: finding the offset with `cyclic()`/`cyclic_find()` using a custom alphabet
  (excluding the banned letters) consistently gave 38, verified two independent ways (crash
  `rbp`, and `rsp` read directly at the `ret`). The real offset was 40, confirmed by brute-forcing
  `b"A"*40 + marker` directly. Pinning `n=4` explicitly on both calls didn't fix it. Didn't chase
  it to ground — noting it here as something to watch for next time a custom alphabet is involved.

## What I learned

- Not every character you need to write has to survive the filter directly — you only need
  something *reversible* that does, applied after the filter can no longer see it.
- `add`/`sub` with a constant key beats a case-flip XOR trick for arbitrary bytes: it works
  regardless of whether the target byte is a letter, and the same key works across every position.
- Register size suffixes (`r14b` = low byte of `r14`) matter once gadgets operate at byte
  granularity instead of full-width writes.