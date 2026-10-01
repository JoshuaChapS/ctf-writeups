# fluff

ROP Emporium · fluff · x86_64 · 30 Sep 2026

## The challenge

Same goal as every rung so far — get "flag.txt" into memory, call `print_file` — but this time
there's no clean `pop reg; ret` or `mov [reg], reg` gadget anywhere in the binary. Everything
useful is buried inside `questionableGadgets`, built from rare x86 instructions most people never
touch.

## Recon

    checksec fluff      # NX enabled, No PIE, No canary, Partial RELRO

`questionableGadgets` disassembles to:

    xlat   BYTE PTR ds:[rbx]                    ; ret
    pop rdx ; pop rcx ; add rcx, 0x3ef2 ; bextr rbx, rcx, rdx ; ret
    stos   BYTE PTR es:[rdi], al                ; ret

No `pop rax`, `pop rbx`, `pop rcx`, or `pop rdx` exist anywhere else in the binary (`ROPgadget
--all` confirms it) — the bextr chain is the *only* way to touch `rcx`/`rdx`/`rbx`, and there's no
direct way to set `al` at all.

## The vulnerability

Same overflow as every rung. Offset to the return address: 40.

## The exploit

Three unusual instructions, chained:

- `stos` writes `al` to `[rdi]` and auto-increments `rdi`. Doesn't touch `al`.
- `xlat` sets `al = *(rbx + al)` — a table lookup using the *current* `al` as an index.
- `bextr rbx, rcx, rdx` extracts bits from `rcx` into `rbx`, using `rdx` as a start/length
  control. Setting `rdx = 0x4000` (start=0, length=64) extracts the whole register — turning
  `bextr` into a disguised `mov rbx, rcx`, and giving full control over `rbx`.

`al` starts at `0x0b` — not something I set, just whatever's left over at that point in the
program (checked directly with gdb at the same breakpoint used for the offset). Every character
after the first uses the previous character's value, since `xlat` is the only thing that changes
`al`.

For each byte I want in `al`, I need `rbx + al = address_of_that_byte`, so:

    rbx_needed = target_addr - al
    rcx_to_pop = rbx_needed - 0x3ef2     # compensate for the gadget's own add

Repeating the write/xlat/stos sequence 8 times (recomputing `rcx_to_pop` each time from the
*previous* `al`) lands "flag.txt" one character at a time. `rdi` has to be set once before the
loop (it has no prior value worth trusting) and reset once after — `stos` advances it 8 times
during the writes, so it's no longer pointing at the start of the string by the time `print_file`
needs it.

The source addresses for each character came from the binary's own already-loaded bytes — not
necessarily part of a readable string, just any byte with the right value sitting in loaded
memory:

    data = elf.read(0x400000, 0x700)
    for i, b in enumerate(data):
        if b == ord('g'):
            print(hex(0x400000 + i))

No PIE means the file's static content maps 1:1 to runtime addresses, so reading the file
directly works without touching a live process at all.

## What I tripped on

- No way to set `al` directly, and no way to set `rbx` directly either — only `rcx`/`rdx` via the
  one combined gadget. Had to find the "disguised mov" trick (`bextr` with a full-width `ctrl`) to
  get real control over `rbx`.
- Tried to search live process memory for source bytes with gdb's `find`, spanning the binary's
  full address range in one shot — it kept failing with "unable to access" at the very first byte,
  even on addresses `vmmap` confirmed were mapped. Turned out the binary loads as two separate,
  non-contiguous chunks (code near `0x400000`, data near `0x600000`), and `find` chokes the moment
  its range crosses the gap between them. Reading the static file directly with `elf.read()`
  sidestepped the whole problem.
- Almost called `print_file` with `rdi` still sitting past the end of the string — `stos`'s
  auto-increment is easy to forget about once you're focused on getting the right byte into `al`.

## What I learned

- When a binary gives you no direct way to set a register, look for *any* instruction that writes
  to it — even an obscure one like `bextr` can be forced into acting like a plain `mov` with the
  right control value.
- A byte you need doesn't have to come from a readable string. Any already-loaded memory —
  including raw instruction bytes in `.text` — works as a source as long as you know its address
  and its value.
- With no PIE, reading the static ELF file directly is often simpler and more reliable than
  searching live process memory, especially across a binary's non-contiguous segments.