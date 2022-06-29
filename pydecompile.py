from iced_x86 import *

# This example produces the following output:
# 00007FFAC46ACDA4 48895C2410           mov       [rsp+10h],rbx
# 00007FFAC46ACDA9 4889742418           mov       [rsp+18h],rsi
# 00007FFAC46ACDAE 55                   push      rbp
# 00007FFAC46ACDAF 57                   push      rdi
# 00007FFAC46ACDB0 4156                 push      r14
# 00007FFAC46ACDB2 488DAC2400FFFFFF     lea       rbp,[rsp-100h]
# 00007FFAC46ACDBA 4881EC00020000       sub       rsp,200h
# 00007FFAC46ACDC1 488B0518570A00       mov       rax,[rel 7FFA`C475`24E0h]
# 00007FFAC46ACDC8 4833C4               xor       rax,rsp
# 00007FFAC46ACDCB 488985F0000000       mov       [rbp+0F0h],rax
# 00007FFAC46ACDD2 4C8B052F240A00       mov       r8,[rel 7FFA`C474`F208h]
# 00007FFAC46ACDD9 488D05787C0400       lea       rax,[rel 7FFA`C46F`4A58h]
# 00007FFAC46ACDE0 33FF                 xor       edi,edi
#
# Format specifiers example:
# xchg [rdx+rsi+16h],ah
# xchg %ah,0x16(%rdx,%rsi)
# xchg [rdx+rsi+16h],ah
# xchg ah,[rdx+rsi+16h]
# xchg ah,[rdx+rsi+16h]
# xchgb %ah, %ds:0x16(%rdx,%rsi)

EXAMPLE_CODE_BITNESS = 64
EXAMPLE_CODE_RIP = 0
EXAMPLE_CODE = """48 83 EC 28 48 C7 C1 00 00 00 00 48 8D 15 F4 1F 00 00 4C 8D 05 E7 1F 00 00 41 B9 00 00 00 00 E8 11 00 00 00 48 83 C4 28 8B C8 E8 00 00 00 00 FF 25 CB 0F 00 00 FF 25 D5 0F 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"""
EXAMPLE_CODE = [int(x, 16) for x in EXAMPLE_CODE.split(" ")]
EXAMPLE_CODE = bytearray(EXAMPLE_CODE)

# Create the decoder and initialize RIP
decoder = Decoder(EXAMPLE_CODE_BITNESS, EXAMPLE_CODE, ip=EXAMPLE_CODE_RIP)

# Formatters: MASM, NASM, GAS (AT&T) and INTEL (XED).
# There's also `FastFormatter` which is ~1.25x faster. Use it if formatting
# speed is more important than being able to re-assemble formatted
# instructions.
#    formatter = FastFormatter()
formatter = Formatter(FormatterSyntax.NASM)

# Change some options, there are many more
formatter.digit_separator = "`"
formatter.first_operand_char_index = 10

# You can also call decoder.can_decode + decoder.decode()/decode_out(instr)
# but the iterator is faster
for instr in decoder:
    disasm = formatter.format(instr)
    # You can also get only the mnemonic string, or only one or more of the operands:
    #   mnemonic_str = formatter.format_mnemonic(instr, FormatMnemonicOptions.NO_PREFIXES)
    #   op0_str = formatter.format_operand(instr, 0)
    #   operands_str = formatter.format_all_operands(instr)

    start_index = instr.ip - EXAMPLE_CODE_RIP
    bytes_str = EXAMPLE_CODE[start_index:start_index + instr.len].hex().upper()
    # Eg. "00007FFAC46ACDB2 488DAC2400FFFFFF     lea       rbp,[rsp-100h]"
    print(f"{instr.ip:016X} {bytes_str:20} {disasm}")

# Instruction also supports format specifiers, see the table below
decoder = Decoder(64, b"\x86\x64\x32\x16", ip=0x1234_5678)
instr = decoder.decode()

print()
print("Format specifiers example:")
print(f"{instr:f}")
print(f"{instr:g}")
print(f"{instr:i}")
print(f"{instr:m}")
print(f"{instr:n}")
print(f"{instr:gG_xSs}")

# ====== =============================================================================
# F-Spec Description
# ====== =============================================================================
# f      Fast formatter (masm-like syntax)
# g      GNU Assembler formatter
# i      Intel (XED) formatter
# m      masm formatter
# n      nasm formatter
# X      Uppercase hex numbers with ``0x`` prefix
# x      Lowercase hex numbers with ``0x`` prefix
# H      Uppercase hex numbers with ``h`` suffix
# h      Lowercase hex numbers with ``h`` suffix
# r      RIP-relative memory operands use RIP register instead of abs addr (``[rip+123h]`` vs ``[123456789ABCDEF0h]``)
# U      Uppercase everything except numbers and hex prefixes/suffixes (ignored by fast fmt)
# s      Add a space after the operand separator
# S      Always show the segment register (memory operands)
# B      Don't show the branch size (``SHORT`` or ``NEAR PTR``) (ignored by fast fmt)
# G      (GNU Assembler): Add mnemonic size suffix (eg. ``movl`` vs ``mov``)
# M      Always show the memory size (eg. ``BYTE PTR``) even when not needed
# _      Use digit separators (eg. ``0x12345678`` vs ``0x1234_5678``) (ignored by fast fmt)
# ====== =============================================================================


print(0x2406)
