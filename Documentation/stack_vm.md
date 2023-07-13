StackVM instruction set

this is a little-endian 64-bit address stack based architecture where the stack pointer value decreases as items get pushed onto the stack

# the following instructions have a simple encoding as a single byte

## the following instructions are unary operators, they operate on only 1 argument on the stack

NOP (0x00) does nothing

the following instructions are comparison operators take a signed single byte integer as an argument and push a single byte value of 0 (false) or 1 (true) depending on the condition

EQ0 (0x02) condition: argument equals 0

LT0 (0x04) condition: argument less than 0

LE0 (0x05) condition: argument less than or equal to 0

GT0 (0x06) condition: argument greater than 0

GE0 (0x07) condition: argument greater than or equal to 0

NOT1,NOT2,NOT4,NOT8 (0x28, 0x29, 0x2A, 0x2B) pop a 1, 2, 4 or 8 byte argument off the stack respectively, perform bitwise negation and push the result (same size as the argument) back on the stack

ADD_SP1,ADD_SP2,ADD_SP4,ADD_SP8 (0x38, 0x39, 0x3A, 0x3B) pop a 1, 2, 4 or 8 byte unsigned integer argument off the stack respectively and subtracts it from the stack pointer

RST_SP1,RST_SP2,RST_SP4,RST_SP8 (0x3C, 0x3D, 0x3E, 0x3F) pop a 1, 2, 4 or 8 byte unsigned integer argument off the stack respectively and adds it to the stack pointer

## the following instructions are binary (2 argument operators)

NOTE: when determining which argument is a and which argument is b the argument order is pop a then pop b

### the following instructions are binary operators which take arguments of the same data-type and size and push a result of the same data-type and size on the stack

AND1,AND2,AND4,AND8 (0x20, 0x21, 0x22, 0x23) pushes the C expression `a & b` for argument sizes of 1, 2, 4 and 8 bytes respectively

OR1,OR2,OR4,OR8 (0x24, 0x25, 0x26, 0x27) pushes the C expression `a | b` for argument sizes of 1, 2, 4 and 8 bytes respectively

XOR1,XOR2,XOR4,XOR8 (0x2C, 0x2D, 0x2E, 0x2F) pushes the C expression `a ^ b` for argument sizes of 1, 2, 4 and 8 bytes respectively

ADD1,ADD2,ADD4,ADD8 (0x30, 0x31, 0x32, 0x33) pushes the C expression `a + b` for argument sizes of 1, 2, 4 and 8 bytes respectively, NOTE: while a and b are treated like unsigned integers, signed addition can be done due to representation with 2's complement system

SUB1,SUB2,SUB4,SUB8 (0x34, 0x35, 0x36, 0x37) pushes the C expression `a - b` for argument sizes of 1, 2, 4 and 8 bytes respectively, NOTE: while a and b are treated like unsigned integers, signed subtraction can be done due to representation with 2's complement system

MUL1,MUL1S,MUL2,MUL2S,MUL4,MUL4S,MUL8,MUL8S (0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47) pushes the C expression `a * b` for arguments of type uint8_t, int8_t, uint16_t, int16_t, uint32_t, int32_t, uint64_t, int64_t respectively

DIV1,DIV1S,DIV2,DIV2S,DIV4,DIV4S,DIV8,DIV8S (0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F) pushes the C expression `a / b` for arguments of type uint8_t, int8_t, uint16_t, int16_t, uint32_t, int32_t, uint64_t, int64_t respectively

MOD1,MOD1S,MOD2,MOD2S,MOD4,MOD4S,MOD8,MOD8S (0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57) pushes the C expression `a % b` for arguments of type uint8_t, int8_t, uint16_t, int16_t, uint32_t, int32_t, uint64_t, int64_t respectively

FADD_2,FADD_4,FADD_8,FADD_16 (0x60, 0x61, 0x62, 0x63) pushes the C expression `a + b` for IEEE754 half, single, double and quad precision floating point numbers respectively

FSUB_2,FSUB_4,FSUB_8,FSUB_16 (0x64, 0x65, 0x66, 0x67) pushes the C expression `a - b` for IEEE754 half, single, double and quad precision floating point numbers respectively

FMUL_2,FMUL_4,FMUL_8,FMUL_16 (0x68, 0x69, 0x6A, 0x6B) pushes the C expression `a * b` for IEEE754 half, single, double and quad precision floating point numbers respectively

FDIV_2,FDIV_4,FDIV_8,FDIV_16 (0x6C, 0x6D, 0x6E, 0x6F) pushes the C expression `a / b` for IEEE754 half, single, double and quad precision floating point numbers respectively

FMOD_2,FMOD_4,FMOD_8,FMOD_16 (0x70, 0x71, 0x72, 0x73) pushes the C expression `a % b` for IEEE754 half, single, double and quad precision floating point numbers respectively

### the following instructions are binary comparison operators which take arguments of same size and type and push a signed single byte integer on the stack which has the same sign as the result of `a - b`

CMP1,CMP1S,CMP2,CMP2S,CMP4,CMP4S,CMP8,CMP8S (0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F) compares arguments of type uint8_t, int8_t, uint16_t, int16_t, uint32_t, int32_t, uint64_t, int64_t respectively

FCMP_2,FCMP_4,FCMP_8,FCMP_16 (0x74, 0x75, 0x76, 0x77) compares arguments of type IEEE754 half, single, double and quad precision floating point numbers respectively

## the following instructions are control flow instructions

JMP (0x78) pops an unsigned 8 byte address off the stack and performs an unconditional jump to that address

JMP_IF (0x79) pops an unsigned 8 byte address off the stack and pops a signed 1 byte boolean off the stack, if the boolean is non-zero then performs an unconditional jump to the address

RJMP (0x7A) pops a signed 8 byte offset off the stack and performs an unconditional jump to the current address (points to the instruction after this JMP instruction) plus the offset

RJMP_IF (0x7B) pops a signed 8 byte offset off the stack and pops a signed 1 byte boolean off the stack, if the boolean is non-zero then performs an unconditional jump to the current address (points to the instruction after this JMP instruction) plus the offset

call instructions follow this pattern:

- the current base pointer is pushed on
- the address of the next instruction (the return address) after the current CALL instruction is pushed on the stack
- the current base pointer is set to the current stack pointer (after pushing the return address)

CALL (0x7C) pops an unsigned 8 byte address off the stack and performs an absolute call to that address.

RCALL (0x7D) pops a signed 8 byte offset off the stack and performs a relative call to the current address (points to the instruction after this CALL instruction) plus the offset

RET (0x7E) pops the return address off the stack and pops the base pointer off the stack, then sets the current base pointer to the popped base pointer and jumps to the popped return address

IRET (0x7F) return from interrupt

## the following instructions have a more complicated encoding as multiple bytes are used to encode the instruction

CONV (0x08) pops an argument of one type, converts it to another type and pushes the result on the stack, the encoding of this instruction is as follows:

- 1 byte following the CONV opcode is split. bits 0-3 represent the source type, bits 4-7 represent the destination type
- the type encoded as 4 bits follows the following encoding
  - 0x0: uint8_t
  - 0x1: int8_t
  - 0x2: uint16_t
  - 0x3: int16_t
  - 0x4: uint32_t
  - 0x5: int32_t
  - 0x6: uint64_t
  - 0x7: int64_t
  - 0x8: IEEE754 half precision floating point number
  - 0x9: IEEE754 single precision floating point number
  - 0xA: IEEE754 double precision floating point number
  - 0xB: IEEE754 quad precision floating point number

SWAP (0x09)

- pop argument b
- pop argument a
- push argument b
- push argument a
- 1 byte following the SWAP opcode is split. bits 0-2 represent the size of a, bits 3-5 represent the size of b, bits 6-7 are RESERVED and must be set to 0
- size of an argument is encoded as follows
  - 0x0: 1 byte
  - 0x1: 2 bytes
  - 0x2: 4 bytes
  - 0x3: 8 bytes
  - 0x4: 16 bytes
  - higher sizes are currently unsupported

LOAD (0x0A) and STOR (0x0B)

- the byte following the LOAD/STOR instruction indicates the size of the data, as well as the source location.
  - bits 5-7 indicate the size of the data
    - 0x0: 1 byte
    - 0x1: 2 bytes
    - 0x2: 4 bytes
    - 0x3: 8 bytes
    - higher sizes are currently unsupported
  - bits 0-4 indicate the source/destination location
    - 0x00: (ABS_A4) value is at 4 byte address specified immediately in the instruction
    - 0x01: (ABS_A8) value is at 8 byte address specified immediately in the instruction
    - 0x02: (ABS_S4) value is at 4 byte address popped off the stack
    - 0x03: (ABS_S8) value is at 8 byte address popped off the stack
    - 0x04: (R_BP1) value is at 1 byte signed offset (specified immediately in the instruction) from the current base pointer
    - 0x05: (R_BP2) value is at 2 byte signed offset (specified immediately in the instruction) from the current base pointer
    - 0x06: (R_BP4) value is at 4 byte signed offset (specified immediately in the instruction) from the current base pointer
    - 0x07: (R_BP8) value is at 8 byte signed offset (specified immediately in the instruction) from the current base pointer
    - 0x08: (ABS_C) (LOAD Only) value is specified immediately in the instruction
    - 0x09: (REG_BP) value is the current base pointer. NOTE: size is always assumed to be 8 bytes for this source
    - 0x0A: RESERVED
    - 0x0B: (EA_R_IP) (LOAD Only) value is the instruction pointer added to the signed address offset specified as [size] bytes immediately in the instruction
    - 0x0C: (TOS) (LOAD Only) value is the top of the stack.
    - 0x0D: (SYSREG) value is a system register. the register is specified as a single byte immediately in the instruction. NOTE: size is always assumed to be 8 bytes for this source

StackVm System Registers (SVSR)

- Register 0x00: (SVSR_FLAGS) flags register
  - bit 0-7: priority level
  - bit 8: privilege level (0 = kernel, 1 = user)
  - bit 9: vaddr_msb_eq_priv
    - if 1 then the most significant bit of all virtual addresses is equal to the privilege level and indicates which address space the virtual address is resolved in
    - 0 is unsupported right now
  - bit 10-13: Virtual Memory Mode
    - 0x0: no virtual memory
    - 0x1:
      - 4 levels
      - 9 bits per level
      - 4 KiB per page (12 low order bits directly index into page)
      - 48 bit total virtual address size
    - 0x2:
      - 4 levels
      - 10 bits per level
      - 8 KiB per page (13 low order bits directly index into page)
      - 53 bit total virtual address size
    - 0x3:
      - 2 levels
      - 10 bits per level
      - 4 KiB per page (12 low order bits directly index into page)
      - 32 bit total virtual address size
    - 0x4:
      - 4 levels
      - 11 bits per level
      - 16 KiB per page (14 low order bits directly index into page)
      - 58 bit total virtual address size
    - 0x5:
      - 4 levels
      - 12 bits per level
      - 32 KiB per page (15 low order bits directly index into page)
      - 63 bit total virtual address size
  - bit 14: Enable Interrupts (1 = enabled, 0 = disabled)
- Register 0x01: (SVSR_ISR) Kernel Interrupt Service Routine Table Pointer
  - 8 byte pointer to the kernel interrupt service routine table
  - each entry for interupt n (n from 0 to 255) in the table represents the following
    - 8 bytes at `SVSR_ISR + 16 * n` represent the FLAGS register value to use when servicing interrupt n
    - 8 bytes at `SVSR_ISR + 16 * n + 8` represent the address of the interrupt service routine for interrupt n
  - since this table is 4096 bytes in size (16 \* 256) it is recommended that start of the table be aligned to a page boundary for optimal performance
- Register 0x02: (SVSR_SDP) Kernel Startup Data Pointer (points to instance of struct StartupData defined in the StackVM io interface headers)
- Register 0x03: (SVSR_KERNEL_SYS_FN) address in kernel spage of SYSCALL handler
- Register 0x04: (SVSR_KERNEL_SP) kernel stack pointer
- Register 0x05: (SVSR_USER_SP) user stack pointer
- Register 0x06: (SVSR_KERNEL_BP) kernel base pointer
- Register 0x07: (SVSR_USER_BP) user base pointer
- Register 0x08: (SVSR_KERNEL_PTE) top level kernel page table entry
- Register 0x09: (SVSR_USER_PTE) top level user page table entry
