import struct
import array
from typing import Union, Optional

float_t = struct.Struct("<f")
double_t = struct.Struct("<d")

BC_NOP = 0
BC_HLT = 1
BC_EQ0 = 2
BC_NE0 = 3
BC_LT0 = 4
BC_LE0 = 5
BC_GT0 = 6
BC_GE0 = 7
BC_CONV = 8
BC_SWAP = 9
BC_LOAD = 10
BC_STOR = 11
BC_CALL_E = 12
BC_RET_E = 13
BC_INT128 = 14  # Extended 128-bit / BITOP group (opcode 0x0E)
BC_INVTLB = 15  # TLB invalidation group (opcode 0x0F)
BC_LSHIFT1 = 16
BC_LSHIFT2 = 17
BC_LSHIFT4 = 18
BC_LSHIFT8 = 19
BC_RSHIFT1 = 20
BC_RSHIFT2 = 21
BC_RSHIFT4 = 22
BC_RSHIFT8 = 23
BC_CLZ1 = 24  # Count Leading Zeros (1-byte)
BC_CLZ2 = 25
BC_CLZ4 = 26
BC_CLZ8 = 27
BC_CTZ1 = 28  # Count Trailing Zeros (1-byte)
BC_CTZ2 = 29
BC_CTZ4 = 30
BC_CTZ8 = 31
BC_AND1 = 32
BC_AND2 = 33
BC_AND4 = 34
BC_AND8 = 35
BC_OR1 = 36
BC_OR2 = 37
BC_OR4 = 38
BC_OR8 = 39
BC_NOT1 = 40
BC_NOT2 = 41
BC_NOT4 = 42
BC_NOT8 = 43
BC_XOR1 = 44
BC_XOR2 = 45
BC_XOR4 = 46
BC_XOR8 = 47
BC_ADD1 = 48
BC_ADD2 = 49
BC_ADD4 = 50
BC_ADD8 = 51
BC_SUB1 = 52
BC_SUB2 = 53
BC_SUB4 = 54
BC_SUB8 = 55
BC_ADD_SP1 = 56
BC_ADD_SP2 = 57
BC_ADD_SP4 = 58
BC_ADD_SP8 = 59
BC_RST_SP1 = 60
BC_RST_SP2 = 61
BC_RST_SP4 = 62
BC_RST_SP8 = 63
BC_MUL1 = 64
BC_MUL1S = 65
BC_MUL2 = 66
BC_MUL2S = 67
BC_MUL4 = 68
BC_MUL4S = 69
BC_MUL8 = 70
BC_MUL8S = 71
BC_DIV1 = 72
BC_DIV1S = 73
BC_DIV2 = 74
BC_DIV2S = 75
BC_DIV4 = 76
BC_DIV4S = 77
BC_DIV8 = 78
BC_DIV8S = 79
BC_MOD1 = 80
BC_MOD1S = 81
BC_MOD2 = 82
BC_MOD2S = 83
BC_MOD4 = 84
BC_MOD4S = 85
BC_MOD8 = 86
BC_MOD8S = 87
BC_CMP1 = 88
BC_CMP1S = 89
BC_CMP2 = 90
BC_CMP2S = 91
BC_CMP4 = 92
BC_CMP4S = 93
BC_CMP8 = 94
BC_CMP8S = 95
BC_FADD_2 = 96
BC_FADD_4 = 97
BC_FADD_8 = 98
BC_FADD_16 = 99
BC_FSUB_2 = 100
BC_FSUB_4 = 101
BC_FSUB_8 = 102
BC_FSUB_16 = 103
BC_FMUL_2 = 104
BC_FMUL_4 = 105
BC_FMUL_8 = 106
BC_FMUL_16 = 107
BC_FDIV_2 = 108
BC_FDIV_4 = 109
BC_FDIV_8 = 110
BC_FDIV_16 = 111
BC_FMOD_2 = 112
BC_FMOD_4 = 113
BC_FMOD_8 = 114
BC_FMOD_16 = 115
BC_FCMP_2 = 116
BC_FCMP_4 = 117
BC_FCMP_8 = 118
BC_FCMP_16 = 119
BC_JMP = 120
BC_JMPIF = 121
BC_RJMP = 122
BC_RJMPIF = 123
BC_CALL = 124
BC_RCALL = 125
BC_RET = 126
BC_RET_N2 = 127
BCR_ABS_A4 = 0x00
BCR_ABS_A8 = 0x01
BCR_ABS_S4 = 0x02
BCR_ABS_S8 = 0x03
BCR_R_BP1 = 0x04
BCR_R_BP2 = 0x05
BCR_R_BP4 = 0x06
BCR_R_BP8 = 0x07
BCR_ABS_C = 0x08  # LOAD: load constant from instruction stream
BCR_ATOMIC_STORE = 0x08  # STOR: atomic seq-cst store [sz value][8B addr]
BCR_REG_BP = 0x09
BCR_FENCE_ALL = 0x0A  # STOR: MFENCE (all)
BCR_EA_R_IP = 0x0B  # LOAD: effective address relative to IP
BCR_FENCE_LOAD = 0x0B  # STOR: LFENCE (load fence)
BCR_TOS = 0x0C  # LOAD: peek TOS
BCR_FENCE_STORE = 0x0C  # STOR: SFENCE (store fence)
BCR_SYSREG = 0x0D
# Atomic LOAD BCR codes (require 1-byte memory ordering after BCR byte)
BCR_ATOMIC_LOAD = 0x0E  # [ordering][8B addr] -> [sz val]
BCR_ATOMIC_XCHG = 0x0F  # [ordering][8B addr] -> [sz old]; pops [sz new] first
BCR_ATOMIC_CAS = 0x10  # [ordering][8B addr] -> [sz old]; pops [sz desired][sz expected]
BCR_ATOMIC_FADD = 0x11  # fetch-and-add
BCR_ATOMIC_FSUB = 0x12  # fetch-and-subtract
BCR_ATOMIC_FAND = 0x13  # fetch-and-AND
BCR_ATOMIC_FOR = 0x14  # fetch-and-OR
BCR_ATOMIC_FXOR = 0x15  # fetch-and-XOR
BCR_SZ_1 = 0x0 << 5
BCR_SZ_2 = 0x1 << 5
BCR_SZ_4 = 0x2 << 5
BCR_SZ_8 = 0x3 << 5
BCR_SZ_16 = 0x4 << 5
BCR_TYP_MASK = 0x1F  # low 5 bits
BCR_SZ_MASK = 0xE0  # high 3 bits 0:1, 1:2, 2:4, 3:8
BCR_R_BP_MASK = 0x1C
BCR_R_BP_VAL = 0x04
BCS_SZ1_A = 0x00
BCS_SZ2_A = 0x01
BCS_SZ4_A = 0x02
BCS_SZ8_A = 0x03
BCS_SZ16_A = 0x04
BCS_SZ32_A = 0x05
BCS_SZ64_A = 0x06
BCS_SZ128_A = 0x07
BCS_SZ1_B = 0x00
BCS_SZ2_B = 0x08
BCS_SZ4_B = 0x10
BCS_SZ8_B = 0x18
BCS_SZ16_B = 0x20
BCS_SZ32_B = 0x28
BCS_SZ64_B = 0x30
BCS_SZ128_B = 0x38
BCS_SZ_A_MASK = 0x07
BCS_SZ_B_MASK = 0x38
BCC_I_MASK = 0x0F
BCC_O_MASK = 0xF0
BCC_UI_1_I = 0x00
BCC_SI_1_I = 0x01
BCC_UI_2_I = 0x02
BCC_SI_2_I = 0x03
BCC_UI_4_I = 0x04
BCC_SI_4_I = 0x05
BCC_UI_8_I = 0x06
BCC_SI_8_I = 0x07
BCC_F_2_I = 0x08
BCC_F_4_I = 0x09
BCC_F_8_I = 0x0A
BCC_F_16_I = 0x0B
BCC_UI_1_O = 0x00
BCC_SI_1_O = 0x10
BCC_UI_2_O = 0x20
BCC_SI_2_O = 0x30
BCC_UI_4_O = 0x40
BCC_SI_4_O = 0x50
BCC_UI_8_O = 0x60
BCC_SI_8_O = 0x70
BCC_F_2_O = 0x80
BCC_F_4_O = 0x90
BCC_F_8_O = 0xA0
BCC_F_16_O = 0xB0
BCRE_SYS = 0x1 << 7
BCRE_RST_SP_SZ1 = 0x0 << 5
BCRE_RST_SP_SZ2 = 0x1 << 5
BCRE_RST_SP_SZ4 = 0x2 << 5
BCRE_RST_SP_SZ8 = 0x3 << 5
BCRE_RST_SP_SZ_MASK = 0x3 << 5
BCRE_RES_SZ1 = 0x0 << 3
BCRE_RES_SZ2 = 0x1 << 3
BCRE_RES_SZ4 = 0x2 << 3
BCRE_RES_SZ8 = 0x3 << 3
BCRE_RES_SZ_MASK = 0x3 << 3
BCCE_SYSCALL = 1 << 7
BCCE_IS_REL = 1 << 6
BCCE_S_SYSN_SZ1 = 0 << 5
BCCE_S_SYSN_SZ2 = 1 << 5
BCCE_S_SYSN_SZ4 = 2 << 5
BCCE_S_SYSN_SZ8 = 3 << 5
BCCE_S_ARG_SZ1 = 0 << 3
BCCE_S_ARG_SZ2 = 1 << 3
BCCE_S_ARG_SZ4 = 2 << 3
BCCE_S_ARG_SZ8 = 3 << 3
BCCE_IS_INT = 1 << 5  # CALL_E flag: software interrupt (IS_SYS=0 path)
BCRE_IS_INT = 1 << 6  # RET_E flag: IRET interrupt-return (IS_SYS=1 path)

# StackVm SysReg
SVSRB_SP = 0x04
SVSRB_BP = 0x06
SVSRB_TLPTR = 0x08

SVSR_FLAGS = 0x00
SVSR_ISR = 0x01
SVSR_SDP = 0x02
SVSR_SYS_FN = 0x03
SVSR_KERNEL_SP = 0x04
SVSR_USER_SP = 0x05
SVSR_KERNEL_BP = 0x06
SVSR_USER_BP = 0x07
SVSR_KERNEL_TLPTR = 0x08
SVSR_USER_TLPTR = 0x09
SVSR_CORE_ID = 0x0A  # R (kernel): current core ID; 0 on single-core
SVSR_IPI = 0x0B  # W (kernel): SMP IPI -- (irq << 8) | target_core_id
SVSR_CYCLE_COUNT = 0x0C  # R (kernel): per-core cycle counter
SVSR_PAGE_FAULT_ADDR = (
    0x0D  # R (kernel): CR2 equivalent; set by VM on page/protect fault
)
# Interrupt-argument registers (read-only, kernel): populated by the VM when it
# delivers an interrupt that carries arguments (e.g. the TLB-shootdown descriptor
# for INT_TLB_SHOOTDOWN / INT_TLB_SHOOTDOWN_DONE, or the info pointer for HW_IO).
SVSR_INT_ARG0 = 0x0E
SVSR_INT_ARG1 = 0x0F
SVSR_INT_ARG2 = 0x10
SVSR_INT_ARG3 = 0x11
# Thread-pointer register for the userspace TLS ABI.  Holds the base address of
# the current thread's TLS block; a thread-local variable lives at
# TLS_BASE + (its offset within the TLS template).  Readable from user mode (the
# compiler emits TLS-relative loads in user code); written by the kernel/loader
# on context switch.  See Documentation/ThreadLocalStorage.html.
SVSR_TLS_BASE = 0x12

# ---- SVSR_FLAGS bit layout (see Documentation/stack_vm.md) -----------------
# bits 0-7 : priority level.  Doubles as the interrupt-mask threshold: lower
#            number == more urgent, so a pending maskable interrupt is delivered
#            only when its priority is numerically *less* than this field.
# bit 8    : privilege level (0 = kernel, 1 = user)
# bit 9    : vaddr_msb_eq_priv
# bits 10-13: virtual memory mode
# bit 14   : Enable Interrupts (1 = maskable interrupts may be delivered, 0 = masked)
FLAGS_PRIORITY_MASK = 0xFF
FLAGS_INT_ENABLE = 1 << 14

StackVM_SVSR_Codes = {
    # v3 two-privilege-level layout
    "FLAGS": SVSR_FLAGS,
    "ISR": SVSR_ISR,
    "SDP": SVSR_SDP,
    "SYS_FN": SVSR_SYS_FN,
    "KERNEL_SP": SVSR_KERNEL_SP,
    "USER_SP": SVSR_USER_SP,
    "KERNEL_BP": SVSR_KERNEL_BP,
    "USER_BP": SVSR_USER_BP,
    "KERNEL_TLPTR": SVSR_KERNEL_TLPTR,
    "USER_TLPTR": SVSR_USER_TLPTR,
    "CORE_ID": SVSR_CORE_ID,
    "IPI": SVSR_IPI,
    "CYCLE_COUNT": SVSR_CYCLE_COUNT,
    "PAGE_FAULT_ADDR": SVSR_PAGE_FAULT_ADDR,
    "INT_ARG0": SVSR_INT_ARG0,
    "INT_ARG1": SVSR_INT_ARG1,
    "INT_ARG2": SVSR_INT_ARG2,
    "INT_ARG3": SVSR_INT_ARG3,
    "TLS_BASE": SVSR_TLS_BASE,
}

INT_DIV_BY_ZERO = 0x00
INT_DEBUG = 0x01
INT_NMI = 0x02
INT_BREAKPOINT = 0x03
INT_OVERFLOW = 0x04
INT_BOUNDS_CHECK = 0x05
INT_INVAL_OPCODE = 0x06
INT_FPU_FAULT = 0x07
INT_DOUBLE_FAULT = 0x08
INT_PROTECT_FAULT = 0x0D
INT_PAGE_FAULT = 0x0E
INT_INVAL_SYSCALL = 0x0F
INT_HW_IO = 0x10
INT_TIMER = 0x11
INT_TLB_SHOOTDOWN_DONE = 0x1E  # async TLB-shootdown completion (delivered to done_core)
INT_TLB_SHOOTDOWN = 0x1F  # TLB-shootdown request (remote-interrupt fallback path)
INT_LST = (
    [
        "DIV_BY_ZERO",  # 0x00
        "DEBUG",  # 0x01
        "NMI",  # 0x02
        "BREAKPOINT",  # 0x03
        "OVERFLOW",  # 0x04
        "BOUNDS_CHECK",  # 0x05
        "INVAL_OPCODE",  # 0x06
        "FPU_FAULT",  # 0x07
        "DOUBLE_FAULT",  # 0x08
        "UNKNOWN",  # 0x09
        "UNKNOWN",  # 0x0A
        "UNKNOWN",  # 0x0B
        "UNKNOWN",  # 0x0C
        "PROTECT_FAULT",  # 0x0D
        "PAGE_FAULT",  # 0x0E
        "INVAL_SYSCALL",  # 0x0F
        "HW_IO",  # 0x10
        "TIMER",  # 0x11
    ]
    + ["UNKNOWN"] * 12  # 0x12 .. 0x1D
    + ["TLB_SHOOTDOWN_DONE"]  # 0x1E
    + ["TLB_SHOOTDOWN"]  # 0x1F
    + ["UNKNOWN"] * 224  # 0x20 .. 0xFF
)
assert len(INT_LST) == 256

MRQ_DONT_CHECK = 0
MRQ_READ = 1
MRQ_WRITE = 2
MRQ_EXEC = 3

StackVM_BCRE_Codes = {
    "RST_SP_SZ1": 0x00,
    "RST_SP_SZ2": 0x20,
    "RST_SP_SZ4": 0x40,
    "RST_SP_SZ8": 0x60,
    "RES_SZ1": 0x0,
    "RES_SZ2": 0x8,
    "RES_SZ4": 0x10,
    "RES_SZ8": 0x18,
}

LstStackVM_Codes = [
    "NOP",
    "HLT",
    "EQ0",
    "NE0",
    "LT0",
    "LE0",
    "GT0",
    "GE0",
    "CONV",
    "SWAP",
    "LOAD",
    "STOR",
    "CALL_E",
    "RET_E",
    "INT128",
    "INVTLB",
    "LSHIFT1",
    "LSHIFT2",
    "LSHIFT4",
    "LSHIFT8",
    "RSHIFT1",
    "RSHIFT2",
    "RSHIFT4",
    "RSHIFT8",
    "CLZ1",
    "CLZ2",
    "CLZ4",
    "CLZ8",
    "CTZ1",
    "CTZ2",
    "CTZ4",
    "CTZ8",
    "AND1",
    "AND2",
    "AND4",
    "AND8",
    "OR1",
    "OR2",
    "OR4",
    "OR8",
    "NOT1",
    "NOT2",
    "NOT4",
    "NOT8",
    "XOR1",
    "XOR2",
    "XOR4",
    "XOR8",
    "ADD1",
    "ADD2",
    "ADD4",
    "ADD8",
    "SUB1",
    "SUB2",
    "SUB4",
    "SUB8",
    "ADD_SP1",
    "ADD_SP2",
    "ADD_SP4",
    "ADD_SP8",
    "RST_SP1",
    "RST_SP2",
    "RST_SP4",
    "RST_SP8",
    "MUL1",
    "MUL1S",
    "MUL2",
    "MUL2S",
    "MUL4",
    "MUL4S",
    "MUL8",
    "MUL8S",
    "DIV1",
    "DIV1S",
    "DIV2",
    "DIV2S",
    "DIV4",
    "DIV4S",
    "DIV8",
    "DIV8S",
    "MOD1",
    "MOD1S",
    "MOD2",
    "MOD2S",
    "MOD4",
    "MOD4S",
    "MOD8",
    "MOD8S",
    "CMP1",
    "CMP1S",
    "CMP2",
    "CMP2S",
    "CMP4",
    "CMP4S",
    "CMP8",
    "CMP8S",
    "FADD_2",
    "FADD_4",
    "FADD_8",
    "FADD_16",
    "FSUB_2",
    "FSUB_4",
    "FSUB_8",
    "FSUB_16",
    "FMUL_2",
    "FMUL_4",
    "FMUL_8",
    "FMUL_16",
    "FDIV_2",
    "FDIV_4",
    "FDIV_8",
    "FDIV_16",
    "FMOD_2",
    "FMOD_4",
    "FMOD_8",
    "FMOD_16",
    "FCMP_2",
    "FCMP_4",
    "FCMP_8",
    "FCMP_16",
    "JMP",
    "JMPIF",
    "RJMP",
    "RJMPIF",
    "CALL",
    "RCALL",
    "RET",
    "INV_OPCODE",
]

StackVM_Codes = {
    "NOP": 0,
    "HLT": 1,
    "EQ0": 2,
    "NE0": 3,
    "LT0": 4,
    "LE0": 5,
    "GT0": 6,
    "GE0": 7,
    "CONV": 8,
    "SWAP": 9,
    "LOAD": 10,
    "STOR": 11,
    "CALL_E": 12,
    "RET_E": 13,
    "INT128": 14,
    "INVTLB": 15,
    "LSHIFT1": 16,
    "LSHIFT2": 17,
    "LSHIFT4": 18,
    "LSHIFT8": 19,
    "RSHIFT1": 20,
    "RSHIFT2": 21,
    "RSHIFT4": 22,
    "RSHIFT8": 23,
    "CLZ1": 24,
    "CLZ2": 25,
    "CLZ4": 26,
    "CLZ8": 27,
    "CTZ1": 28,
    "CTZ2": 29,
    "CTZ4": 30,
    "CTZ8": 31,
    "AND1": 32,
    "AND2": 33,
    "AND4": 34,
    "AND8": 35,
    "OR1": 36,
    "OR2": 37,
    "OR4": 38,
    "OR8": 39,
    "NOT1": 40,
    "NOT2": 41,
    "NOT4": 42,
    "NOT8": 43,
    "XOR1": 44,
    "XOR2": 45,
    "XOR4": 46,
    "XOR8": 47,
    "ADD1": 48,
    "ADD2": 49,
    "ADD4": 50,
    "ADD8": 51,
    "SUB1": 52,
    "SUB2": 53,
    "SUB4": 54,
    "SUB8": 55,
    "ADD_SP1": 56,
    "ADD_SP2": 57,
    "ADD_SP4": 58,
    "ADD_SP8": 59,
    "RST_SP1": 60,
    "RST_SP2": 61,
    "RST_SP4": 62,
    "RST_SP8": 63,
    "MUL1": 64,
    "MUL1S": 65,
    "MUL2": 66,
    "MUL2S": 67,
    "MUL4": 68,
    "MUL4S": 69,
    "MUL8": 70,
    "MUL8S": 71,
    "DIV1": 72,
    "DIV1S": 73,
    "DIV2": 74,
    "DIV2S": 75,
    "DIV4": 76,
    "DIV4S": 77,
    "DIV8": 78,
    "DIV8S": 79,
    "MOD1": 80,
    "MOD1S": 81,
    "MOD2": 82,
    "MOD2S": 83,
    "MOD4": 84,
    "MOD4S": 85,
    "MOD8": 86,
    "MOD8S": 87,
    "CMP1": 88,
    "CMP1S": 89,
    "CMP2": 90,
    "CMP2S": 91,
    "CMP4": 92,
    "CMP4S": 93,
    "CMP8": 94,
    "CMP8S": 95,
    "FADD_2": 96,
    "FADD_4": 97,
    "FADD_8": 98,
    "FADD_16": 99,
    "FSUB_2": 100,
    "FSUB_4": 101,
    "FSUB_8": 102,
    "FSUB_16": 103,
    "FMUL_2": 104,
    "FMUL_4": 105,
    "FMUL_8": 106,
    "FMUL_16": 107,
    "FDIV_2": 108,
    "FDIV_4": 109,
    "FDIV_8": 110,
    "FDIV_16": 111,
    "FMOD_2": 112,
    "FMOD_4": 113,
    "FMOD_8": 114,
    "FMOD_16": 115,
    "FCMP_2": 116,
    "FCMP_4": 117,
    "FCMP_8": 118,
    "FCMP_16": 119,
    "JMP": 120,
    "JMPIF": 121,
    "RJMP": 122,
    "RJMPIF": 123,
    "CALL": 124,
    "RCALL": 125,
    "RET": 126,
    "INV_OPCODE": 127,
}


def _test():
    for c in range(len(LstStackVM_Codes)):
        assert StackVM_Codes[LstStackVM_Codes[c]] == c, "error c = %u" % c


_test()

StackVM_BCR_Codes = {
    "ABS_A4": 0x00,
    "ABS_A8": 0x01,
    "ABS_S4": 0x02,
    "ABS_S8": 0x03,
    "R_BP1": 0x04,
    "R_BP2": 0x05,
    "R_BP4": 0x06,
    "R_BP8": 0x07,
    "ABS_C": 0x08,
    "ATOMIC_STORE": 0x08,  # STOR context: atomic seq-cst store
    "REG_BP": 0x09,
    "RES": 0x0A,
    "FENCE_ALL": 0x0A,  # STOR context: MFENCE
    "EA_R_IP": 0x0B,
    "FENCE_LOAD": 0x0B,  # STOR context: LFENCE
    "TOS": 0x0C,
    "FENCE_STORE": 0x0C,  # STOR context: SFENCE
    "SYSREG": 0x0D,
    # Atomic LOAD BCR codes (each followed by 1 ordering byte)
    "ATOMIC_LOAD": 0x0E,
    "ATOMIC_XCHG": 0x0F,
    "ATOMIC_CAS": 0x10,
    "ATOMIC_FADD": 0x11,
    "ATOMIC_FSUB": 0x12,
    "ATOMIC_FAND": 0x13,
    "ATOMIC_FOR": 0x14,
    "ATOMIC_FXOR": 0x15,
    "SZ_1": 0x0 << 5,
    "SZ_2": 0x1 << 5,
    "SZ_4": 0x2 << 5,
    "SZ_8": 0x3 << 5,
    "SZ_16": 0x4 << 5,
}
StackVM_BCS_Codes = {
    "SZ1_A": 0x00,
    "SZ2_A": 0x01,
    "SZ4_A": 0x02,
    "SZ8_A": 0x03,
    "SZ16_A": 0x04,
    "SZ32_A": 0x05,
    "SZ64_A": 0x06,
    "SZ128_A": 0x07,
    "SZ1_B": 0x00,
    "SZ2_B": 0x08,
    "SZ4_B": 0x10,
    "SZ8_B": 0x18,
    "SZ16_B": 0x20,
    "SZ32_B": 0x28,
    "SZ64_B": 0x30,
    "SZ128_B": 0x38,
}
StackVM_BCC_Codes = {
    "UI_1_I": 0x00,
    "SI_1_I": 0x01,
    "UI_2_I": 0x02,
    "SI_2_I": 0x03,
    "UI_4_I": 0x04,
    "SI_4_I": 0x05,
    "UI_8_I": 0x06,
    "SI_8_I": 0x07,
    "F_2_I": 0x08,
    "F_4_I": 0x09,
    "F_8_I": 0x0A,
    "F_16_I": 0x0B,
    "UI_16_I": 0x0C,  # uint128 input
    "SI_16_I": 0x0D,  # int128 input
    "UI_1_O": 0x00,
    "SI_1_O": 0x10,
    "UI_2_O": 0x20,
    "SI_2_O": 0x30,
    "UI_4_O": 0x40,
    "SI_4_O": 0x50,
    "UI_8_O": 0x60,
    "SI_8_O": 0x70,
    "F_2_O": 0x80,
    "F_4_O": 0x90,
    "F_8_O": 0xA0,
    "F_16_O": 0xB0,
    "UI_16_O": 0xC0,  # uint128 output
    "SI_16_O": 0xD0,  # int128 output
}
StackVM_BCCE_Codes = {
    "SYSCALL": 0x80,
    "IS_REL": 0x40,
    "S_SYSN_SZ1": 0x00,
    "S_SYSN_SZ2": 0x20,
    "S_SYSN_SZ4": 0x40,
    "S_SYSN_SZ8": 0x60,
    "S_ARG_SZ1": 0x00,
    "S_ARG_SZ2": 0x08,
    "S_ARG_SZ4": 0x10,
    "S_ARG_SZ8": 0x18,
}
StackVM_BC128_Codes = {
    "ADD128U": 0x00,
    "ADD128S": 0x01,
    "SUB128U": 0x02,
    "SUB128S": 0x03,
    "MUL128U": 0x04,
    "MUL128S": 0x05,
    "DIV128U": 0x06,
    "DIV128S": 0x07,
    "MOD128U": 0x08,
    "MOD128S": 0x09,
    "AND128": 0x0A,
    "OR128": 0x0B,
    "XOR128": 0x0C,
    "NOT128": 0x0D,
    "LSHIFT128": 0x0E,
    "RSHIFT128U": 0x0F,
    "RSHIFT128S": 0x10,
    "CMP128U": 0x11,
    "CMP128S": 0x12,
    "POPCNT1": 0x13,
    "POPCNT2": 0x14,
    "POPCNT4": 0x15,
    "POPCNT8": 0x16,
    "BSWAP2": 0x17,
    "BSWAP4": 0x18,
    "BSWAP8": 0x19,
}
StackVM_INVTLB_Codes = {
    "LOCAL": 0x00,
    "ALL_LOCAL": 0x01,
    "SINGLE": 0x02,
    "MULTI": 0x03,
    "ACK": 0x04,
}
StackVM_ORDERING_Codes = {
    "RELAXED": 0x00,
    "ACQUIRE": 0x01,
    "RELEASE": 0x02,
    "SEQ_CST": 0x03,
}
LstStackVM_BCR_Types = [
    "ABS_A4",  # 0x00
    "ABS_A8",  # 0x01
    "ABS_S4",  # 0x02
    "ABS_S8",  # 0x03
    "R_BP1",  # 0x04
    "R_BP2",  # 0x05
    "R_BP4",  # 0x06
    "R_BP8",  # 0x07
    "ABS_C",  # 0x08  (LOAD) / ATOMIC_STORE (STOR)
    "REG_BP",  # 0x09
    "FENCE_ALL",  # 0x0A  (STOR: MFENCE)
    "EA_R_IP",  # 0x0B  (LOAD) / FENCE_LOAD (STOR: LFENCE)
    "TOS",  # 0x0C  (LOAD) / FENCE_STORE (STOR: SFENCE)
    "SYSREG",  # 0x0D
    "ATOMIC_LOAD",  # 0x0E
    "ATOMIC_XCHG",  # 0x0F
    "ATOMIC_CAS",  # 0x10
    "ATOMIC_FADD",  # 0x11
    "ATOMIC_FSUB",  # 0x12
    "ATOMIC_FAND",  # 0x13
    "ATOMIC_FOR",  # 0x14
    "ATOMIC_FXOR",  # 0x15
]
LstStackVM_sysregs = [
    "FLAGS",  # 0x00
    "ISR",  # 0x01
    "SDP",  # 0x02
    "SYS_FN",  # 0x03
    "KERNEL_SP",  # 0x04
    "USER_SP",  # 0x05
    "KERNEL_BP",  # 0x06
    "USER_BP",  # 0x07
    "KERNEL_TLPTR",  # 0x08
    "USER_TLPTR",  # 0x09
    "CORE_ID",  # 0x0A
    "IPI",  # 0x0B
    "CYCLE_COUNT",  # 0x0C
    "PAGE_FAULT_ADDR",  # 0x0D
    "INT_ARG0",  # 0x0E
    "INT_ARG1",  # 0x0F
    "INT_ARG2",  # 0x10
    "INT_ARG3",  # 0x11
]
LstStackVM_BCS_Types = [
    "SZ1_",
    "SZ2_",
    "SZ4_",
    "SZ8_",
    "SZ16_",
    "SZ32_",
    "SZ64_",
    "SZ128_",
]
LstStackVM_BCC_Types = [
    "UI_1_",
    "SI_1_",
    "UI_2_",
    "SI_2_",
    "UI_4_",
    "SI_4_",
    "UI_8_",
    "SI_8_",
    "F_2_",
    "F_4_",
    "F_8_",
    "F_16_",
    "UI_16_",  # 0xC: uint128
    "SI_16_",  # 0xD: int128
]


# ---------------------------------------------------------------------------
# CLZ / CTZ / POPCNT / BSWAP helpers
# ---------------------------------------------------------------------------


def clz1(a: int, n_bits: int) -> int:
    """Count leading zeros in an n_bits-wide value."""
    if a == 0:
        return n_bits
    return n_bits - a.bit_length()


def ctz1(a: int, n_bits: int) -> int:
    """Count trailing zeros in an n_bits-wide value."""
    if a == 0:
        return n_bits
    return (a & -a).bit_length() - 1


def popcnt(a: int) -> int:
    """Population count (number of set bits)."""
    return bin(a).count("1")


def bswap(a: int, n_bytes: int) -> int:
    """Reverse byte order of an n_bytes-wide integer."""
    return int.from_bytes(a.to_bytes(n_bytes, "little"), "big")


# ---------------------------------------------------------------------------
# INT128 / BITOP extended group (opcode 0x0E) sub-operation codes
# ---------------------------------------------------------------------------
BC128_ADD128U = 0x00
BC128_ADD128S = 0x01
BC128_SUB128U = 0x02
BC128_SUB128S = 0x03
BC128_MUL128U = 0x04
BC128_MUL128S = 0x05
BC128_DIV128U = 0x06
BC128_DIV128S = 0x07
BC128_MOD128U = 0x08
BC128_MOD128S = 0x09
BC128_AND128 = 0x0A
BC128_OR128 = 0x0B
BC128_XOR128 = 0x0C
BC128_NOT128 = 0x0D
BC128_LSHIFT128 = 0x0E
BC128_RSHIFT128U = 0x0F
BC128_RSHIFT128S = 0x10
BC128_CMP128U = 0x11
BC128_CMP128S = 0x12
BC128_POPCNT1 = 0x13
BC128_POPCNT2 = 0x14
BC128_POPCNT4 = 0x15
BC128_POPCNT8 = 0x16
BC128_BSWAP2 = 0x17
BC128_BSWAP4 = 0x18
BC128_BSWAP8 = 0x19

_MASK128 = (1 << 128) - 1


def vm_int128(vm_inst):
    """
    Opcode 0x0E — 128-bit integer arithmetic and BITOP extended group.
    :param VirtualMachine vm_inst:
    """
    op = vm_inst.get_instr_dat(1)
    if op is None:
        vm_inst.ip -= 1
        return
    if op == BC128_ADD128U:
        b = vm_inst.pop(16)
        a = vm_inst.pop(16)
        vm_inst.push(16, (a + b) & _MASK128)
    elif op == BC128_ADD128S:
        b = vm_inst.pop(16, 1)
        a = vm_inst.pop(16, 1)
        vm_inst.push(16, a + b, 1)
    elif op == BC128_SUB128U:
        b = vm_inst.pop(16)
        a = vm_inst.pop(16)
        vm_inst.push(16, (a - b) & _MASK128)
    elif op == BC128_SUB128S:
        b = vm_inst.pop(16, 1)
        a = vm_inst.pop(16, 1)
        vm_inst.push(16, a - b, 1)
    elif op == BC128_MUL128U:
        b = vm_inst.pop(16)
        a = vm_inst.pop(16)
        vm_inst.push(16, (a * b) & _MASK128)
    elif op == BC128_MUL128S:
        b = vm_inst.pop(16, 1)
        a = vm_inst.pop(16, 1)
        vm_inst.push(16, a * b, 1)
    elif op == BC128_DIV128U:
        b = vm_inst.pop(16)
        a = vm_inst.pop(16)
        if b == 0:
            vm_inst.trap(INT_DIV_BY_ZERO, vm_inst.ip)
            return
        vm_inst.push(16, a // b)
    elif op == BC128_DIV128S:
        b = vm_inst.pop(16, 1)
        a = vm_inst.pop(16, 1)
        if b == 0:
            vm_inst.trap(INT_DIV_BY_ZERO, vm_inst.ip)
            return
        vm_inst.push(16, a // b, 1)
    elif op == BC128_MOD128U:
        b = vm_inst.pop(16)
        a = vm_inst.pop(16)
        if b == 0:
            vm_inst.trap(INT_DIV_BY_ZERO, vm_inst.ip)
            return
        vm_inst.push(16, a % b)
    elif op == BC128_MOD128S:
        b = vm_inst.pop(16, 1)
        a = vm_inst.pop(16, 1)
        if b == 0:
            vm_inst.trap(INT_DIV_BY_ZERO, vm_inst.ip)
            return
        vm_inst.push(16, a % b, 1)
    elif op == BC128_AND128:
        b = vm_inst.pop(16)
        a = vm_inst.pop(16)
        vm_inst.push(16, a & b)
    elif op == BC128_OR128:
        b = vm_inst.pop(16)
        a = vm_inst.pop(16)
        vm_inst.push(16, a | b)
    elif op == BC128_XOR128:
        b = vm_inst.pop(16)
        a = vm_inst.pop(16)
        vm_inst.push(16, a ^ b)
    elif op == BC128_NOT128:
        a = vm_inst.pop(16)
        vm_inst.push(16, (~a) & _MASK128)
    elif op == BC128_LSHIFT128:
        shift = vm_inst.pop(1)
        a = vm_inst.pop(16)
        vm_inst.push(16, (a << shift) & _MASK128)
    elif op == BC128_RSHIFT128U:
        shift = vm_inst.pop(1)
        a = vm_inst.pop(16)
        vm_inst.push(16, a >> shift)
    elif op == BC128_RSHIFT128S:
        shift = vm_inst.pop(1)
        a = vm_inst.pop(16, 1)
        vm_inst.push(16, a >> shift, 1)
    elif op == BC128_CMP128U:
        b = vm_inst.pop(16)
        a = vm_inst.pop(16)
        vm_inst.push(1, sign_of(a - b), 1)
    elif op == BC128_CMP128S:
        b = vm_inst.pop(16, 1)
        a = vm_inst.pop(16, 1)
        vm_inst.push(1, sign_of(a - b), 1)
    elif op == BC128_POPCNT1:
        vm_inst.push(1, popcnt(vm_inst.pop(1)))
    elif op == BC128_POPCNT2:
        vm_inst.push(1, popcnt(vm_inst.pop(2)))
    elif op == BC128_POPCNT4:
        vm_inst.push(1, popcnt(vm_inst.pop(4)))
    elif op == BC128_POPCNT8:
        vm_inst.push(1, popcnt(vm_inst.pop(8)))
    elif op == BC128_BSWAP2:
        vm_inst.push(2, bswap(vm_inst.pop(2), 2))
    elif op == BC128_BSWAP4:
        vm_inst.push(4, bswap(vm_inst.pop(4), 4))
    elif op == BC128_BSWAP8:
        vm_inst.push(8, bswap(vm_inst.pop(8), 8))
    else:
        vm_inst.trap(INT_INVAL_OPCODE, vm_inst.ip)


# ---------------------------------------------------------------------------
# INVTLB group (opcode 0x0F) sub-operation codes + TLB constants
# ---------------------------------------------------------------------------
# Sub-operations (the byte after the 0x0F opcode):
INVTLB_LOCAL = 0x00  # [0x0F][0x00]        pop(count, base, tlptr): flush local range
INVTLB_ALL_LOCAL = 0x01  # [0x0F][0x01]        flush this core's entire TLB
INVTLB_SINGLE = 0x02  # [0x0F][0x02][flags] pop([done_core,] count, base, tlptr)
INVTLB_MULTI = 0x03  # [0x0F][0x03][flags] pop([done_core,] num_entries, entry_ptr)
INVTLB_ACK = 0x04  # [0x0F][0x04]        pop(handle): remote-int completion ack

# Flags byte for INVTLB_SINGLE / INVTLB_MULTI:
INVTLB_F_ASYNC = 0x01  # don't block; deliver INT_TLB_SHOOTDOWN_DONE on completion
INVTLB_F_REMOTE_INT = 0x02  # fallback: interrupt matching cores instead of HW broadcast
INVTLB_F_ALSO_LOCAL = 0x04  # also invalidate the issuing core's own TLB
INVTLB_F_INCLUDE_INTERMEDIATE = 0x08  # also drop page-walk (intermediate) caches

# Per-entry size for INVTLB_MULTI descriptor array: {tlptr, vaddr_base, page_count}.
INVTLB_ENTRY_SIZE = 24

# TLB permission-validation mask bits (which access modes a cached entry covers).
TLBP_R = 1
TLBP_W = 2
TLBP_X = 4
_MRQ_TO_TLBP = {MRQ_READ: TLBP_R, MRQ_WRITE: TLBP_W, MRQ_EXEC: TLBP_X}

# Page size by virtual-memory mode (used for TLB keying / range invalidation).
# Numeric keys (VM_* constants are defined later in this module):
#   0 = VM_DISABLED, 1 = VM_4_LVL_9_BIT, 2 = VM_4_LVL_10_BIT
_VM_PAGE_SIZE = {0: 4096, 1: 4096, 2: 8192}


def vm_invtlb(vm_inst):
    """
    Opcode 0x0F — TLB maintenance / shootdown group (kernel-only).

    See StackVM/Documentation/INVTLB.html and TlbShootdown.html for the model.
    :param VirtualMachine vm_inst:
    """
    op = vm_inst.get_instr_dat(1)
    if op is None:
        vm_inst.ip -= 1
        return
    if vm_inst.priv_lvl != 0:
        vm_inst.trap(INT_PROTECT_FAULT, vm_inst.ip)
        return
    if op == INVTLB_LOCAL:
        # pop order: count, base, tlptr (push order: tlptr, base, count)
        page_count = vm_inst.pop(8)
        vaddr_base = vm_inst.pop(8)
        tlptr = vm_inst.pop(8)
        vm_inst.tlb_invalidate_range(tlptr, vaddr_base, page_count)
    elif op == INVTLB_ALL_LOCAL:
        vm_inst.tlb_flush_all()
    elif op == INVTLB_SINGLE:
        flags = vm_inst.get_instr_dat(1)
        done_core = vm_inst.pop(8) if (flags & INVTLB_F_ASYNC) else None
        page_count = vm_inst.pop(8)
        vaddr_base = vm_inst.pop(8)
        tlptr = vm_inst.pop(8)
        vm_inst.tlb_shootdown([(tlptr, vaddr_base, page_count)], flags, done_core)
    elif op == INVTLB_MULTI:
        flags = vm_inst.get_instr_dat(1)
        done_core = vm_inst.pop(8) if (flags & INVTLB_F_ASYNC) else None
        num_entries = vm_inst.pop(8)
        entry_ptr = vm_inst.pop(8)
        descs = []
        for i in range(num_entries):
            base_e = entry_ptr + i * INVTLB_ENTRY_SIZE
            tlptr = vm_inst.get_as_priv(0, 8, base_e)
            vaddr_base = vm_inst.get_as_priv(0, 8, base_e + 8)
            page_count = vm_inst.get_as_priv(0, 8, base_e + 16)
            descs.append((tlptr, vaddr_base, page_count))
        vm_inst.tlb_shootdown(
            descs, flags, done_core, multi_ptr=entry_ptr, multi_len=num_entries
        )
    elif op == INVTLB_ACK:
        handle = vm_inst.pop(8)
        if vm_inst.ipi_controller is not None:
            vm_inst.ipi_controller.tlb_ack(handle)
    else:
        vm_inst.trap(INT_INVAL_OPCODE, vm_inst.ip)


def vm_load(vm_inst):
    """
    :param VirtualMachine vm_inst:
    """
    a = vm_inst.get_instr_dat(1)
    if a is None:
        vm_inst.ip -= 1
        return
    typ = a & BCR_TYP_MASK
    sz = 1 << ((a & BCR_SZ_MASK) >> 5)
    if typ == BCR_ABS_A4:
        addr = vm_inst.get_instr_dat(4)
        if addr is None:
            vm_inst.ip -= 2
            return
        data = vm_inst.get(sz, addr)
        if data is None:
            vm_inst.ip -= 6
            return
        if not vm_inst.push(sz, data):
            vm_inst.ip -= 6
    elif typ == BCR_ABS_A8:
        addr = vm_inst.get_instr_dat(8)
        if addr is None:
            vm_inst.ip -= 2
            return
        data = vm_inst.get(sz, addr)
        if data is None:
            vm_inst.ip -= 10
            return
        if not vm_inst.push(sz, data):
            vm_inst.ip -= 10
    elif typ == BCR_ABS_S4:
        addr = vm_inst.pop(4)
        if addr is None:
            vm_inst.ip -= 2
            return
        data = vm_inst.get(sz, addr)
        if data is None:
            vm_inst.ip -= 2
            vm_inst.sp -= 4
            return
        if not vm_inst.push(sz, data):
            vm_inst.ip -= 2
            vm_inst.sp -= 4
    elif typ == BCR_ABS_S8:
        addr = vm_inst.pop(8)
        if addr is None:
            vm_inst.ip -= 2
            return
        data = vm_inst.get(sz, addr)
        if data is None:
            vm_inst.ip -= 2
            vm_inst.sp -= 8
            return
        if not vm_inst.push(sz, data):
            vm_inst.ip -= 2
            vm_inst.sp -= 8
    elif (
        typ & BCR_R_BP_MASK == BCR_R_BP_VAL
    ):  # BCR_R_BP1, BCR_R_BP2, BCR_R_BP4, BCR_R_BP8
        n_bytes = 1 << (typ & 0x03)
        addr = vm_inst.get_instr_dat(n_bytes, 1)
        if addr is None:
            vm_inst.ip -= 2
            return
        addr += vm_inst.bp
        data = vm_inst.get(sz, addr)
        if data is None:
            vm_inst.ip -= 2 + n_bytes
            return
        if not vm_inst.push(sz, data):
            vm_inst.ip -= 2 + n_bytes
    elif typ == BCR_ABS_C:
        data = vm_inst.get_instr_dat(sz)
        if data is None:
            vm_inst.ip -= 2
            return
        if not vm_inst.push(sz, data):
            vm_inst.ip -= 2 + sz
    elif typ == BCR_REG_BP:
        if not vm_inst.push(8, vm_inst.bp):
            vm_inst.ip -= 2
    elif typ == BCR_EA_R_IP:
        off = vm_inst.get_instr_dat(sz, 1)
        if off is None:
            vm_inst.ip -= 2
            return
        if not vm_inst.push(8, off + vm_inst.ip):
            vm_inst.ip -= 2 + sz
    elif typ == BCR_TOS:
        data = vm_inst.get(sz, vm_inst.sp)
        if data is None:
            vm_inst.ip -= 2
            return
        if not vm_inst.push(sz, data):
            vm_inst.ip -= 2
    elif typ == BCR_SYSREG:
        which = vm_inst.get_instr_dat(1)
        if which is None:
            vm_inst.ip -= 2
            return
        if not vm_inst.push(8, vm_inst.sys_regs[which]):
            vm_inst.ip -= 3
    elif typ == BCR_ATOMIC_LOAD:
        # [ordering_byte][addr on stack] -> [sz value]  (single-core: regular load)
        _ordering = vm_inst.get_instr_dat(1)  # consume ordering byte
        addr = vm_inst.pop(8)
        if addr is None:
            vm_inst.ip -= 3
            return
        data = vm_inst.get(sz, addr)
        if data is None:
            vm_inst.ip -= 3
            vm_inst.sp -= 8
            return
        vm_inst.push(sz, data)
    elif typ == BCR_ATOMIC_XCHG:
        # [ordering][addr stack] -> [old]; pops [new_val] first
        _ordering = vm_inst.get_instr_dat(1)
        addr = vm_inst.pop(8)
        if addr is None:
            vm_inst.ip -= 3
            return
        new_val = vm_inst.pop(sz)
        if new_val is None:
            vm_inst.ip -= 3
            vm_inst.sp -= 8
            return
        old_val = vm_inst.get(sz, addr)
        if old_val is None:
            vm_inst.ip -= 3
            vm_inst.sp -= 8 + sz
            return
        vm_inst.set(sz, addr, new_val)
        vm_inst.push(sz, old_val)
    elif typ == BCR_ATOMIC_CAS:
        # [ordering][addr stack] -> [old]; pops [desired][expected]
        _ordering = vm_inst.get_instr_dat(1)
        addr = vm_inst.pop(8)
        if addr is None:
            vm_inst.ip -= 3
            return
        expected = vm_inst.pop(sz)
        desired = vm_inst.pop(sz)
        if desired is None:
            vm_inst.ip -= 3
            vm_inst.sp -= 8 + sz
            return
        old_val = vm_inst.get(sz, addr)
        if old_val is None:
            vm_inst.ip -= 3
            vm_inst.sp -= 8 + 2 * sz
            return
        if old_val == expected:
            vm_inst.set(sz, addr, desired)
        vm_inst.push(sz, old_val)
    elif typ in (
        BCR_ATOMIC_FADD,
        BCR_ATOMIC_FSUB,
        BCR_ATOMIC_FAND,
        BCR_ATOMIC_FOR,
        BCR_ATOMIC_FXOR,
    ):
        # [ordering][addr stack] -> [old]; pops [operand]
        _ordering = vm_inst.get_instr_dat(1)
        addr = vm_inst.pop(8)
        if addr is None:
            vm_inst.ip -= 3
            return
        operand = vm_inst.pop(sz)
        if operand is None:
            vm_inst.ip -= 3
            vm_inst.sp -= 8
            return
        old_val = vm_inst.get(sz, addr)
        if old_val is None:
            vm_inst.ip -= 3
            vm_inst.sp -= 8 + sz
            return
        mask = (1 << (8 * sz)) - 1
        if typ == BCR_ATOMIC_FADD:
            new_val = (old_val + operand) & mask
        elif typ == BCR_ATOMIC_FSUB:
            new_val = (old_val - operand) & mask
        elif typ == BCR_ATOMIC_FAND:
            new_val = old_val & operand
        elif typ == BCR_ATOMIC_FOR:
            new_val = old_val | operand
        else:
            new_val = old_val ^ operand  # FXOR
        vm_inst.set(sz, addr, new_val)
        vm_inst.push(sz, old_val)
    else:
        raise ValueError(
            "Unsupported BCR code for BC_LOAD instruction: %u at 0x%X"
            % (typ, vm_inst.ip)
        )


def vm_store(vm_inst):
    """
    :param VirtualMachine vm_inst:
    """
    a = vm_inst.get_instr_dat(1)
    if a is None:
        vm_inst.ip -= 1
        return
    typ = a & BCR_TYP_MASK
    sz = 1 << ((a & BCR_SZ_MASK) >> 5)
    if typ == BCR_ABS_A4:
        addr = vm_inst.get_instr_dat(4)
        if addr is None:
            vm_inst.ip -= 2
            return
        data = vm_inst.pop(sz)
        if data is None:
            vm_inst.ip -= 6
            return
        if not vm_inst.set(sz, addr, data):
            vm_inst.ip -= 6
            vm_inst.sp -= sz
    elif typ == BCR_ABS_A8:
        addr = vm_inst.get_instr_dat(8)
        if addr is None:
            vm_inst.ip -= 2
            return
        data = vm_inst.pop(sz)
        if data is None:
            vm_inst.ip -= 10
            return
        if not vm_inst.set(sz, addr, data):
            vm_inst.ip -= 10
            vm_inst.sp -= sz
    elif typ == BCR_ABS_S4:
        addr = vm_inst.pop(4)
        if addr is None:
            vm_inst.ip -= 2
            return
        data = vm_inst.pop(sz)
        if data is None:
            vm_inst.ip -= 2
            vm_inst.sp -= 4
            return
        if not vm_inst.set(sz, addr, data):
            vm_inst.ip -= 2
            vm_inst.sp -= 4 + sz
    elif typ == BCR_ABS_S8:
        addr = vm_inst.pop(8)
        if addr is None:
            vm_inst.ip -= 2
            return
        data = vm_inst.pop(sz)
        if data is None:
            vm_inst.ip -= 2
            vm_inst.sp -= 8
            return
        if not vm_inst.set(sz, addr, data):
            vm_inst.ip -= 2
            vm_inst.sp -= 8 + sz
    elif (
        typ & BCR_R_BP_MASK == BCR_R_BP_VAL
    ):  # BCR_R_BP1, BCR_R_BP2, BCR_R_BP4, BCR_R_BP8
        n_bytes = 1 << (typ & 0x03)
        addr = vm_inst.get_instr_dat(n_bytes, 1)
        if addr is None:
            vm_inst.ip -= 2
            return
        addr += vm_inst.bp
        vm_inst.set(sz, addr, vm_inst.pop(sz))
    elif typ == BCR_SYSREG:
        which = vm_inst.get_instr_dat(1)
        reg_v = vm_inst.pop(8)
        if which == SVSR_IPI:
            vm_inst.send_ipi(reg_v)
        else:
            vm_inst.sys_regs[which] = reg_v
        if which == SVSR_FLAGS:  # v3: FLAGS is at 0x00
            vm_inst.priv_lvl = (reg_v >> 8) & 1
            vm_inst.priority = reg_v & 0xFF
            vm_inst.virt_mem_mode = (reg_v >> 10) & 0xF
    elif typ == BCR_ATOMIC_STORE:  # 0x08 on STOR: atomic seq-cst store
        # [sz value][8B addr] -> --
        _ordering = vm_inst.get_instr_dat(1)  # consume ordering byte
        addr = vm_inst.pop(8)
        if addr is None:
            vm_inst.ip -= 3
            return
        data = vm_inst.pop(sz)
        if data is None:
            vm_inst.ip -= 3
            vm_inst.sp -= 8
            return
        vm_inst.set(sz, addr, data)
    elif typ == BCR_REG_BP:
        vm_inst.bp = vm_inst.pop(8)
    elif typ in (BCR_FENCE_ALL, BCR_FENCE_LOAD, BCR_FENCE_STORE):
        pass  # single-core emulator: memory fences are no-ops
    else:
        raise ValueError(
            "Unsupported BCR code for BC_STOR instruction: %u at 0x%X"
            % (typ, vm_inst.ip)
        )


def vm_exit(vm_inst):
    """
    :param VirtualMachine vm_inst:
    """
    vm_inst.running = 0


def get_vm_sz_type(conv_typ):
    if conv_typ == 0xC:  # uint128
        return 16, 0
    if conv_typ == 0xD:  # int128
        return 16, 1
    if conv_typ >= 0xE:
        raise NotImplementedError("CONV type code 0x%X not implemented" % conv_typ)
    is_flt = bool(conv_typ & 0x8)
    typ = 2 if is_flt else (conv_typ & 0x1)
    sz = conv_typ & 0x7
    if is_flt:
        sz = 2 << sz
    else:
        sz = 1 << (sz >> 1)
    return sz, typ


def vm_conv(vm_inst):
    """
    :param VirtualMachine vm_inst:
    """
    typ = vm_inst.get_instr_dat(1)
    cnv_typ_i = typ & BCC_I_MASK
    cnv_typ_o = (typ & BCC_O_MASK) >> 4
    sz_i, typ_i = get_vm_sz_type(cnv_typ_i)
    sz_o, typ_o = get_vm_sz_type(cnv_typ_o)
    a = vm_inst.pop(sz_i, typ_i)
    if typ_o == 2:
        a = float(a)
    else:
        a = int(a)
        if a < 0:
            typ_o = 1
    vm_inst.push(sz_o, a, typ_o)


def vm_swap(vm_inst):
    """
    :param VirtualMachine vm_inst:
    """
    typ = vm_inst.get_instr_dat(1)
    sz_cls_a = typ & BCS_SZ_A_MASK
    sz_cls_b = (typ & BCS_SZ_B_MASK) >> 3
    sz_a = 1 << sz_cls_a
    sz_b = 1 << sz_cls_b
    b = vm_inst.pop(sz_b)
    a = vm_inst.pop(sz_a)
    vm_inst.push(sz_b, b)
    vm_inst.push(sz_a, a)


def vm_call_ext(vm_inst):
    """
    :param VirtualMachine vm_inst:
    """
    a = vm_inst.get_instr_dat(1)
    if a & 0x80:
        sys_num_sz_cls = (a >> 5) & 3
        sys_num_sz = (1, 2, 4, 8)[sys_num_sz_cls]
        sys_num = vm_inst.pop(sys_num_sz)
        vm_inst.syscall(sys_num)
        """sys_num = vm_inst.pop()
        if vm_inst.cr4 & 0x3 == vm_inst.virtual_syscalls_lvl:
            vm_inst.virt_syscall(sys_num)
        else:
            num = vm_inst.sys_fn[vm_inst.cr4 & 0x3]
            old_regs = [vm_inst.cr4, vm_inst.ip, vm_inst.sp, vm_inst.bp]  # TODO
            vm_inst.call(num)
        raise NotImplementedError("SysCall (CALL_E with IS_SYS=1) is unsupported")
        """
    else:
        if a & BCCE_IS_INT:  # bit 5: software interrupt
            int_n = vm_inst.get_instr_dat(1)
            if int_n is None:
                vm_inst.ip -= 2
                return
            vm_inst.switch_to_interrupt(int_n)
        elif a & 0x40:
            addr = vm_inst.pop(8)
            vm_inst.call(addr + vm_inst.ip)
        else:
            addr = vm_inst.pop(8)
            vm_inst.call(addr)


def vm_ret_ext(vm_inst):
    """
    :param VirtualMachine vm_inst:
    """
    a = vm_inst.get_instr_dat(1)
    if a & 0x80:
        if a & BCRE_IS_INT:  # bit 6 when IS_SYS=1: IRET
            vm_inst.return_from_interrupt()
        else:
            vm_inst.sysret()
        # raise NotImplementedError("SysCall (CALL_E with IS_SYS=1) is unsupported")
    else:
        sz_cls_rst_sp = (a & 0x60) >> 5
        rst_sp = vm_inst.pop(1 << sz_cls_rst_sp)
        sz_cls_res_sz = (a & 0x18) >> 3
        res_sz = vm_inst.pop(1 << sz_cls_res_sz)
        vm_inst.ret(rst_sp, res_sz)


def vm_sys_ret(vm_inst):
    """
    :param VirtualMachine vm_inst:
    """
    vm_inst.trap(6, vm_inst.ip)
    # del vm_inst
    # raise NotImplementedError("SysCall (CALL_E with IS_SYS=1) is unsupported")


class InterruptApi(object):
    def __init__(self):
        import sys

        self.sys = sys
        self.stdout = sys.stdout
        self.stdin = sys.stdin
        self.read_buf = ""

    def interrupt(self, vm_inst, n):
        """
        :param VirtualMachine vm_inst:
        :param int n:
        """
        if n == 0x29:  # StackVM Pow function
            cmd = vm_inst.get(1, vm_inst.sp)
            if cmd != 0:
                raise NotImplementedError("Not Implemented")
            assert cmd == 0  # double pow(double base, int exponent);
            exponent = vm_inst.get(4, vm_inst.sp + 1)
            if exponent & 0x80000000:
                exponent -= 0x100000000
            base = vm_inst.get_float(8, vm_inst.sp + 5)
            vm_inst.set_float(8, vm_inst.sp + 13, base**exponent)
            return
        if n != 0x21:  # MSDOS "INT 21h"
            raise NotImplementedError("Not Implemented")
        cmd = vm_inst.get(1, vm_inst.sp)
        if cmd == 0x01:  # getchar [int getchar()]
            vm_inst.set(4, vm_inst.sp + 1, ord(self.getchar()))
        elif cmd == 0x02:  # putchar [void putchar(int)]
            ch = vm_inst.get(4, vm_inst.sp + 1)
            ch = chr(ch)
            self.putchar(ch)
            # skip 0x05, 0x06
        elif cmd == 0x07:  # TODO: getch (direct) [int getch()]
            vm_inst.set(4, vm_inst.sp + 1, ord(self.getchar()))
        elif cmd == 0x08:  # TODO: getch [int getch()]
            vm_inst.set(4, vm_inst.sp + 1, ord(self.getchar()))
        elif cmd == 0x09:  # puts [void puts(char *str)]
            addr = vm_inst.get(8, vm_inst.sp + 1)
            byts = bytearray()
            ch = vm_inst.get(1, addr)
            while ch:
                byts.append(ch)
                addr += 1
                ch = vm_inst.get(1, addr)
            byts = bytes(byts)
            self.puts(byts)
        elif cmd == 0x0A:  # gets [UInt64 gets(char *str, UInt64 length)]
            addr = vm_inst.get(8, vm_inst.sp + 1)
            size = vm_inst.get(8, vm_inst.sp + 9)
            length = self.gets_len()
            real_len = min(size, length, len(vm_inst.memory) - addr)
            vm_inst.memory[addr : addr + real_len] = self.read_buf[:real_len]
            self.read_buf = self.read_buf[real_len:]
            vm_inst.set(8, vm_inst.sp + 17, real_len)
        elif cmd == 0x0B:  # get status [UInt64 getStatus()]
            vm_inst.set(8, vm_inst.sp + 1, self.gets_len())

    def putchar(self, ch):
        self.stdout.write(str(ch))

    def puts(self, s):
        self.stdout.write(s.decode("utf-8"))

    def getchar(self):
        if len(self.read_buf) == 0:
            self.read_buf = self.stdin.readline()
        rtn = self.read_buf[0]
        self.read_buf = self.read_buf[1:]
        return rtn

    def gets(self):
        if len(self.read_buf):
            rtn = self.read_buf
            self.read_buf = ""
            return rtn
        else:
            return self.stdin.readline()

    def gets_len(self):
        length = len(self.read_buf)
        if length:
            return length
        self.read_buf = self.stdin.readline()
        return len(self.read_buf)


class AdvProgIntCtl(object):
    """Per-core asynchronous interrupt controller (a small local APIC).

    Hardware / asynchronous sources (timer, IPI, TLB-shootdown, device IRQs)
    post interrupts here with trigger(); the CPU drains the controller between
    instructions (execute_with_interrupts / debug_with_interrupts).  Delivery is
    *gated* by the receiving core's FLAGS register, which the VM evaluates via
    take_deliverable():

      * A maskable interrupt is delivered only when interrupts are enabled
        (FLAGS bit 14) *and* the interrupt is strictly more urgent than the
        current FLAGS priority (lower priority number == more urgent).
      * INT_NMI (0x02) is **non-maskable**: it is delivered regardless of the
        enable bit and the priority mask.

    Unlike the original single-slot mailbox, pending interrupts are held in a
    small queue, so a burst of sources is not silently lost; the queue is
    drained most-urgent-first (FIFO among equal priorities).  Each entry is
      [int_n, arg0, arg1, arg2, arg3, priority]
    where ``priority`` is either an explicit value supplied by the source or
    ``None`` (resolve from the handler's ISR-table FLAGS entry at delivery time).

    The legacy single-slot attributes (int_ready / which_int / arg0..arg3)
    mirror the head of the queue for backward compatibility.
    """

    __slots__ = [
        "int_ready",
        "which_int",
        "arg0",
        "arg1",
        "arg2",
        "arg3",
        "_queue",
        "_nmi",
    ]

    def __init__(self):
        self._queue = []  # list of [int_n, a0, a1, a2, a3, priority|None]
        self._nmi = None  # at most one pending NMI (edge-collapsed), or None
        self._refresh_head()

    def _refresh_head(self):
        """Point the legacy single-slot view at the next pending interrupt."""
        head = self._nmi if self._nmi is not None else (
            self._queue[0] if self._queue else None
        )
        if head is None:
            self.int_ready = False
            self.which_int = 0
            self.arg0 = self.arg1 = self.arg2 = self.arg3 = 0
        else:
            self.int_ready = True
            self.which_int = head[0]
            self.arg0, self.arg1, self.arg2, self.arg3 = head[1], head[2], head[3], head[4]

    def trigger(
        self,
        which_int: int,
        arg0: int = 0,
        arg1: int = 0,
        arg2: int = 0,
        arg3: int = 0,
        priority=None,
    ):
        """Post an interrupt to this core.

        ``priority`` (0-255, lower == more urgent) lets a source pin a delivery
        priority; when ``None`` the VM derives it from the handler's ISR-table
        FLAGS entry.  INT_NMI collapses to a single pending edge (the latest
        wins); all other sources are queued.
        """
        entry = [which_int, arg0, arg1, arg2, arg3, priority]
        if which_int == INT_NMI:
            self._nmi = entry
        else:
            self._queue.append(entry)
        self._refresh_head()

    def pending(self) -> bool:
        """True if any interrupt (NMI or queued) is waiting -- a cheap gate the
        execute loop checks before doing the masking evaluation."""
        return self._nmi is not None or bool(self._queue)

    def take_deliverable(self, enabled: bool, cur_priority: int, priority_of):
        """Remove and return the interrupt that should be delivered now, or None.

        ``enabled``/``cur_priority`` come from the receiving core's FLAGS; an NMI
        is returned regardless of either.  Among queued maskable interrupts, the
        most urgent one whose priority is strictly more urgent (numerically less)
        than ``cur_priority`` is chosen, FIFO breaking ties.  ``priority_of`` maps
        an interrupt number to its ISR-configured priority for entries that did
        not pin one explicitly.
        """
        if self._nmi is not None:
            entry = self._nmi
            self._nmi = None
            self._refresh_head()
            return entry
        if not enabled:
            return None
        best_idx = None
        best_pri = None
        for i, e in enumerate(self._queue):
            p = e[5] if e[5] is not None else priority_of(e[0])
            if p < cur_priority and (best_pri is None or p < best_pri):
                best_pri = p
                best_idx = i
        if best_idx is None:
            return None
        entry = self._queue.pop(best_idx)
        self._refresh_head()
        return entry


class ProgrammableIntervalTimer(object):
    """Programmable interval timer (PIT) that drives the scheduler tick.

    A single periodic/one-shot countdown timer wired to a core's local
    interrupt controller (AdvProgIntCtl).  Its timebase is the core's retired
    instruction count: the CPU calls tick() once per executed instruction -- the
    same boundary at which SVSR_CYCLE_COUNT is incremented.  When the internal
    countdown reaches zero the timer posts INT_TIMER (0x11) into the APIC (where
    it is then subject to the normal FLAGS enable/priority gating) and, if
    periodic, reloads from ``interval``; a one-shot timer disarms itself after it
    fires.

    The timer is *masked* (counts/posts nothing) while ``enabled`` is False or
    ``interval`` is 0.  ``interval`` is the number of cycles between successive
    INT_TIMER posts.  When ``priority`` is None the delivered interrupt inherits
    the priority of the INT_TIMER ISR-table entry (the normal unpinned path);
    pin a value to force a fixed delivery priority.

    Programming is a host-side API for now (program()/arm()/disable()); a
    kernel-facing MMIO timer-register interface arrives with the D5 device
    framework.
    """

    __slots__ = [
        "apic",
        "interval",
        "periodic",
        "enabled",
        "priority",
        "_counter",
        "fire_count",
    ]

    def __init__(
        self,
        apic: AdvProgIntCtl,
        interval: int = 0,
        periodic: bool = True,
        enabled: bool = False,
        priority=None,
    ):
        self.apic = apic
        self.priority = priority
        self.fire_count = 0  # number of INT_TIMER interrupts posted so far
        self.interval = 0
        self.periodic = True
        self.enabled = False
        self._counter = 0
        self.program(interval, periodic=periodic, enabled=enabled, priority=priority)

    def program(self, interval: int, periodic: bool = True, enabled: bool = True,
                priority=None):
        """(Re)program the timer.

        Sets the reload ``interval`` (in cycles), the periodic/one-shot mode and
        whether it is armed, and reloads the countdown to a full interval.  A
        zero/negative interval leaves the timer disabled.  ``priority`` updates
        the pinned delivery priority when not None.
        """
        self.interval = int(interval)
        self.periodic = bool(periodic)
        if priority is not None:
            self.priority = priority
        self.enabled = bool(enabled) and self.interval > 0
        self._counter = self.interval

    def arm(self):
        """Re-arm a programmed timer without changing its interval/mode.  Reloads
        the countdown only if it had already expired (a one-shot that fired)."""
        if self.interval > 0:
            self.enabled = True
            if self._counter <= 0:
                self._counter = self.interval

    def disable(self):
        """Mask the timer without discarding its programmed interval/mode."""
        self.enabled = False

    @property
    def remaining(self) -> int:
        """Cycles until the next INT_TIMER post (0 while masked)."""
        return self._counter if (self.enabled and self.interval > 0) else 0

    def tick(self, cycles: int = 1):
        """Advance the timebase by ``cycles`` retired instructions.

        Posts one INT_TIMER per interval boundary crossed and returns the number
        posted (0 while masked).  Driven once per instruction the common case
        crosses at most one boundary; a larger ``cycles`` step still posts one
        interrupt per boundary, mirroring a real timer whose backlog the APIC
        collapses under masking.
        """
        if not self.enabled or self.interval <= 0:
            return 0
        self._counter -= int(cycles)
        posted = 0
        while self._counter <= 0:
            self.apic.trigger(INT_TIMER, priority=self.priority)
            self.fire_count += 1
            posted += 1
            if not self.periodic:
                self.enabled = False
                self._counter = 0
                break
            self._counter += self.interval
        return posted


class MultiCoreController(object):
    """Minimal coherence / IPI bus shared by a set of StackVM cores.

    Cores register via add_core(); the bus routes inter-processor interrupts and
    TLB-shootdown requests.  TLB shootdowns use the hardware-broadcast model by
    default (sibling TLBs are invalidated directly, without interrupting those
    cores).  The REMOTE_INT fallback instead posts INT_TLB_SHOOTDOWN to the cores
    whose active TLPTRs match the request; those cores acknowledge by executing
    INVTLB_ACK, which the bus routes back to the issuer.

    This is a cooperative (single-threaded) model: cores are stepped explicitly
    by the host.  Each core's mailbox (AdvProgIntCtl) holds a single pending
    interrupt, so the host should let a core service one interrupt before
    another is posted to it.
    """

    def __init__(self):
        self.cores = {}  # core_id -> VirtualMachine
        self._handle_issuer = {}  # shootdown handle -> issuing VirtualMachine

    def add_core(self, vm):
        self.cores[int(vm.sys_regs[SVSR_CORE_ID])] = vm
        vm.ipi_controller = self
        return vm

    def deliver_interrupt(self, core_id, int_n, a0=0, a1=0, a2=0, a3=0):
        vm = self.cores.get(int(core_id))
        if vm is None:
            return False
        if vm.apic is not None:
            vm.apic.trigger(int_n, a0, a1, a2, a3)
        else:
            vm.ipi_log.append(("int", int_n, a0, a1, a2, a3))
        return True

    def send_ipi(self, src, target_core_id, irq, value):
        # General IPI: deliver `irq` as the interrupt vector to the target core.
        self.deliver_interrupt(target_core_id, irq, value)

    def tlb_shootdown(self, src, descs, remote_int, sync, handle):
        """Apply a shootdown to sibling cores; return the number of cores that
        still owe an INVTLB_ACK (only ever non-zero on the async remote-int
        path)."""
        remaining = 0
        for cid, c in self.cores.items():
            if c is src:
                continue
            matches = any(c.tlb_has_tlptr(t) for (t, _b, _n) in descs)
            if remote_int and not sync:
                if matches:
                    self._handle_issuer[handle] = src
                    t, b, n = descs[0]
                    self.deliver_interrupt(cid, INT_TLB_SHOOTDOWN, t, b, n, handle)
                    remaining += 1
            else:
                # Broadcast (and the SYNC fallback): invalidate sibling TLBs
                # directly.  REMOTE_INT additionally posts the request interrupt
                # for observability, but completion does not depend on it.
                for (t, b, n) in descs:
                    c.tlb_invalidate_range(t, b, n)
                if remote_int and matches:
                    t, b, n = descs[0]
                    self.deliver_interrupt(cid, INT_TLB_SHOOTDOWN, t, b, n, 0)
        return remaining

    def tlb_ack(self, handle):
        issuer = self._handle_issuer.get(handle)
        if issuer is None:
            return
        issuer._tlb_ack_one(handle)
        if handle not in issuer._tlb_outstanding:
            self._handle_issuer.pop(handle, None)


def vm_interrupt(vm_inst):
    """
    :param VirtualMachine vm_inst:
    """
    a = vm_inst.get_instr_dat(1)
    # if a > 0x3F: raise NotImplementedError("Not Implemented")
    vm_inst.switch_to_interrupt(a)
    # vm_inst.api.interrupt(vm_inst, a)


def sign_of(a):
    if a > 0:
        return 1
    elif a < 0:
        return -1
    else:
        return 0


def lshift1(b, a):
    return a << b


def rshift1(b, a):
    return a >> b


def lrot1(b, a, n):
    mask = (1 << n) - 1
    b %= n
    return ((a << b) | (a >> (n - b))) & mask


def rrot1(b, a, n):
    mask = (1 << n) - 1
    b %= n
    return ((a >> b) | (a << (n - b))) & mask


def and1(b, a):
    return a & b


def or1(b, a):
    return a | b


def not1(a, n):
    return a ^ ((1 << n) - 1)


def xor1(b, a):
    return a ^ b


def add1(b, a):
    return a + b


def sub1(b, a):
    return a - b


def mul1(b, a):
    return a * b


def div1(b, a):
    return a // b


def fdiv(b, a):
    return a / b


def mod1(b, a):
    return a % b


def cmp1(b, a):
    return sign_of(a - b)


VM_DISABLED = 0
VM_4_LVL_9_BIT = 1
VM_4_LVL_10_BIT = 2

VME_NONE = 0
VME_PAGE_NOT_PRESENT = 1
VME_PAGE_BAD_PERMS = 2


class ObjectIdAllocator(object):
    __slots__ = ["free_list", "objects"]

    def __init__(self, start: int, end: int):
        self.free_list = [(start, end)]
        self.objects = {}

    def acquire_id(self) -> int:
        start, end = self.free_list[0]
        if end - start > 1:
            self.free_list[0] = (start + 1, end)
        else:
            self.free_list.pop(0)
        return start

    def release_id(self, num: int):
        last_index = -1
        free_list = self.free_list
        for c, (start, end) in enumerate(free_list):
            if end > num:
                if start == num + 1:
                    free_list[c] = (num, end)
                    last_index = c
                    break
                elif start <= num:
                    break
                else:
                    free_list.insert(c, (num, num + 1))
                    last_index = c
                    break
            elif end == num:
                if c + 1 < len(free_list):
                    last_index = c + 1
                free_list[c] = (start, end + 1)
        if last_index > 0:
            start_f, end_f = free_list[last_index - 1]
            start_l, end_l = free_list[last_index]
            if end_f >= start_l:
                free_list[last_index - 1] = start_f, end_l
                free_list.pop(last_index)

    def __getitem__(self, idx: int):
        return self.objects[idx]

    def __setitem__(self, idx: int, obj):
        self.objects[idx] = obj

    def __delitem__(self, idx: int):
        del self.objects[idx]
        self.release_id(idx)

    def put(self, obj) -> int:
        idx = self.acquire_id()
        self.objects[idx] = obj
        return idx


WATCH_NONE = 0
WATCH_EXCEPTIONAL = 1
WATCH_WARNING = 2


class SplitMemView(object):
    __slots__ = ["mva", "mvb", "sz"]

    def __init__(self, mva: memoryview, mvb: memoryview):
        self.mva = mva
        self.mvb = mvb
        self.sz = len(mva) + len(mvb)

    def unpack_float(self) -> float:
        sz = self.sz
        assert sz == 4 or sz == 8
        data = bytearray(self.mva)
        data.extend(self.mvb)
        return (float_t if sz == 4 else double_t).unpack(data)[0]

    def pack_float(self, f: float):
        data = (float_t if self.sz == 4 else double_t).pack(f)
        mva = self.mva
        mva[:] = data[: len(mva)]
        self.mvb = data[len(mva) :]

    def pack_int(self, i: int, signed=False):
        data = i.to_bytes(self.sz, "little", signed=signed)
        mva = self.mva
        mva[:] = data[: len(mva)]
        self.mvb = data[len(mva) :]

    def unpack_int(self, signed=False) -> int:
        data = bytearray(self.mva)
        data.extend(self.mvb)
        return int.from_bytes(data, "little", signed=signed)

    def pack_bytes(self, data: Union[bytes, bytearray, memoryview]):
        mva = self.mva
        mva[:] = data[: len(mva)]
        self.mvb = data[len(mva) :]


class VirtualMachine(object):
    BASE_SIZE = 4096
    BC_Dispatch = [
        lambda vm_inst: None,
        vm_exit,
        lambda vm_inst: vm_inst.push(1, vm_inst.pop(1, 1) == 0),
        lambda vm_inst: vm_inst.push(1, vm_inst.pop(1, 1) != 0),
        lambda vm_inst: vm_inst.push(1, vm_inst.pop(1, 1) < 0),
        lambda vm_inst: vm_inst.push(1, vm_inst.pop(1, 1) <= 0),
        lambda vm_inst: vm_inst.push(1, vm_inst.pop(1, 1) > 0),
        lambda vm_inst: vm_inst.push(1, vm_inst.pop(1, 1) >= 0),
        vm_conv,
        vm_swap,
        vm_load,
        vm_store,
        vm_call_ext,
        vm_ret_ext,
        vm_int128,  # 0x0E: INT128 / BITOP extended group
        vm_invtlb,  # 0x0F: INVTLB TLB-invalidation group
        # Bit/Byte Manip
        lambda vm_inst: vm_inst.push(1, lshift1(vm_inst.pop(1), vm_inst.pop(1))),
        lambda vm_inst: vm_inst.push(2, lshift1(vm_inst.pop(1), vm_inst.pop(2))),
        lambda vm_inst: vm_inst.push(4, lshift1(vm_inst.pop(1), vm_inst.pop(4))),
        lambda vm_inst: vm_inst.push(8, lshift1(vm_inst.pop(1), vm_inst.pop(8))),
        lambda vm_inst: vm_inst.push(1, rshift1(vm_inst.pop(1), vm_inst.pop(1))),
        lambda vm_inst: vm_inst.push(2, rshift1(vm_inst.pop(1), vm_inst.pop(2))),
        lambda vm_inst: vm_inst.push(4, rshift1(vm_inst.pop(1), vm_inst.pop(4))),
        lambda vm_inst: vm_inst.push(8, rshift1(vm_inst.pop(1), vm_inst.pop(8))),
        # CLZ — Count Leading Zeros (replaces deprecated LROT)
        lambda vm_inst: vm_inst.push(1, clz1(vm_inst.pop(1), 8)),
        lambda vm_inst: vm_inst.push(1, clz1(vm_inst.pop(2), 16)),
        lambda vm_inst: vm_inst.push(1, clz1(vm_inst.pop(4), 32)),
        lambda vm_inst: vm_inst.push(1, clz1(vm_inst.pop(8), 64)),
        # CTZ — Count Trailing Zeros (replaces deprecated RROT)
        lambda vm_inst: vm_inst.push(1, ctz1(vm_inst.pop(1), 8)),
        lambda vm_inst: vm_inst.push(1, ctz1(vm_inst.pop(2), 16)),
        lambda vm_inst: vm_inst.push(1, ctz1(vm_inst.pop(4), 32)),
        lambda vm_inst: vm_inst.push(1, ctz1(vm_inst.pop(8), 64)),
        # ALU Sign Independent
        lambda vm_inst: vm_inst.push(1, and1(vm_inst.pop(1), vm_inst.pop(1))),
        lambda vm_inst: vm_inst.push(2, and1(vm_inst.pop(2), vm_inst.pop(2))),
        lambda vm_inst: vm_inst.push(4, and1(vm_inst.pop(4), vm_inst.pop(4))),
        lambda vm_inst: vm_inst.push(8, and1(vm_inst.pop(8), vm_inst.pop(8))),
        lambda vm_inst: vm_inst.push(1, or1(vm_inst.pop(1), vm_inst.pop(1))),
        lambda vm_inst: vm_inst.push(2, or1(vm_inst.pop(2), vm_inst.pop(2))),
        lambda vm_inst: vm_inst.push(4, or1(vm_inst.pop(4), vm_inst.pop(4))),
        lambda vm_inst: vm_inst.push(8, or1(vm_inst.pop(8), vm_inst.pop(8))),
        lambda vm_inst: vm_inst.push(1, not1(vm_inst.pop(1), 8)),
        lambda vm_inst: vm_inst.push(2, not1(vm_inst.pop(2), 16)),
        lambda vm_inst: vm_inst.push(4, not1(vm_inst.pop(4), 32)),
        lambda vm_inst: vm_inst.push(8, not1(vm_inst.pop(8), 64)),
        lambda vm_inst: vm_inst.push(1, xor1(vm_inst.pop(1), vm_inst.pop(1))),
        lambda vm_inst: vm_inst.push(2, xor1(vm_inst.pop(2), vm_inst.pop(2))),
        lambda vm_inst: vm_inst.push(4, xor1(vm_inst.pop(4), vm_inst.pop(4))),
        lambda vm_inst: vm_inst.push(8, xor1(vm_inst.pop(8), vm_inst.pop(8))),
        lambda vm_inst: vm_inst.push(1, add1(vm_inst.pop(1), vm_inst.pop(1))),
        lambda vm_inst: vm_inst.push(2, add1(vm_inst.pop(2), vm_inst.pop(2))),
        lambda vm_inst: vm_inst.push(4, add1(vm_inst.pop(4), vm_inst.pop(4))),
        lambda vm_inst: vm_inst.push(8, add1(vm_inst.pop(8), vm_inst.pop(8))),
        lambda vm_inst: vm_inst.push(1, sub1(vm_inst.pop(1), vm_inst.pop(1))),
        lambda vm_inst: vm_inst.push(2, sub1(vm_inst.pop(2), vm_inst.pop(2))),
        lambda vm_inst: vm_inst.push(4, sub1(vm_inst.pop(4), vm_inst.pop(4))),
        lambda vm_inst: vm_inst.push(8, sub1(vm_inst.pop(8), vm_inst.pop(8))),
        lambda vm_inst: vm_inst.add_stack(vm_inst.pop(1)),
        lambda vm_inst: vm_inst.add_stack(vm_inst.pop(2)),
        lambda vm_inst: vm_inst.add_stack(vm_inst.pop(4)),
        lambda vm_inst: vm_inst.add_stack(vm_inst.pop(8)),
        lambda vm_inst: vm_inst.reset_stack(vm_inst.pop(1)),
        lambda vm_inst: vm_inst.reset_stack(vm_inst.pop(2)),
        lambda vm_inst: vm_inst.reset_stack(vm_inst.pop(4)),
        lambda vm_inst: vm_inst.reset_stack(vm_inst.pop(8)),
        # ALU Sign Specific
        lambda vm_inst: vm_inst.push(1, mul1(vm_inst.pop(1), vm_inst.pop(1))),
        lambda vm_inst: vm_inst.push(1, mul1(vm_inst.pop(1, 1), vm_inst.pop(1, 1)), 1),
        lambda vm_inst: vm_inst.push(2, mul1(vm_inst.pop(2), vm_inst.pop(2))),
        lambda vm_inst: vm_inst.push(2, mul1(vm_inst.pop(2, 1), vm_inst.pop(2, 1)), 1),
        lambda vm_inst: vm_inst.push(4, mul1(vm_inst.pop(4), vm_inst.pop(4))),
        lambda vm_inst: vm_inst.push(4, mul1(vm_inst.pop(4, 1), vm_inst.pop(4, 1)), 1),
        lambda vm_inst: vm_inst.push(8, mul1(vm_inst.pop(8), vm_inst.pop(8))),
        lambda vm_inst: vm_inst.push(8, mul1(vm_inst.pop(8, 1), vm_inst.pop(8, 1)), 1),
        lambda vm_inst: vm_inst.push(1, div1(vm_inst.pop(1), vm_inst.pop(1))),
        lambda vm_inst: vm_inst.push(1, div1(vm_inst.pop(1, 1), vm_inst.pop(1, 1)), 1),
        lambda vm_inst: vm_inst.push(2, div1(vm_inst.pop(2), vm_inst.pop(2))),
        lambda vm_inst: vm_inst.push(2, div1(vm_inst.pop(2, 1), vm_inst.pop(2, 1)), 1),
        lambda vm_inst: vm_inst.push(4, div1(vm_inst.pop(4), vm_inst.pop(4))),
        lambda vm_inst: vm_inst.push(4, div1(vm_inst.pop(4, 1), vm_inst.pop(4, 1)), 1),
        lambda vm_inst: vm_inst.push(8, div1(vm_inst.pop(8), vm_inst.pop(8))),
        lambda vm_inst: vm_inst.push(8, div1(vm_inst.pop(8, 1), vm_inst.pop(8, 1)), 1),
        lambda vm_inst: vm_inst.push(1, mod1(vm_inst.pop(1), vm_inst.pop(1))),
        lambda vm_inst: vm_inst.push(1, mod1(vm_inst.pop(1, 1), vm_inst.pop(1, 1)), 1),
        lambda vm_inst: vm_inst.push(2, mod1(vm_inst.pop(2), vm_inst.pop(2))),
        lambda vm_inst: vm_inst.push(2, mod1(vm_inst.pop(2, 1), vm_inst.pop(2, 1)), 1),
        lambda vm_inst: vm_inst.push(4, mod1(vm_inst.pop(4), vm_inst.pop(4))),
        lambda vm_inst: vm_inst.push(4, mod1(vm_inst.pop(4, 1), vm_inst.pop(4, 1)), 1),
        lambda vm_inst: vm_inst.push(8, mod1(vm_inst.pop(8), vm_inst.pop(8))),
        lambda vm_inst: vm_inst.push(8, mod1(vm_inst.pop(8, 1), vm_inst.pop(8, 1)), 1),
        lambda vm_inst: vm_inst.push(1, cmp1(vm_inst.pop(1), vm_inst.pop(1)), 1),
        lambda vm_inst: vm_inst.push(1, cmp1(vm_inst.pop(1, 1), vm_inst.pop(1, 1)), 1),
        lambda vm_inst: vm_inst.push(1, cmp1(vm_inst.pop(2), vm_inst.pop(2)), 1),
        lambda vm_inst: vm_inst.push(1, cmp1(vm_inst.pop(2, 1), vm_inst.pop(2, 1)), 1),
        lambda vm_inst: vm_inst.push(1, cmp1(vm_inst.pop(4), vm_inst.pop(4)), 1),
        lambda vm_inst: vm_inst.push(1, cmp1(vm_inst.pop(4, 1), vm_inst.pop(4, 1)), 1),
        lambda vm_inst: vm_inst.push(1, cmp1(vm_inst.pop(8), vm_inst.pop(8)), 1),
        lambda vm_inst: vm_inst.push(1, cmp1(vm_inst.pop(8, 1), vm_inst.pop(8, 1)), 1),
        # FPU
        lambda vm_inst: vm_inst.push(2, add1(vm_inst.pop(2, 2), vm_inst.pop(2, 2)), 2),
        lambda vm_inst: vm_inst.push(4, add1(vm_inst.pop(4, 2), vm_inst.pop(4, 2)), 2),
        lambda vm_inst: vm_inst.push(8, add1(vm_inst.pop(8, 2), vm_inst.pop(8, 2)), 2),
        lambda vm_inst: vm_inst.push(
            16, add1(vm_inst.pop(16, 2), vm_inst.pop(16, 2)), 2
        ),
        lambda vm_inst: vm_inst.push(2, sub1(vm_inst.pop(2, 2), vm_inst.pop(2, 2)), 2),
        lambda vm_inst: vm_inst.push(4, sub1(vm_inst.pop(4, 2), vm_inst.pop(4, 2)), 2),
        lambda vm_inst: vm_inst.push(8, sub1(vm_inst.pop(8, 2), vm_inst.pop(8, 2)), 2),
        lambda vm_inst: vm_inst.push(
            16, sub1(vm_inst.pop(16, 2), vm_inst.pop(16, 2)), 2
        ),
        lambda vm_inst: vm_inst.push(2, mul1(vm_inst.pop(2, 2), vm_inst.pop(2, 2)), 2),
        lambda vm_inst: vm_inst.push(4, mul1(vm_inst.pop(4, 2), vm_inst.pop(4, 2)), 2),
        lambda vm_inst: vm_inst.push(8, mul1(vm_inst.pop(8, 2), vm_inst.pop(8, 2)), 2),
        lambda vm_inst: vm_inst.push(
            16, mul1(vm_inst.pop(16, 2), vm_inst.pop(16, 2)), 2
        ),
        lambda vm_inst: vm_inst.push(2, fdiv(vm_inst.pop(2, 2), vm_inst.pop(2, 2)), 2),
        lambda vm_inst: vm_inst.push(4, fdiv(vm_inst.pop(4, 2), vm_inst.pop(4, 2)), 2),
        lambda vm_inst: vm_inst.push(8, fdiv(vm_inst.pop(8, 2), vm_inst.pop(8, 2)), 2),
        lambda vm_inst: vm_inst.push(
            16, fdiv(vm_inst.pop(16, 2), vm_inst.pop(16, 2)), 2
        ),
        lambda vm_inst: vm_inst.push(2, mod1(vm_inst.pop(2, 2), vm_inst.pop(2, 2)), 2),
        lambda vm_inst: vm_inst.push(4, mod1(vm_inst.pop(4, 2), vm_inst.pop(4, 2)), 2),
        lambda vm_inst: vm_inst.push(8, mod1(vm_inst.pop(8, 2), vm_inst.pop(8, 2)), 2),
        lambda vm_inst: vm_inst.push(
            16, mod1(vm_inst.pop(16, 2), vm_inst.pop(16, 2)), 2
        ),
        lambda vm_inst: vm_inst.push(1, cmp1(vm_inst.pop(2), vm_inst.pop(2)), 1),
        lambda vm_inst: vm_inst.push(1, cmp1(vm_inst.pop(4), vm_inst.pop(4)), 1),
        lambda vm_inst: vm_inst.push(1, cmp1(vm_inst.pop(8), vm_inst.pop(8)), 1),
        lambda vm_inst: vm_inst.push(1, cmp1(vm_inst.pop(16), vm_inst.pop(16)), 1),
        # Control Flow
        lambda vm_inst: vm_inst.set_ip(vm_inst.pop(8)),
        lambda vm_inst: vm_inst.set_ip_if(vm_inst.pop(8), vm_inst.pop(1)),
        lambda vm_inst: vm_inst.set_ip(vm_inst.pop(8, 1) + vm_inst.ip),
        lambda vm_inst: vm_inst.set_ip_if(
            vm_inst.pop(8, 1) + vm_inst.ip, vm_inst.pop(1)
        ),
        lambda vm_inst: vm_inst.call(vm_inst.pop(8)),
        lambda vm_inst: vm_inst.call(vm_inst.pop(8, 1) + vm_inst.ip),
        lambda vm_inst: vm_inst.ret(),
        lambda vm_inst: vm_inst.trap(
            INT_INVAL_OPCODE, vm_inst.ip
        ),  # 0x7F: reserved (IRET folded into RET_E)
    ]
    assert BC_Dispatch[BC_LOAD] is vm_load
    assert BC_Dispatch[BC_STOR] is vm_store
    assert BC_Dispatch[BC_HLT] is vm_exit
    assert len(BC_Dispatch) == 128

    def __init__(self, heap_sz=16384, stack_sz=4096):
        self.api = InterruptApi()
        self.sys_regs = array.array("Q", [0] * 19)
        self.priority = 255
        self.priv_lvl = 1
        self.sys_regs[SVSR_FLAGS] = self.priority | (self.priv_lvl << 8)
        self.memory = bytearray(heap_sz + stack_sz)
        self.watch_memory = WATCH_NONE
        self.watch_points = []
        self.ip = 0
        self.sp = len(self.memory)
        self.bp = self.sp
        self.ax = 0
        self.running = 1
        self.objects = ObjectIdAllocator(0, 1 << 64)
        self.pyg_index = -1
        self.apic = None
        # Optional ProgrammableIntervalTimer driving INT_TIMER / the scheduler
        # tick.  Advanced once per retired instruction by the interrupt-aware
        # execution loops (and step); None means no timer is attached.
        self.timer = None
        self.ipi_log = []
        self.ipi_controller = None
        self.virt_mem_mode = VM_DISABLED
        # FLAGS bit 9: 0 => kernel may fall back to USER_TLPTR; 1 => the vaddr MSB
        # selects the address space (see SYSREG.html / _select_tlptrs).
        self.vaddr_msb_eq_priv = 0
        self.virt_error_code = VME_NONE
        self.dbg_walk_page = False

        # 0: page_table_entry that points to the table where the entry was expected (or 0 if top level )
        # 1: pointer offset into page table to find the faulting entry (if top level this is the full tlpte)
        # 2: reason/level:
        #    level is bits 0,1,2
        #    reason is bits 3,4,5,6,7
        #       0 for page not present, 1 for bad write perms, 2 for bad execute perms
        # 3: the address being resolved
        self.virt_error_data = (0,) * 4
        self.virtualize_syscalls = (
            True  # True if virtualizing syscalls from USER to KERNEL
        )
        self.watch_data = []
        # ---- Software TLB ---------------------------------------------------
        # Per-core translation cache.  Key: (tlptr, page_aligned_vaddr).
        # Value: [phys_page_base, validated_perm_mask] where the mask records
        # which access modes (TLBP_R/W/X) have already been validated through a
        # full page-table walk for this entry.  The TLB may only hold entries
        # belonging to the two currently-active TLPTRs (kernel + user); this is
        # enforced lazily by _tlb_check_switch() whenever a TLPTR changes.
        self.tlb = {}
        self._tlb_tag = [None, None]  # last-seen active TLPTR per priv slot (0,1)
        # Outstanding ASYNC shootdowns issued by this core: handle -> record.
        self._tlb_outstanding = {}
        self._tlb_next_handle = 1

    def set_core_id(self, core_id: int):
        self.sys_regs[SVSR_CORE_ID] = int(core_id)

    def send_ipi(self, value: int):
        value = int(value) & ((1 << 64) - 1)
        self.sys_regs[SVSR_IPI] = value
        target_core_id = value & 0xFF
        irq = (value >> 8) & 0xFF
        if self.ipi_controller is not None:
            self.ipi_controller.send_ipi(self, target_core_id, irq, value)
        elif self.apic is not None and target_core_id == self.sys_regs[SVSR_CORE_ID]:
            self.apic.trigger(irq, self.sys_regs[SVSR_CORE_ID], value)
        else:
            self.ipi_log.append((target_core_id, irq, value))

    # -----------------------------------------------------------------------
    # Software TLB + TLB shootdown
    # -----------------------------------------------------------------------
    def active_tlptr(self, priv_lvl: int) -> int:
        """Top-level page-table base used to translate addresses at *priv_lvl*.

        Kernel (priv 0) uses SVSR_KERNEL_TLPTR (0x08); user (priv 1) uses
        SVSR_USER_TLPTR (0x09), per the architectural register layout in
        SYSREG.html.  This is the value walk_page() consumes; the TLB is tagged
        with it and shootdown requests self-filter against the two active TLPTRs.
        """
        return self.sys_regs[SVSRB_TLPTR + priv_lvl]

    def tlb_has_tlptr(self, tlptr: int) -> bool:
        """True if *tlptr* is one of this core's two active TLPTRs (kernel/user).

        A shootdown for a TLPTR that is not active here can be safely ignored.
        """
        return (
            tlptr == self.sys_regs[SVSR_KERNEL_TLPTR]
            or tlptr == self.sys_regs[SVSR_USER_TLPTR]
        )

    def _tlb_page_size(self) -> int:
        return _VM_PAGE_SIZE.get(self.virt_mem_mode, 4096)

    def _tlb_check_switch(self):
        """Enforce the invariant that the TLB only holds entries for the two
        currently-active TLPTRs (KERNEL_TLPTR + USER_TLPTR).  Called lazily on
        each translation: if either TLPTR changed, evict entries belonging to the
        replaced value (unless it is still referenced by the other slot)."""
        for slot in (0, 1):
            cur = self.active_tlptr(slot)
            old = self._tlb_tag[slot]
            if cur == old:
                continue
            if old is not None and old != self.active_tlptr(slot ^ 1):
                self.tlb_flush_tlptr(old)
            self._tlb_tag[slot] = cur

    def _select_tlptrs(self, virt_addr: int, priv_lvl: int):
        """Ordered TLPTRs to try when translating *virt_addr* at *priv_lvl*, per
        the access model in SYSREG.html.  An empty tuple means the access is not
        permitted (fault).  Both modes allow the kernel to reach user space."""
        K = self.sys_regs[SVSR_KERNEL_TLPTR]
        U = self.sys_regs[SVSR_USER_TLPTR]
        if self.vaddr_msb_eq_priv:
            # The MSB of the virtual address selects the address space.
            if (virt_addr >> 63) & 1:
                return (U,)  # user half: kernel and user both use USER_TLPTR
            return (K,) if priv_lvl == 0 else ()  # kernel half: kernel only
        # MSB-independent: kernel tries KERNEL_TLPTR then falls back to USER_TLPTR.
        if priv_lvl == 0:
            return (K, U)
        return (U,)

    def tlb_invalidate_range(self, tlptr: int, vaddr_base: int, page_count: int):
        """Remove TLB entries for *page_count* pages starting at *vaddr_base*
        under address space *tlptr* (no-op for pages not currently cached)."""
        if not self.tlb:
            return
        page_size = self._tlb_page_size()
        base = vaddr_base - (vaddr_base % page_size)
        tlb = self.tlb
        for i in range(page_count):
            tlb.pop((tlptr, base + i * page_size), None)

    def tlb_flush_tlptr(self, tlptr: int):
        """Remove every TLB entry belonging to address space *tlptr*."""
        if not self.tlb:
            return
        for key in [k for k in self.tlb if k[0] == tlptr]:
            del self.tlb[key]

    def tlb_flush_all(self):
        """Flush this core's entire TLB."""
        self.tlb.clear()
        self._tlb_tag = [None, None]

    def _tlb_alloc_handle(self) -> int:
        """Allocate a globally-unique shootdown handle (core id in the high bits)."""
        h = (int(self.sys_regs[SVSR_CORE_ID]) << 32) | self._tlb_next_handle
        self._tlb_next_handle += 1
        return h

    def tlb_shootdown(self, descs, flags, done_core, multi_ptr=None, multi_len=None):
        """Issue a TLB shootdown for the list of (tlptr, vaddr_base, page_count)
        descriptors.  *flags* selects SYNC/ASYNC, broadcast/remote-int, and
        whether to also invalidate the issuing core."""
        also_local = bool(flags & INVTLB_F_ALSO_LOCAL)
        remote_int = bool(flags & INVTLB_F_REMOTE_INT)
        is_async = bool(flags & INVTLB_F_ASYNC)
        if also_local:
            for (tlptr, base, count) in descs:
                self.tlb_invalidate_range(tlptr, base, count)
        ctrl = self.ipi_controller
        if is_async:
            handle = self._tlb_alloc_handle()
            done = (
                int(self.sys_regs[SVSR_CORE_ID]) if done_core is None else int(done_core)
            )
            if multi_ptr is not None:
                comp_args = (multi_ptr, multi_len, 0, 0)
            elif descs:
                t, b, n = descs[0]
                comp_args = (t, b, n, 0)
            else:
                comp_args = (0, 0, 0, 0)
            rec = {"remaining": 0, "done_core": done, "args": comp_args}
            self._tlb_outstanding[handle] = rec
            if ctrl is not None:
                rec["remaining"] = ctrl.tlb_shootdown(
                    self, descs, remote_int=remote_int, sync=False, handle=handle
                )
            if rec["remaining"] == 0:
                self._tlb_complete(handle)
        else:
            # SYNC: cannot block the issuing core in a cooperative emulator, so
            # the controller applies the invalidation to siblings synchronously
            # (broadcast).  REMOTE_INT additionally posts the request interrupt
            # to matching cores for observability but never gates completion.
            if ctrl is not None:
                ctrl.tlb_shootdown(
                    self, descs, remote_int=remote_int, sync=True, handle=0
                )

    def _tlb_ack_one(self, handle: int):
        """A remote core acknowledged completion of a remote-interrupt shootdown."""
        rec = self._tlb_outstanding.get(handle)
        if rec is None:
            return
        rec["remaining"] -= 1
        if rec["remaining"] <= 0:
            self._tlb_complete(handle)

    def _tlb_complete(self, handle: int):
        """Finalise an ASYNC shootdown: deliver INT_TLB_SHOOTDOWN_DONE to done_core."""
        rec = self._tlb_outstanding.pop(handle, None)
        if rec is None:
            return
        done = rec["done_core"]
        a0, a1, a2, a3 = rec["args"]
        ctrl = self.ipi_controller
        if ctrl is not None and done != int(self.sys_regs[SVSR_CORE_ID]):
            ctrl.deliver_interrupt(done, INT_TLB_SHOOTDOWN_DONE, a0, a1, a2, a3)
        elif self.apic is not None:
            self.apic.trigger(INT_TLB_SHOOTDOWN_DONE, a0, a1, a2, a3)
        else:
            self.ipi_log.append(("tlb_done", done, a0, a1, a2, a3))

    def check_perm_set_or_clr_error(
        self,
        pte_top: int,
        pte_index: int,
        pte_ptr: int,
        pte: int,
        virt_addr: int,
        mem_req_perms: int,
    ):
        PTE_WRITE_BIT = 0x002
        PTE_EXEC_BIT = 0x004
        PTE_DIRTY_BIT = 0x008
        dbg_walk_page = self.dbg_walk_page
        if mem_req_perms != MRQ_DONT_CHECK and mem_req_perms != MRQ_READ:
            if dbg_walk_page:
                print("checking permissions")
            if mem_req_perms == MRQ_WRITE:
                if pte & PTE_WRITE_BIT == 0:
                    if dbg_walk_page:
                        print("bad permissions")
                    self.virt_error_code = VME_PAGE_BAD_PERMS
                    self.virt_error_data = (pte_top, pte_index, (1 << 3) | 4, virt_addr)
                    return
                elif pte & PTE_DIRTY_BIT == 0:
                    pte |= PTE_DIRTY_BIT
                    if dbg_walk_page:
                        print("write back page table DIRTY")
                    self.memory[pte_ptr : pte_ptr + 8] = pte.to_bytes(8, "little")
            elif mem_req_perms == MRQ_EXEC:
                if pte & PTE_EXEC_BIT == 0:
                    self.virt_error_code = VME_PAGE_BAD_PERMS
                    self.virt_error_data = (pte_top, pte_index, (2 << 3) | 4, virt_addr)
                    return
        self.virt_error_code = VME_NONE
        self.virt_error_data = (0, 0, 0, 0)

    def walk_page(
        self, virt_addr, tlpte, virt_mode=VM_4_LVL_9_BIT, mem_req_perms=MRQ_DONT_CHECK
    ) -> Optional[int]:
        # tlpte: top level page table entry
        mem = memoryview(self.memory)
        PTE_VALID_BIT = 0x001
        PTE_WRITE_BIT = 0x002
        PTE_EXEC_BIT = 0x004
        PTE_DIRTY_BIT = 0x008
        PTE_HUGE_BIT = 0x010
        from_bytes = int.from_bytes
        dbg_walk_page = self.dbg_walk_page
        if virt_mode == VM_4_LVL_9_BIT:
            PTE_MASK = 0xFFFFFFFFFFFFF000
            PTE4_HMASK, PTE4_LMASK = 0xFFFFFF8000000000, 0x7FFFFFFFFF
            PTE3_HMASK, PTE3_LMASK = 0xFFFFFFFFC0000000, 0x3FFFFFFF
            PTE2_HMASK, PTE2_LMASK = 0xFFFFFFFFFFE00000, 0x1FFFFF
            if dbg_walk_page:
                print("resolving from tlpte")
            if (tlpte & PTE_VALID_BIT) == 0:
                self.virt_error_code = VME_PAGE_NOT_PRESENT
                self.virt_error_data = (0, tlpte, (0 << 3) | 0, virt_addr)
                # self.trap(INT_PAGE_FAULT, 0, virt_addr, 0)
                return
            pte_4_index = ((virt_addr >> 39) & 0x1FF) << 3
            pte_4_ptr = (tlpte & PTE_MASK) | pte_4_index
            if dbg_walk_page:
                print("resolved pte_4_ptr=%016X from tlpte" % pte_4_ptr)
            pte_4 = from_bytes(mem[pte_4_ptr : pte_4_ptr + 8], "little")
            if dbg_walk_page:
                print("resolved pte_4=%016X" % pte_4)
            if (pte_4 & PTE_VALID_BIT) == 0:
                self.virt_error_code = VME_PAGE_NOT_PRESENT
                self.virt_error_data = (tlpte, pte_4_index, (0 << 3) | 1, virt_addr)
                # self.trap(INT_PAGE_FAULT, pte_4_ptr, virt_addr, 1)
                return
            elif pte_4 & PTE_HUGE_BIT:
                self.check_perm_set_or_clr_error(
                    tlpte, pte_4_ptr, pte_4_index, pte_4, virt_addr, mem_req_perms
                )
                return (pte_4 & PTE4_HMASK) | (virt_addr & PTE4_LMASK)
            pte_3_index = ((virt_addr >> 30) & 0x1FF) << 3
            pte_3_ptr = (pte_4 & PTE_MASK) | pte_3_index
            if dbg_walk_page:
                print("resolved pte_3_ptr=%016X from pte_4" % pte_3_ptr)
            pte_3 = from_bytes(mem[pte_3_ptr : pte_3_ptr + 8], "little")
            if dbg_walk_page:
                print("resolved pte_3=%016X" % pte_3)
            if (pte_3 & PTE_VALID_BIT) == 0:
                self.virt_error_code = VME_PAGE_NOT_PRESENT
                self.virt_error_data = (pte_4, pte_3_index, (0 << 3) | 2, virt_addr)
                # self.trap(INT_PAGE_FAULT, pte_3_ptr, virt_addr, 2)
                return
            elif pte_3 & PTE_HUGE_BIT:
                self.check_perm_set_or_clr_error(
                    pte_4, pte_3_ptr, pte_3_index, pte_3, virt_addr, mem_req_perms
                )
                return (pte_3 & PTE3_HMASK) | (virt_addr & PTE3_LMASK)
            pte_2_index = ((virt_addr >> 21) & 0x1FF) << 3
            pte_2_ptr = (pte_3 & PTE_MASK) | pte_2_index
            if dbg_walk_page:
                print("resolved pte_2_ptr=%016X from pte_3" % pte_2_ptr)
            pte_2 = from_bytes(mem[pte_2_ptr : pte_2_ptr + 8], "little")
            if dbg_walk_page:
                print("resolved pte_2=%016X" % pte_2)
            if (pte_2 & PTE_VALID_BIT) == 0:
                self.virt_error_code = VME_PAGE_NOT_PRESENT
                self.virt_error_data = (pte_3, pte_2_index, (0 << 3) | 3, virt_addr)
                # self.trap(INT_PAGE_FAULT, pte_2_ptr, virt_addr, 3)
                return
            elif pte_2 & PTE_HUGE_BIT:
                self.check_perm_set_or_clr_error(
                    pte_3, pte_2_ptr, pte_2_index, pte_2, virt_addr, mem_req_perms
                )
                return (pte_2 & PTE2_HMASK) | (virt_addr & PTE2_LMASK)
            pte_1_index = ((virt_addr >> 12) & 0x1FF) << 3
            pte_1_ptr = (pte_2 & PTE_MASK) | pte_1_index
            if dbg_walk_page:
                print("resolved pte_1_ptr=%016X from pte_2" % pte_1_ptr)
            pte_1 = from_bytes(mem[pte_1_ptr : pte_1_ptr + 8], "little")
            if dbg_walk_page:
                print("resolved pte_1=%016X" % pte_1)
            if (pte_1 & PTE_VALID_BIT) == 0:
                self.virt_error_code = VME_PAGE_NOT_PRESENT
                self.virt_error_data = (pte_2, pte_1_index, (0 << 3) | 4, virt_addr)
                # self.trap(INT_PAGE_FAULT, pte_1_ptr, virt_addr, 4)
                return
            self.check_perm_set_or_clr_error(
                pte_2, pte_1_ptr, pte_1_index, pte_1, virt_addr, mem_req_perms
            )
            return (pte_1 & PTE_MASK) | (virt_addr & 0xFFF)  # , pte_1 & 0xFFF
        elif virt_mode == VM_4_LVL_10_BIT:
            PTE_MASK = 0xFFFFFFFFFFFFE000
            PTE4_HMASK, PTE4_LMASK = 0xFFFFF80000000000, 0x7FFFFFFFFFF
            PTE3_HMASK, PTE3_LMASK = 0xFFFFFFFE00000000, 0x1FFFFFFFF
            PTE2_HMASK, PTE2_LMASK = 0xFFFFFFFFFF800000, 0x7FFFFF
            if dbg_walk_page:
                print("resolving from tlpte")
            # pte_4_ptr = (tlpte & PTE_MASK) | ((virt_addr >> 43) & 0x3ff)
            # pte_4 = from_bytes(mem[pte_4_ptr:pte_4_ptr + 8], "little")
            # pte_3_ptr = (pte_4 & PTE_MASK) | ((virt_addr >> 33) & 0x3ff)
            # pte_3 = from_bytes(mem[pte_3_ptr:pte_3_ptr + 8], "little")
            # pte_2_ptr = (pte_3 & PTE_MASK) | ((virt_addr >> 23) & 0x3ff)
            # pte_2 = from_bytes(mem[pte_2_ptr:pte_2_ptr + 8], "little")
            # pte_1_ptr = (pte_2 & PTE_MASK) | ((virt_addr >> 13) & 0x3ff)
            # pte_1 = from_bytes(mem[pte_1_ptr:pte_1_ptr + 8], "little")
            # return (pte_1 & PTE_MASK) | (virt_addr & 0x1FFF), pte_1 & 0x1FFF
            if (tlpte & PTE_VALID_BIT) == 0:
                self.virt_error_code = VME_PAGE_NOT_PRESENT
                self.virt_error_data = (0, tlpte, (0 << 3) | 0, virt_addr)
                # self.trap(INT_PAGE_FAULT, 0, virt_addr, 0)
                return
            pte_4_index = ((virt_addr >> 43) & 0x3FF) << 3
            pte_4_ptr = (tlpte & PTE_MASK) | pte_4_index
            if dbg_walk_page:
                print("resolved pte_4_ptr=%016X from tlpte" % pte_4_ptr)
            pte_4 = from_bytes(mem[pte_4_ptr : pte_4_ptr + 8], "little")
            if dbg_walk_page:
                print("resolved pte_4=%016X" % pte_4)
            if (pte_4 & PTE_VALID_BIT) == 0:
                self.virt_error_code = VME_PAGE_NOT_PRESENT
                self.virt_error_data = (tlpte, pte_4_index, (0 << 3) | 1, virt_addr)
                # self.trap(INT_PAGE_FAULT, pte_4_ptr, virt_addr, 1)
                return
            elif pte_4 & PTE_HUGE_BIT:
                self.check_perm_set_or_clr_error(
                    tlpte, pte_4_ptr, pte_4_index, pte_4, virt_addr, mem_req_perms
                )
                return (pte_4 & PTE4_HMASK) | (virt_addr & PTE4_LMASK)
            pte_3_index = ((virt_addr >> 33) & 0x3FF) << 3
            pte_3_ptr = (pte_4 & PTE_MASK) | pte_3_index
            if dbg_walk_page:
                print("resolved pte_3_ptr=%016X from pte_4" % pte_3_ptr)
            pte_3 = from_bytes(mem[pte_3_ptr : pte_3_ptr + 8], "little")
            if dbg_walk_page:
                print("resolved pte_3=%016X" % pte_3)
            if (pte_3 & PTE_VALID_BIT) == 0:
                self.virt_error_code = VME_PAGE_NOT_PRESENT
                self.virt_error_data = (pte_4, pte_3_index, (0 << 3) | 2, virt_addr)
                # self.trap(INT_PAGE_FAULT, pte_3_ptr, virt_addr, 2)
                return
            elif pte_3 & PTE_HUGE_BIT:
                self.check_perm_set_or_clr_error(
                    pte_4, pte_3_ptr, pte_3_index, pte_3, virt_addr, mem_req_perms
                )
                return (pte_3 & PTE3_HMASK) | (virt_addr & PTE3_LMASK)
            pte_2_index = ((virt_addr >> 23) & 0x3FF) << 3
            pte_2_ptr = (pte_3 & PTE_MASK) | pte_2_index
            if dbg_walk_page:
                print("resolved pte_2_ptr=%016X from pte_3" % pte_2_ptr)
            pte_2 = from_bytes(mem[pte_2_ptr : pte_2_ptr + 8], "little")
            if dbg_walk_page:
                print("resolved pte_2=%016X" % pte_2)
            if (pte_2 & PTE_VALID_BIT) == 0:
                self.virt_error_code = VME_PAGE_NOT_PRESENT
                self.virt_error_data = (pte_3, pte_2_index, (0 << 3) | 3, virt_addr)
                # self.trap(INT_PAGE_FAULT, pte_2_ptr, virt_addr, 3)
                return
            elif pte_2 & PTE_HUGE_BIT:
                self.check_perm_set_or_clr_error(
                    pte_3, pte_2_ptr, pte_2_index, pte_2, virt_addr, mem_req_perms
                )
                return (pte_2 & PTE2_HMASK) | (virt_addr & PTE2_LMASK)
            pte_1_index = ((virt_addr >> 13) & 0x3FF) << 3
            pte_1_ptr = (pte_2 & PTE_MASK) | pte_1_index
            if dbg_walk_page:
                print("resolved pte_1_ptr=%016X from pte_2" % pte_1_ptr)
            pte_1 = from_bytes(mem[pte_1_ptr : pte_1_ptr + 8], "little")
            if dbg_walk_page:
                print("resolved pte_1=%016X" % pte_1)
            if (pte_1 & PTE_VALID_BIT) == 0:
                self.virt_error_code = VME_PAGE_NOT_PRESENT
                self.virt_error_data = (pte_2, pte_1_index, (0 << 3) | 4, virt_addr)
                # self.trap(INT_PAGE_FAULT, pte_1_ptr, virt_addr, 4)
                return
            if mem_req_perms != MRQ_DONT_CHECK and mem_req_perms != MRQ_READ:
                if dbg_walk_page:
                    print("checking permissions")
                if mem_req_perms == MRQ_WRITE:
                    if pte_1 & PTE_WRITE_BIT == 0:
                        if dbg_walk_page:
                            print("bad permissions")
                        self.virt_error_code = VME_PAGE_BAD_PERMS
                        self.virt_error_data = (
                            pte_2,
                            pte_1_index,
                            (1 << 3) | 4,
                            virt_addr,
                        )
                        return
                    elif pte_1 & PTE_DIRTY_BIT == 0:
                        pte_1 |= PTE_DIRTY_BIT
                        if dbg_walk_page:
                            print("write back page table DIRTY")
                        mem[pte_1_ptr : pte_1_ptr + 8] = pte_1.to_bytes(8, "little")
                elif mem_req_perms == MRQ_EXEC:
                    if pte_1 & PTE_EXEC_BIT == 0:
                        self.virt_error_code = VME_PAGE_BAD_PERMS
                        self.virt_error_data = (
                            pte_2,
                            pte_1_index,
                            (2 << 3) | 4,
                            virt_addr,
                        )
            self.virt_error_code = VME_NONE
            self.virt_error_data = (0, 0, 0, 0)
            return (pte_1 & PTE_MASK) | (virt_addr & 0x1FFF)  # , pte_1 & 0x1FFF

    def syscall(self, n: int):
        if self.priv_lvl == 0:
            self.trap(INT_INVAL_SYSCALL, 1)
            return
        if self.virtualize_syscalls:
            self.virt_syscall(n)
            return
        pl = self.priv_lvl - 1
        sys_tgt = self.sys_regs[SVSRB_SYS_FN | pl]
        bp = self.bp
        ip = self.ip
        sp = self.sp

        tgt_sp = self.sys_regs[SVSRB_SP | pl]
        # copy bytes
        sz_copy = self.get(8, sp) + 8
        tgt_sp -= sz_copy
        self.copy_within(sp, sz_copy, tgt_sp)

        # save stack pointer in sys_reg
        self.sys_regs[SVSRB_SP | self.priv_lvl] = sp + sz_copy

        # push syscall number, base pointer, instruction pointer
        self.sp = tgt_sp
        self.push(8, n)
        self.push(8, bp)
        self.push(8, ip)
        self.bp = self.sp

        self.ip = sys_tgt
        self.priv_lvl = pl
        self.sys_regs[SVSR_FLAGS] = self.priority | (self.priv_lvl << 8)

    def sysret(self):
        if self.priv_lvl == 3:
            self.trap(INT_INVAL_SYSCALL, 2)
            return
        pl = self.priv_lvl + 1
        sys_tgt = self.sys_regs[SVSRB_SYS_FN | pl]
        tgt_sp = self.sys_regs[SVSRB_SP | pl]
        bp = self.bp
        sp = self.sp
        # copy return bytes
        sz_copy = self.get(8, sp)
        tgt_sp -= sz_copy
        self.copy_within(sp, sz_copy, tgt_sp)
        # restore sys stack
        sp = bp
        prev_ip = self.get(8, sp)
        sp += 8
        prev_bp = self.get(8, sp)
        sp += 16
        num_bytes = self.get(8, sp)
        sp += 8 + num_bytes
        self.sys_regs[SVSRB_SP | self.priv_lvl] = sp
        # go back to original location
        self.sp = tgt_sp
        self.bp = prev_bp
        self.ip = prev_ip
        self.priv_lvl = pl
        self.sys_regs[SVSR_FLAGS] = self.priority | (self.priv_lvl << 8)

    def copy_within(self, src: int, size: int, tgt: int):
        mem = self.memory
        size = min(size, len(mem) - tgt, len(mem) - src)
        mem[tgt : tgt + size] = mem[src : src + size]

    def trap(
        self, int_n: int, arg0: int = 0, arg1: int = 0, arg2: int = 0, arg3: int = 0
    ):
        raise Exception(
            "interrupt %u (%s), reasons: %016X, %016X, %016X, %016X"
            % (int_n, INT_LST[int_n], arg0, arg1, arg2, arg3)
        )

    def extract_zstr(self, addr: int, encoding: str) -> Optional[str]:
        data = bytearray()
        v = self.get(1, addr)
        if v is None:
            return
        while v:
            data.append(v)
            addr += 1
            v = self.get(1, addr)
            if v is None:
                return
        return data.decode(encoding)

    def virt_syscall(self, n: int):
        # n is syscall number
        if n == 0x21:
            from sys import stdout

            addr = self.get(8, self.sp + 8)
            if addr is None:
                return
            # for c in range(0, 48, 8):
            #     v = self.get(8, self.sp + c)
            #     print("%016X@0x%04X (off = %u)" % (v, self.sp + c, c))
            # print("addr = 0x%04X" % addr)
            s = self.extract_zstr(addr, "utf8")
            stdout.write(s)
        elif n == 0x01:
            a = self.get(8, self.sp + 8)
            b = self.get(8, self.sp + 16)
            c = self.get(8, self.sp + 24)
            d = self.get(8, self.sp + 32)
            self.set(8, self.sp + 32, 1234)
            print(a, b, c, d)
        elif n == 0x02:  # pygame_init
            import pygame

            idx = self.objects.put(pygame)
            self.pyg_index = idx
            self.set(8, self.sp + 32, idx)  # return idx as the object id
        elif n == 0x03:  # display_init
            a = self.get(8, self.sp + 8)
            pygame = self.objects[a]
            pygame.display.init()
        elif n == 0x04:  # font_init
            a = self.get(8, self.sp + 8)
            pygame = self.objects[a]
            pygame.font.init()
        elif n == 0x05:  # display_set_mode
            a = self.get(8, self.sp + 8)
            b = self.get(8, self.sp + 16)
            if a is None or b is None:
                return
            pygame = self.objects[a]
            surf = pygame.display.set_mode((b & 0xFFFFFFFF, b >> 32))
            idx = self.objects.put(surf)
            self.set(8, self.sp + 32, idx)  # return idx as the object id
        elif n == 0x06:  # Surface.fill
            a = self.get(8, self.sp + 8)  # surf obj index
            b = self.get(
                8, self.sp + 16
            )  # color/flags  LO-DWORD: color 0x??RRGGBB, HI-DWORD: flags
            c = self.get(8, self.sp + 24)  # rect left, top
            d = self.get(8, self.sp + 32)  # rect width, height
            # import pygame
            pygame = self.objects[self.pyg_index]
            surf = self.objects[a]
            assert isinstance(surf, pygame.Surface)
            # print("in_virt: b = 0x%08X" % b)
            color = ((b & 0xFF0000) >> 16, (b & 0xFF00) >> 8, b & 0xFF)
            # print("in_virt: color =", color)
            flags = b >> 32
            surf.fill(
                color, pygame.Rect(c & 0xFFFFFFFF, c >> 32, d & 0xFFFFFFFF, d >> 32)
            )
        elif n == 0x07:  # pygame.display.update
            a = self.get(8, self.sp + 8)  # pygame
            b = self.get(8, self.sp + 16)  # pointer to array of rects to update
            c = self.get(8, self.sp + 24)  # length of array of rects to update
            pygame = self.objects[a]
            if c:
                lst_rects = [
                    pygame.Rect(
                        self.get(4, off),
                        self.get(4, off + 4),
                        self.get(4, off + 8),
                        self.get(4, off + 12),
                    )
                    for off in range(b, b + c * 16)
                ]
                pygame.display.update(lst_rects)
            else:
                pygame.display.update()
        elif n == 0x08:
            a = self.get(8, self.sp + 8)
            pygame = self.objects[a]
            pygame.quit()
        elif n == 0x09:
            a = self.get(8, self.sp + 8)
            pygame = self.objects[a]
            self.set(
                8, self.sp + 32, self.objects.put(pygame.event.wait())
            )  # return idx as the object id
        elif n == 0x0A:  # delete object
            idx = self.get(8, self.sp + 8)
            del self.objects[idx]
        elif n == 0x0B:  # get event info
            a = self.get(8, self.sp + 8)  # pygame
            b = self.get(8, self.sp + 16)
            c = self.get(8, self.sp + 24)  # ptr to the event
            pygame = self.objects[a]
            evt = self.objects[b]
            self.set(4, c, evt.type)
            if evt.type == pygame.KEYDOWN:
                self.set(4, c + 4, evt.key)
                self.set(4, c + 8, evt.mod)
                self.set(4, c + 12, ord(evt.unicode) if len(evt.unicode) else 0)
            elif evt.type == pygame.KEYUP:
                self.set(4, c + 4, evt.key)
                self.set(4, c + 8, evt.mod)
            elif evt.type == pygame.MOUSEMOTION:
                btns = 0
                for i, b in enumerate(evt.buttons):
                    btns |= b << i
                self.set(4, c + 4, btns)
                self.set(4, c + 8, evt.pos[0])
                self.set(4, c + 12, evt.pos[1])
                self.set(4, c + 16, evt.rel[0])
                self.set(4, c + 20, evt.rel[1])
            elif evt.type == pygame.MOUSEBUTTONDOWN:
                self.set(4, c + 4, evt.button)
                self.set(4, c + 8, evt.pos[0])
                self.set(4, c + 12, evt.pos[1])
            elif evt.type == pygame.MOUSEBUTTONUP:
                self.set(4, c + 4, evt.button)
                self.set(4, c + 8, evt.pos[0])
                self.set(4, c + 12, evt.pos[1])
        elif n == 0x0C:  # get event type number by string key
            a = self.get(8, self.sp + 8)  # pygame
            b = self.get(8, self.sp + 16)  # pointer to string
            attr = self.extract_zstr(b, "utf8")
            pygame = self.objects[a]
            res = 0xFFFFFFFFFFFFFFFF
            try:
                res = getattr(pygame, attr)
            except:
                pass
            else:
                if not isinstance(res, int):
                    res = 0xFFFFFFFFFFFFFFFF
            self.set(8, self.sp + 32, res)
        else:
            print("WARN: unrecognized syscall number %u" % n)

    def load_program(self, memory, at_addr=0, in_virt_space=True):
        """
        :param bytearray memory:
        :param int at_addr:
        :param bool in_virt_space:
        in_virt_space = true if you want to load the program in continuous virtual address space
        NOTE: if using virtual memory, only page aligned loads are supported
        in_virt_space = false for continuous physical address space
        """
        in_virt_space = in_virt_space and self.virt_mem_mode != VM_DISABLED
        if in_virt_space:
            mem_v = memoryview(memory)
            page_size = {VM_4_LVL_9_BIT: 4096, VM_4_LVL_10_BIT: 8192}[
                self.virt_mem_mode
            ]
            page_mask = page_size - 1
            assert at_addr & page_mask == 0, "must load progam at page boundary"
            end = at_addr + len(memory)
            end1 = (end | page_mask) ^ page_mask
            for addr in range(at_addr, end1, page_size):
                mv = self.get_mv_as_priv(self.priv_lvl, page_size, addr, MRQ_DONT_CHECK)
                mv[:] = mem_v[addr : addr + page_size]
            if end1 != end:
                mv = self.get_mv_as_priv(
                    self.priv_lvl, end - end1, end1, MRQ_DONT_CHECK
                )
                mv[:] = mem_v[end1:]
        else:
            a = len(memory)
            b = len(self.memory)
            if a > b:
                raise ValueError(
                    "Not Enough memory (given %u bytes when only %u are available"
                    % (a, b)
                )
            a += at_addr
            if a > b:
                raise ValueError(
                    "Not Enough memory (given %u minus offset bytes when only %u are available"
                    % (a, b)
                )
            self.memory[at_addr:a] = memory

    def _tlb_translate_under(self, tlptr, addr, vmd, permissions, page_mask):
        """Translate a single-page-contained access under a specific *tlptr* via
        the software TLB.  Returns the physical address, or None with
        ``self.virt_error_code`` set on fault (the caller decides whether to try a
        fallback TLPTR or raise).  On a miss (or an access mode not yet validated
        for a cached entry) a full page-table walk is performed and the successful
        result is cached, so a stale entry persists until INVTLB invalidates it."""
        vpn = addr & page_mask
        key = (tlptr, vpn)
        ent = self.tlb.get(key)
        pbit = _MRQ_TO_TLBP.get(permissions, 0)
        if ent is not None and (pbit == 0 or (ent[1] & pbit)):
            self.virt_error_code = VME_NONE
            return ent[0] | (addr - vpn)
        phys = self.walk_page(addr, tlptr, vmd, permissions)
        if self.virt_error_code:
            return None
        if ent is None:
            self.tlb[key] = [phys & page_mask, pbit]
        else:
            ent[0] = phys & page_mask
            ent[1] |= pbit
        return phys

    def _translate(self, addr, priv_lvl, permissions, page_mask, vmd, use_tlb):
        """Resolve *addr* to a physical address using the TLPTR-selection model
        (see _select_tlptrs), trying the kernel→user fallback where applicable.
        Returns the physical address, or None after raising the appropriate fault
        interrupt."""
        candidates = self._select_tlptrs(addr, priv_lvl)
        if not candidates:
            # Access not permitted at this privilege (e.g. user touching kernel
            # space while vaddr_msb_eq_priv is set).
            self.virt_error_code = VME_PAGE_BAD_PERMS
            self.virt_error_data = (0, 0, permissions, addr)
            self.trap(INT_PROTECT_FAULT, *self.virt_error_data)
            return None
        last = len(candidates) - 1
        for i, tlptr in enumerate(candidates):
            if use_tlb:
                phys = self._tlb_translate_under(
                    tlptr, addr, vmd, permissions, page_mask
                )
            else:
                phys = self.walk_page(addr, tlptr, vmd, permissions)
                if self.virt_error_code:
                    phys = None
            if phys is not None:
                return phys
            if i == last:
                ec = self.virt_error_code
                if ec == VME_PAGE_NOT_PRESENT:
                    self.trap(INT_PAGE_FAULT, *self.virt_error_data)
                elif ec == VME_PAGE_BAD_PERMS:
                    self.trap(INT_PROTECT_FAULT, *self.virt_error_data)
                return None
        return None

    def get_mv_as_priv(
        self, priv_lvl: int, sz: int, addr: int, permissions: int
    ) -> Optional[Union[memoryview, SplitMemView]]:
        vmd = self.virt_mem_mode
        if vmd == VM_4_LVL_10_BIT:
            assert sz <= 8192
        elif vmd == VM_4_LVL_9_BIT:
            assert sz <= 4096
        if vmd:
            self._tlb_check_switch()
            page_mask = [0, 0xFFFFFFFFFFFFF000, 0xFFFFFFFFFFFFE000, 0xFFFFF000][vmd]
            if sz > 1 and (addr & page_mask) != ((addr + sz - 1) & page_mask):
                # Access straddles a page boundary: translate both pages with
                # full walks (the TLB fast-path only handles single-page access).
                phys_addr = self._translate(
                    addr, priv_lvl, permissions, page_mask, vmd, False
                )
                if phys_addr is None:
                    return
                index_mask = [0, 0xFFF, 0x1FFF, 0xFFF][vmd]
                index_mask_p1 = index_mask + 1
                addr1 = self._translate(
                    addr + index_mask_p1, priv_lvl, permissions, page_mask, vmd, False
                )
                if addr1 is None:
                    return
                sz0 = index_mask_p1 - (addr1 & index_mask)
                sz1 = (addr1 + sz) & index_mask
                addr = phys_addr
                mem = memoryview(self.memory)
                if addr + sz0 > len(mem):
                    raise IndexError(
                        "Memory address out of bounds (Sz = %u, addr = %u)"
                        % (sz0, addr)
                    )
                elif addr1 + sz1 > len(mem):
                    raise IndexError(
                        "Memory address out of bounds (Sz = %u, addr = %u)"
                        % (sz1, addr1)
                    )
                if self.watch_memory:
                    assert (
                        self.watch_memory == 1
                    ), "Only Exceptional watchpoints are supported"
                    for i, (perm, pt) in enumerate(self.watch_points):
                        if perm != permissions:
                            continue
                        if addr <= pt < addr + sz0 or addr1 <= pt < addr1 + sz1:
                            raise Warning(
                                "Watchpoint %u encountered (perm = %u, pt = %u)"
                                % (i, perm, pt)
                            )
                return SplitMemView(mem[addr : addr + sz0], mem[addr1 : addr1 + sz1])
            phys_addr = self._translate(
                addr, priv_lvl, permissions, page_mask, vmd, True
            )
            if phys_addr is None:
                return
            addr = phys_addr
        mem = memoryview(self.memory)
        assert isinstance(addr, int)
        assert isinstance(sz, int)
        if addr + sz > len(mem):
            raise IndexError(
                "Memory address out of bounds (Sz = %u, addr = %u)" % (sz, addr)
            )
        if self.watch_memory:
            assert self.watch_memory == 1, "Only Exceptional watchpoints are supported"
            for i, (perm, pt) in enumerate(self.watch_points):
                if perm != permissions:
                    continue
                if addr <= pt < addr + sz:
                    raise Warning(
                        "Watchpoint %u encountered (perm = %u, pt = %u)" % (i, perm, pt)
                    )
        return mem[addr : addr + sz]

    def get_as_priv(self, priv_lvl: int, sz: int, addr: int) -> Optional[int]:
        mem = self.get_mv_as_priv(priv_lvl, sz, addr, MRQ_READ)
        if isinstance(mem, memoryview):
            return int.from_bytes(mem, "little", signed=False)
        elif isinstance(mem, SplitMemView):
            return mem.unpack_int(False)

    def get(self, sz: int, addr: int) -> Optional[int]:
        assert isinstance(addr, int)
        assert isinstance(sz, int)
        mem = self.get_mv_as_priv(self.priv_lvl, sz, addr, MRQ_READ)
        if isinstance(mem, memoryview):
            return int.from_bytes(mem, "little", signed=False)
        elif isinstance(mem, SplitMemView):
            return mem.unpack_int(False)

    def get_float(self, sz: int, addr: int) -> Optional[float]:
        assert sz in [2, 4, 8, 16]
        mem = self.get_mv_as_priv(self.priv_lvl, sz, addr, MRQ_READ)
        if isinstance(mem, memoryview):
            if sz == 8:
                return double_t.unpack(mem)[0]
            elif sz == 4:
                return float_t.unpack(mem)[0]
        elif isinstance(mem, SplitMemView):
            return mem.unpack_float()

    def set(self, sz: int, addr: int, v: int) -> bool:
        mem = self.get_mv_as_priv(self.priv_lvl, sz, addr, MRQ_WRITE)
        if isinstance(mem, memoryview):
            mem[:] = v.to_bytes(sz, "little", signed=v < 0)
            return True
        elif isinstance(mem, SplitMemView):
            mem.pack_int(v, signed=v < 0)
            return True
        return False

    def set_float(self, sz: int, addr: int, v: float) -> bool:
        assert sz in [2, 4, 8, 16]
        mem = self.get_mv_as_priv(self.priv_lvl, sz, addr, MRQ_WRITE)
        if isinstance(mem, memoryview):
            if sz == 8:
                double_t.pack_into(mem, 0, v)
            elif sz == 4:
                float_t.pack_into(mem, 0, v)
            else:
                raise NotImplementedError("Not Implemented")
            return True
        elif isinstance(mem, SplitMemView):
            mem.pack_float(v)
            return True
        return False

    def set_bytes(self, addr: int, data: Union[memoryview, bytes, bytearray]) -> bool:
        mem = self.get_mv_as_priv(self.priv_lvl, len(data), addr, MRQ_WRITE)
        if isinstance(mem, memoryview):
            mem[:] = data
            return True
        elif isinstance(mem, SplitMemView):
            mem.pack_bytes(data)
            return True
        return False

    def set_ip(self, v: int):
        self.ip = v

    def set_ip_if(self, v: int, b: bool):
        if b:
            self.ip = v

    def call(self, addr: int):
        self.push(8, self.bp)
        self.push(8, self.ip)
        self.ip = addr
        self.bp = self.sp

    def ret(self, n: int = 0, r_sz: int = 0):
        self.ax = bytes(self.memory[self.sp : self.sp + r_sz])
        self.sp = self.bp
        self.ip = self.pop(8)
        self.bp = self.pop(8)
        if n > 0:
            self.sp += n

    def reset_stack(self, n: int):
        self.sp += n

    def add_stack(self, n: int):
        self.sp -= n

    """
    def swap(self, sz: int):
        a = self.pop(sz)
        b = self.pop(sz)
        self.push(sz, a)
        self.push(sz, b)
    """

    def _push(self, sz: int, val: Union[int, float], typ: int = 0) -> bool:
        # typ must be 0 for unsigned 1 for signed, 2 for float
        assert typ == 0 or typ == 1 or typ == 2, "Unrecognized TypeId %u" % typ
        mem = self.get_mv_as_priv(self.priv_lvl, sz, self.sp - sz, MRQ_WRITE)
        if isinstance(mem, memoryview):
            if typ == 0 or typ == 1:
                mask = 1 << (8 * sz)
                if -(mask >> 1) <= val < 0:
                    val += mask
                elif val < -(mask >> 1):
                    val %= mask
                elif val >= mask:
                    val &= mask - 1
                mem[:] = val.to_bytes(sz, "little", signed=False)
            elif typ == 2:
                if sz == 4:
                    float_t.pack_into(mem, 0, val)
                elif sz == 8:
                    double_t.pack_into(mem, 0, val)
                else:
                    raise TypeError("Cannot have a %u byte float" % sz)
        elif isinstance(mem, SplitMemView):
            if typ == 0 or typ == 1:
                mask = 1 << (8 * sz)
                if -(mask >> 1) <= val < 0:
                    val += mask
                elif val < -(mask >> 1):
                    val %= mask
                elif val >= mask:
                    val &= mask - 1
                mem.pack_int(val)
            elif typ == 2:
                mem.pack_float(val)
        else:
            return False
        self.sp -= sz
        return True

    def get_instr_dat(self, sz: int, typ: int = 0) -> Optional[Union[int, float]]:
        # typ must be 0 for unsigned 1 for signed, 2 for float
        assert typ == 0 or typ == 1 or typ == 2, "Unrecognized TypeId %u" % typ
        mem = self.get_mv_as_priv(self.priv_lvl, sz, self.ip, MRQ_EXEC)
        rtn = 0
        if isinstance(mem, memoryview):
            if typ == 0:
                rtn = int.from_bytes(mem, "little", signed=False)
            elif typ == 1:
                rtn = int.from_bytes(mem, "little", signed=True)
            elif typ == 2:
                if sz == 4:
                    rtn = float_t.unpack(mem)[0]
                elif sz == 8:
                    rtn = double_t.unpack(mem)[0]
                else:
                    raise TypeError("Cannot have a %u byte float" % sz)
        elif isinstance(mem, SplitMemView):
            if typ == 0:
                rtn = mem.unpack_int()
            elif typ == 1:
                rtn = mem.unpack_int(True)
            elif typ == 2:
                rtn = mem.unpack_float()
        else:
            return
        self.ip += sz
        return rtn

    def _pop(self, sz: int, typ: int = 0) -> Optional[Union[int, float]]:
        # typ must be 0 for unsigned 1 for signed, 2 for float
        assert typ == 0 or typ == 1 or typ == 2, "Unrecognized TypeId %u" % typ
        mem = self.get_mv_as_priv(self.priv_lvl, sz, self.sp, MRQ_READ)
        rtn = 0
        if isinstance(mem, memoryview):
            if typ == 0:
                rtn = int.from_bytes(mem, "little", signed=False)
            elif typ == 1:
                rtn = int.from_bytes(mem, "little", signed=True)
            elif typ == 2:
                if sz == 4:
                    rtn = float_t.unpack(mem)[0]
                elif sz == 8:
                    rtn = double_t.unpack(mem)[0]
                else:
                    raise TypeError("Cannot have a %u byte float" % sz)
        elif isinstance(mem, SplitMemView):
            if typ == 0:
                rtn = mem.unpack_int()
            elif typ == 1:
                rtn = mem.unpack_float()
            elif typ == 2:
                rtn = mem.unpack_float()
        else:
            return
        self.sp += sz
        return rtn

    def push_watched(self, sz, val, typ=0):
        self.watch_data.append((sz, val))
        return self._push(sz, val, typ)

    def pop_watched(self, sz, typ=0):
        val = self._pop(sz, typ)
        self.watch_data.append((-sz, val))
        return val

    def enable_watch(self):
        self.push = self.push_watched
        self.pop = self.pop_watched

    def disable_watch(self):
        del self.push
        del self.pop

    push = _push
    pop = _pop

    def execute(self):
        BC_Dispatch = self.BC_Dispatch
        get_instr_dat = self.get_instr_dat
        self.apic = None
        while self.running:
            code = get_instr_dat(1, 0)
            try:
                BC_Dispatch[code](self)
            except IndexError:
                print("@ location", self.ip - 1, hex(code))
                if code >= len(BC_Dispatch):
                    self.ip -= 1
                    self.trap(INT_INVAL_OPCODE, code, self.ip)
                else:
                    raise

    def execute_with_interrupts(self, apic: AdvProgIntCtl, timer=None):
        BC_Dispatch = self.BC_Dispatch
        get_instr_dat = self.get_instr_dat
        self.apic = apic
        if timer is not None:
            self.timer = timer
        timer = self.timer
        sys_regs = self.sys_regs
        while self.running:
            code = get_instr_dat(1, 0)
            try:
                BC_Dispatch[code](self)
            except IndexError:
                if code >= len(BC_Dispatch):
                    self.ip -= 1
                    self.trap(INT_INVAL_OPCODE, code, self.ip)
                else:
                    raise
            sys_regs[SVSR_CYCLE_COUNT] = (
                sys_regs[SVSR_CYCLE_COUNT] + 1
            ) & 0xFFFFFFFFFFFFFFFF
            if timer is not None:
                timer.tick()
            if apic.pending():
                self.deliver_pending_interrupt(apic)

    def _isr_priority(self, int_n: int) -> int:
        """Priority an interrupt would run at, taken from its ISR-table FLAGS
        entry's priority field.  Used to mask deliveries when a source did not
        pin an explicit priority.  An uninitialised/unreadable table yields 0
        (most urgent) so delivery still proceeds and surfaces the missing-handler
        error in switch_to_interrupt rather than silently stalling."""
        isr_base = self.sys_regs[SVSR_ISR]
        if isr_base == 0:
            return 0
        isr_flags = self.get_as_priv(0, 8, isr_base + int_n * 16)
        if isr_flags is None:
            return 0
        return isr_flags & FLAGS_PRIORITY_MASK

    def deliver_pending_interrupt(self, apic: AdvProgIntCtl):
        """Drain at most one interrupt from *apic*, honouring the FLAGS
        interrupt-enable bit (bit 14) and the priority mask (NMI bypasses both).

        Returns the delivered interrupt number, or None if everything pending is
        currently masked.  Delivery raises the new handler's priority via its ISR
        FLAGS, so any still-pending, less-urgent interrupts naturally stay queued
        until IRET lowers the priority again.
        """
        flags = self.sys_regs[SVSR_FLAGS]
        enabled = bool(flags & FLAGS_INT_ENABLE)
        cur_priority = flags & FLAGS_PRIORITY_MASK
        entry = apic.take_deliverable(enabled, cur_priority, self._isr_priority)
        if entry is None:
            return None
        int_n, a0, a1, a2, a3, _pri = entry
        self.switch_to_interrupt_direct(int_n, a0, a1, a2, a3)
        return int_n

    def switch_to_interrupt(self, int_n: int, error_code: int = 0):
        """
        Enter an interrupt handler.  Builds the v3 interrupt frame on the kernel
        stack and jumps to the ISR from SVSR_ISR table entry int_n.

        Frame layout (48 bytes, bp = sp after setup):
          [bp+0]:  int_num        <- TOS
          [bp+8]:  error_code
          [bp+16]: saved_flags
          [bp+24]: user_bp
          [bp+32]: user_sp
          [bp+40]: user_ip
        """
        user_ip = self.ip
        user_sp = self.sp
        user_bp = self.bp
        saved_flags = self.sys_regs[SVSR_FLAGS]

        # Look up 16-byte ISR entry: [8B isr_flags][8B handler_addr]
        isr_base = self.sys_regs[SVSR_ISR]
        if isr_base == 0:
            raise Exception(
                "interrupt %u (%s): ISR table not initialised (SVSR_ISR == 0)"
                % (int_n, INT_LST[int_n])
            )
        isr_flags = self.get_as_priv(0, 8, isr_base + int_n * 16)
        handler = self.get_as_priv(0, 8, isr_base + int_n * 16 + 8)
        if handler == 0:
            raise Exception(
                "interrupt %u (%s): no handler registered (ISR entry handler == 0)"
                % (int_n, INT_LST[int_n])
            )
        isr_priv = (isr_flags >> 8) & 1  # privilege level for this handler

        # Save caller's stack pointer, then switch to the ISR privilege's stack
        self.sys_regs[SVSRB_SP + self.priv_lvl] = self.sp
        self.sp = self.sys_regs[SVSRB_SP + isr_priv]

        # Push v3 frame (user_ip first -> highest address = bp+40 after all pushes)
        self.push(8, user_ip)  # bp+40
        self.push(8, user_sp)  # bp+32
        self.push(8, user_bp)  # bp+24
        self.push(8, saved_flags)  # bp+16
        self.push(8, error_code)  # bp+8
        self.push(8, int_n)  # bp+0  <- TOS
        self.bp = self.sp

        # Apply ISR flags: sets priv_lvl, priority, virt_mem_mode
        self.set_flags(isr_flags)

        self.ip = handler

    def switch_to_interrupt_direct(
        self,
        int_n: int,
        arg0: int = 0,
        arg1: int = 0,
        arg2: int = 0,
        arg3: int = 0,
    ):
        """
        Trigger an interrupt from within VM logic (e.g. a page fault) or from an
        asynchronous source (timer, IPI, TLB shootdown).  Uses the same v3 frame
        format as switch_to_interrupt.  arg0..arg3 are delivered to the handler
        through the read-only interrupt-argument system registers SVSR_INT_ARG0..3
        (the frame error_code stays 0).
        """
        self.sys_regs[SVSR_INT_ARG0] = arg0 & 0xFFFFFFFFFFFFFFFF
        self.sys_regs[SVSR_INT_ARG1] = arg1 & 0xFFFFFFFFFFFFFFFF
        self.sys_regs[SVSR_INT_ARG2] = arg2 & 0xFFFFFFFFFFFFFFFF
        self.sys_regs[SVSR_INT_ARG3] = arg3 & 0xFFFFFFFFFFFFFFFF
        self.switch_to_interrupt(int_n, 0)

    def return_from_interrupt(self):
        """
        IRET: restore state from the v3 interrupt frame and return to user/kernel code.

        Frame offsets (relative to sp = bp on entry to handler):
          [sp+0]:  int_num   (discard)
          [sp+8]:  error_code (discard)
          [sp+16]: saved_flags
          [sp+24]: user_bp
          [sp+32]: user_sp
          [sp+40]: user_ip
        """
        sp = self.sp
        # int_num and error_code are discarded on return
        saved_flags = self.get(8, sp + 16)
        user_bp = self.get(8, sp + 24)
        user_sp = self.get(8, sp + 32)
        user_ip = self.get(8, sp + 40)

        # Prevent privilege escalation: cannot IRET to a higher privilege level (lower number)
        ret_priv = (saved_flags >> 8) & 1
        if ret_priv < self.priv_lvl:
            self.switch_to_interrupt(INT_PROTECT_FAULT, 0)
            return

        # Save current kernel SP so the next interrupt can resume cleanly
        self.sys_regs[SVSR_KERNEL_SP] = sp + 48

        # Restore user state
        self.set_flags(saved_flags)  # restores priv_lvl, priority, virt_mem_mode
        self.bp = user_bp
        self.sp = user_sp
        self.ip = user_ip

    def debug(self, brk_points):
        get_instr_dat = self.get_instr_dat
        BC_Dispatch = self.BC_Dispatch
        self.apic = None
        while self.running:
            if self.ip in brk_points:
                return True
            code = get_instr_dat(1, 0)
            try:
                BC_Dispatch[code](self)
            except IndexError:
                print("@ location", self.ip - 1, hex(code))
                if code >= len(BC_Dispatch):
                    self.ip -= 1
                    self.trap(INT_INVAL_OPCODE, code, self.ip)
                else:
                    raise
        return False

    def debug_with_interrupts(self, brk_points, apic: AdvProgIntCtl, timer=None):
        BC_Dispatch = self.BC_Dispatch
        get_instr_dat = self.get_instr_dat
        self.apic = apic
        if timer is not None:
            self.timer = timer
        timer = self.timer
        sys_regs = self.sys_regs
        while self.running:
            if self.ip in brk_points:
                return True
            code = get_instr_dat(1, 0)
            try:
                BC_Dispatch[code](self)
            except IndexError:
                if code >= len(BC_Dispatch):
                    self.ip -= 1
                    self.trap(INT_INVAL_OPCODE, code, self.ip)
                else:
                    raise
            sys_regs[SVSR_CYCLE_COUNT] = (
                sys_regs[SVSR_CYCLE_COUNT] + 1
            ) & 0xFFFFFFFFFFFFFFFF
            if timer is not None:
                timer.tick()
            if apic.pending():
                self.deliver_pending_interrupt(apic)
        return False

    def step(self):
        if not self.running:
            return False
        code = self.get_instr_dat(1, 0)
        try:
            self.BC_Dispatch[code](self)
        except IndexError:
            if code >= len(self.BC_Dispatch):
                self.ip -= 1
                self.trap(INT_INVAL_OPCODE, code, self.ip)
            else:
                raise
        self.sys_regs[SVSR_CYCLE_COUNT] = (
            self.sys_regs[SVSR_CYCLE_COUNT] + 1
        ) & 0xFFFFFFFFFFFFFFFF
        if self.timer is not None:
            self.timer.tick()
        return True

    def get_stack_list(self, most_recent_call_last=False):
        ip = self.ip
        bp = self.bp
        rtn = [(ip, bp)]
        while bp < len(self.memory):
            ip = self.get(8, bp)
            bp = self.get(8, bp + 8)
            rtn.append((ip, bp))
        if most_recent_call_last:
            rtn.reverse()
        return rtn

    def print_stack_trace(self, most_recent_call_last=False):
        print(
            "\n".join(
                [
                    "CodeAddr = 0x%04X, BasePointer = 0x%04X" % (ip, bp)
                    for ip, bp in self.get_stack_list(most_recent_call_last)
                ]
            )
        )

    def test_load(self, bcr: int, *args: int):
        typ = bcr & BCR_TYP_MASK
        sz_cls = (bcr & BCR_SZ_MASK) >> 5
        size = 1 << sz_cls
        if typ in [BCR_R_BP1, BCR_R_BP2, BCR_R_BP4, BCR_R_BP8]:
            assert len(args) == 1
            return self.get(size, self.bp + args[0])
        else:
            raise NotImplementedError("Not Implemented")

    def test_set_sp(self, pl: int, sp: int):
        assert pl in [0, 1, 2, 3]
        self.sys_regs[SVSRB_SP | pl] = sp
        if self.priv_lvl == pl:
            self.sp = sp

    def test_set_sys_fn(self, pl: int, sys_fn_ptr: int):
        assert pl in [0, 1, 2, 3]
        self.sys_regs[SVSRB_SYS_FN | pl] = sys_fn_ptr

    def test_set_flags(self, priority: int, priv_lvl: int):
        assert isinstance(priority, int) and 0 <= priority <= 0xFF
        assert priv_lvl in [0, 1, 2, 3]
        self.sys_regs[SVSR_FLAGS] = priority | (priv_lvl << 8)
        self.priv_lvl = priv_lvl
        self.priority = priority

    def set_flags_pri_priv(self, priority: int, priv_lvl: int):
        mem_mode = self.sys_regs[SVSR_FLAGS] & 0x3C00
        self.sys_regs[SVSR_FLAGS] = (
            priority | (priv_lvl << 8) | (self.vaddr_msb_eq_priv << 9) | mem_mode
        )
        self.priv_lvl = priv_lvl
        self.priority = priority

    def set_flags_pri_priv_mmd(self, priority: int, priv_lvl: int, mem_mode: int):
        self.sys_regs[SVSR_FLAGS] = (
            priority | (priv_lvl << 8) | (self.vaddr_msb_eq_priv << 9) | (mem_mode << 10)
        )
        self.priv_lvl = priv_lvl
        self.priority = priority
        self.virt_mem_mode = mem_mode

    def set_mem_mode(self, mem_mode: int):
        assert mem_mode & 0xF == mem_mode
        flags = self.sys_regs[SVSR_FLAGS]
        flags |= 0xF << 10
        flags ^= 0xF << 10
        flags |= mem_mode << 10
        self.virt_mem_mode = mem_mode

    def set_flags(self, flags: int):
        self.sys_regs[SVSR_FLAGS] = flags
        self.priv_lvl = (flags >> 8) & 3
        self.priority = flags & 0xFF
        self.vaddr_msb_eq_priv = (flags >> 9) & 1
        self.virt_mem_mode = (flags >> 10) & 0xF


VM = VirtualMachine


def run_stack_vm_tests():
    vm = VM(512, 256)
    try:
        vm.load_program(bytearray([BC_LOAD, BCR_EA_R_IP | BCR_SZ_1, 12, BC_HLT]))
        vm.execute()
        v = vm.pop(8)
        assert v == 15, "got %u" % v
        vm.load_program(
            bytearray(
                [
                    BC_LOAD,
                    BCR_ABS_C | BCR_SZ_1,
                    13,
                    BC_LOAD,
                    BCR_ABS_C | BCR_SZ_1,
                    21,
                    BC_ADD1,
                    BC_HLT,
                ]
            )
        )
        vm.ip, vm.sp = 0, len(vm.memory)
        vm.bp, vm.running = vm.sp, 1
        vm.execute()
        v = vm.pop(1)
        assert v == 13 + 21, "got %u" % v
        vm.memory[6] = BC_SUB1
        vm.ip, vm.sp = 0, len(vm.memory)
        vm.bp, vm.running = vm.sp, 1
        vm.execute()
        v = vm.pop(1, 1)
        assert v == 13 - 21, "got %i" % v
        vm.memory[6] = BC_AND1
        vm.ip, vm.sp = 0, len(vm.memory)
        vm.bp, vm.running = vm.sp, 1
        vm.execute()
        v = vm.pop(1, 1)
        assert v == 13 & 21, "got %i" % v
        vm.memory[6] = BC_XOR1
        vm.ip, vm.sp = 0, len(vm.memory)
        vm.bp, vm.running = vm.sp, 1
        vm.execute()
        v = vm.pop(1, 1)
        assert v == 13 ^ 21, "got %i" % v
        vm.memory[6] = BC_OR1
        vm.ip, vm.sp = 0, len(vm.memory)
        vm.bp, vm.running = vm.sp, 1
        vm.execute()
        v = vm.pop(1, 1)
        assert v == 13 | 21, "got %i" % v
        # noinspection PyBroadException
    except Exception as exc:
        print("ERROR:", exc)
        vm.print_stack_trace()
        raise


def stack_vm_syscall_tests():
    vm = VM(128, 128)
    vm.ip = 0
    vm.memory[0] = BC_CALL_E
    vm.memory[1] = BCCE_SYSCALL | BCCE_S_SYSN_SZ1
    vm.sp = 256
    vm.bp = 256
    vm.memory[64] = BC_HLT
    vm.test_set_sys_fn(1, 64)  # kernel syscall target
    vm.test_set_flags(255, 2)
    vm.test_set_sp(1, 128)  # kernel_sp
    vm.push(1, 12)
    vm.push(8, 2460234)
    vm.push(4, 5724129)
    vm.push(8, 12)
    vm.push(1, 17)
    print(
        "\n  ".join(
            [
                "BEFORE:",
                "sys_regs = %r" % vm.sys_regs,
                "ip: %u, bp: %u, sp: %u" % (vm.ip, vm.bp, vm.sp),
                "priority = %u" % vm.priority,
                "priv_lvl = %u" % vm.priv_lvl,
            ]
        )
    )
    vm.execute()
    print(
        "\n  ".join(
            [
                "AFTER:",
                "sys_regs = %r" % vm.sys_regs,
                "ip: %u, bp: %u, sp: %u" % (vm.ip, vm.bp, vm.sp),
                "priority = %u" % vm.priority,
                "priv_lvl = %u" % vm.priv_lvl,
            ]
        )
    )
    prev_ip = vm.test_load(BCR_R_BP1 | BCR_SZ_8, 0)
    prev_bp = vm.test_load(BCR_R_BP1 | BCR_SZ_8, 8)
    assert prev_ip == 2, "prev_ip = %u" % prev_ip
    assert prev_bp == 256, "prev_bp = %u" % prev_bp
    assert vm.bp == 84, "vm.bp = %u" % vm.bp
    assert vm.sp == 84, "vm.bp = %u" % vm.sp
    assert vm.priv_lvl == 1, "vm.priv_lvl = %u" % vm.priv_lvl
    assert vm.ip == 65, "vm.ip = %u" % vm.ip
    vm.running = True
    vm.memory[65] = BC_RET_E
    vm.memory[66] = BCRE_SYS
    vm.memory[prev_ip] = BC_HLT
    vm.push(8, 0)
    print(
        "\n  ".join(
            [
                "BEFORE(sysret):",
                "sys_regs = %r" % vm.sys_regs,
                "ip: %u, bp: %u, sp: %u" % (vm.ip, vm.bp, vm.sp),
                "priority = %u" % vm.priority,
                "priv_lvl = %u" % vm.priv_lvl,
            ]
        )
    )
    vm.execute()
    print(
        "\n  ".join(
            [
                "AFTER(sysret):",
                "sys_regs = %r" % vm.sys_regs,
                "ip: %u, bp: %u, sp: %u" % (vm.ip, vm.bp, vm.sp),
                "priority = %u" % vm.priority,
                "priv_lvl = %u" % vm.priv_lvl,
            ]
        )
    )
    assert vm.ip == 3, "vm.ip = %u" % vm.ip
    assert vm.bp == 256, "vm.bp = %u" % vm.bp
    assert vm.sp == 255, "vm.sp = %u" % vm.sp
    assert vm.priv_lvl == 2, "vm.priv_lvl = %u" % vm.priv_lvl


def stack_vm_virt_mem_tests():
    vm = VM(0x10000, 0)
    mem = memoryview(vm.memory)
    from traceback import format_exc
    from sys import stderr

    try:
        PTE_VALID_BIT = 0x001
        vm.set_flags_pri_priv_mmd(vm.priority, vm.priv_lvl, VM_4_LVL_9_BIT)
        vm.sys_regs[SVSR_KERNEL_TLPTR] = 0x1000 | PTE_VALID_BIT
        mem[0x1000:0x1008] = (PTE_VALID_BIT | 0x2000).to_bytes(8, "little")
        for c in range(0x1008, 0x2000, 8):
            mem[c : c + 8] = b"\0" * 8
        mem[0x2000:0x2008] = (PTE_VALID_BIT | 0x3000).to_bytes(8, "little")
        for c in range(0x2008, 0x3000, 8):
            mem[c : c + 8] = b"\0" * 8
        mem[0x3000:0x3008] = (PTE_VALID_BIT | 0x4000).to_bytes(8, "little")
        for c in range(0x3008, 0x4000, 8):
            mem[c : c + 8] = b"\0" * 8
        mem[0x4000:0x4008] = (PTE_VALID_BIT | 0x5000).to_bytes(8, "little")
        for c in range(0x4008, 0x5000, 8):
            mem[c : c + 8] = b"\0" * 8
        num = 12345678987654321
        mem[0x5000:0x5008] = num.to_bytes(8, "little")
        num1 = vm.get(8, 0)
        print("expected:", num, "actual:", num1)
        # TODO: test pages with all permissions enabled
        # TODO: test pages with only execute permissions
        # TODO: test pages with only write permissions
        # TODO: test pages with only read permissions
        # TODO: test user pages being resolved from kernel space
        # TODO: ensure that kernel pages cannot be access from user space
    except:
        stderr.write(format_exc())
    vm.dbg_walk_page = False
    try:
        print("STEP 1")
        insert_page_tables(
            vm, 0xFFFFFFFFFFFFF000, 1, 0x6000, 0x7000, 0x8000, 0x9000, 0xF
        )  # SHOULD NOT FAIL
        print("STEP 2")
        vm.get(8, 0xFFFFFFFFFFFFF000)  # SHOULD NOT FAIL
        print("STEP 3")
        vm.set(8, 0xFFFFFFFFFFFFF000, 12288)  # SHOULD NOT FAIL
        print("STEP 4")
        vm.get(8, 0xFFFFFFFFFFFFEFFF)  # SHOULD FAIL (PAGE_FAULT)
    except:
        stderr.write(format_exc())
    try:
        print("STEP 5")
        vm.set(8, 8, 0xDEADDEADBEEF)  # SHOULD FAIL (PROTECT_FAULT)
    except:
        stderr.write(format_exc())
    else:
        stderr.write("Expected failure\n")
    mem[0x5008] = BC_LOAD
    mem[0x5009] = BCR_ABS_C | BCR_SZ_8
    mem[0x500A : 0x500A + 8] = (12288 + 65536 + 16777219).to_bytes(8, "little")
    mem[0x500A + 8] = BC_HLT
    vm.ip = 8
    vm.sp = 1 << 64
    try:
        vm.execute()  # SHOULD FAIL (PROTECT_FAULT cannot execute non-executeable memory)
    except:
        stderr.write(format_exc())
    else:
        stderr.write("Expected failure\n")
    vm.running = 1
    vm.ip = (1 << 64) - 4096
    vm.sp = (1 << 64) - 2048
    mem[0x9000] = 128
    try:
        vm.execute()  # SHOULD FAIL (INVALID_OPCODE cannot execute invalid opcode)
    except:
        stderr.write(format_exc())
    else:
        stderr.write("Expected Failure\n")
    return vm


def insert_page_tables(
    vm: VirtualMachine,
    virt_addr: int,
    priv_lvl: int,
    def0: int,
    def1: int,
    def2: int,
    def3: int,
    perms: int,
    dbg_prn: bool = True,
    force_new_pte_1: bool = False,
):
    """
    :param vm: virtual machine
    :param virt_addr: virtual address
    :param priv_lvl: privilege level of the address space
    :param def0: level 0
    :param def1: level 1
    :param def2: level 2
    :param def3: level 3
    :param perms: permissions
    :return: list of which of the page levels were created list[0] is True if it used the addess `def0` as a new page in the hierarchy
    """
    mem = memoryview(vm.memory)
    assert (
        vm.virt_mem_mode == VM_4_LVL_9_BIT
    ), "this function only supports VM_4_LVL_9_BIT"
    assert def0 & 0xFFF == 0
    assert def1 & 0xFFF == 0
    assert def2 & 0xFFF == 0
    assert def3 & 0xFFF == 0
    if dbg_prn:
        print("perms=", perms)
    PTE_MASK = 0xFFFFFFFFFFFFF000
    PTE_VALID_BIT = 0x001
    PTE_HUGE_BIT = 0x010
    tlpte = vm.sys_regs[SVSRB_TLPTR + priv_lvl]
    from_bytes = int.from_bytes
    # TODO: copy the principal code of `VirtualMachine.walk_page`
    # TODO: instead of faulting when encountering an invalid page
    # TODO:   set the page pointer to the corresponding default the argunments to this function
    assert (tlpte & PTE_VALID_BIT) != 0
    lst_new = [False] * 4
    pte_4_index = ((virt_addr >> 39) & 0x1FF) << 3
    pte_4_ptr = (tlpte & PTE_MASK) | pte_4_index
    pte_4_old = pte_4 = from_bytes(mem[pte_4_ptr : pte_4_ptr + 8], "little")
    if (pte_4 & PTE_VALID_BIT) == 0:
        pte_4 = def0 | PTE_VALID_BIT
        mem[pte_4_ptr : pte_4_ptr + 8] = pte_4.to_bytes(8, "little")
        lst_new[0] = True
    assert pte_4 & PTE_HUGE_BIT == 0
    pte_3_index = ((virt_addr >> 30) & 0x1FF) << 3
    pte_3_ptr = (pte_4 & PTE_MASK) | pte_3_index
    pte_3_old = pte_3 = from_bytes(mem[pte_3_ptr : pte_3_ptr + 8], "little")
    if (pte_3 & PTE_VALID_BIT) == 0:
        pte_3 = def1 | PTE_VALID_BIT
        mem[pte_3_ptr : pte_3_ptr + 8] = pte_3.to_bytes(8, "little")
        lst_new[1] = True
    assert pte_3 & PTE_HUGE_BIT == 0
    pte_2_index = ((virt_addr >> 21) & 0x1FF) << 3
    pte_2_ptr = (pte_3 & PTE_MASK) | pte_2_index
    pte_2_old = pte_2 = from_bytes(mem[pte_2_ptr : pte_2_ptr + 8], "little")
    if (pte_2 & PTE_VALID_BIT) == 0:
        pte_2 = def2 | PTE_VALID_BIT
        mem[pte_2_ptr : pte_2_ptr + 8] = pte_2.to_bytes(8, "little")
        lst_new[2] = True
    assert pte_2 & PTE_HUGE_BIT == 0
    pte_1_index = ((virt_addr >> 12) & 0x1FF) << 3
    pte_1_ptr = (pte_2 & PTE_MASK) | pte_1_index
    pte_1_old = pte_1 = from_bytes(mem[pte_1_ptr : pte_1_ptr + 8], "little")
    if pte_1 & 0xFFF != perms:
        pte_1 &= perms | PTE_MASK
        pte_1 |= perms
    if (pte_1 & PTE_VALID_BIT) == 0 or force_new_pte_1:
        pte_1 = def3 | PTE_VALID_BIT
    else:
        print("WARNING using existing PTE_1")
    assert pte_1 & PTE_HUGE_BIT == 0
    if pte_1_old != pte_1:
        mem[pte_1_ptr : pte_1_ptr + 8] = pte_1.to_bytes(8, "little")
        lst_new[3] = True
    lst_pte = [
        (pte_4_old, pte_4),
        (pte_3_old, pte_3),
        (pte_2_old, pte_2),
        (pte_1_old, pte_1),
    ]
    if dbg_prn:
        for c, b in enumerate(lst_new):
            old, cur = lst_pte[c]
            print("PTE%u old: %016X new: %016X" % (4 - c, old, cur))
    return lst_new


class AdvPageAlloc(object):
    def __init__(
        self, mv: Optional[Union[memoryview, bytearray]], mn: int, mx: int, pgsize: int
    ):
        if mv is not None:
            assert (mx - mn + 7) // 8 <= len(
                mv
            ), "memory view is not big enough to hold allocation bits"
            self.mv = mv
        else:
            self.mv = bytearray((mx - mn + 7) // 8)
        self.mn = mn
        self.mx = mx
        self.pgsize = pgsize

    def alloc(self) -> int:
        r = 0
        for i, byt in enumerate(self.mv):
            if (i << 3) >= self.mx:
                r = i << 3
                break
            if byt != 0xFF:
                i1 = 0
                while byt & 1:
                    byt >>= 1
                    i1 += 1
                r = i1 | (i << 3)
                if r < self.mx:
                    self.mv[i] |= 1 << i1
                break
        if r >= self.mx:
            raise ValueError("Out of allocation spots")
        return r * self.pgsize

    def free(self, n: int):
        q, r = divmod(n, self.pgsize)
        assert q == 0, "must be aligned to page boundaries"
        assert self.mn <= q < self.mx, "must be within allocation range"
        idx = q >> 3
        bit = q & 0x7
        mask = 0xFF ^ (1 << bit)
        self.mv[idx] &= mask


def insert_page_tables_1(
    vm: VirtualMachine,
    virt_addr: int,
    priv_lvl: int,
    alloc: AdvPageAlloc,
    perms: int,
    dbg_prn: bool = True,
    force_new_pte_1: bool = False,
):
    """
    :param vm: virtual machine
    :param virt_addr: virtual address
    :param priv_lvl: privilege level of the address space
    :param alloc: an allocator with an `alloc()` method that can fail with a ValueError
    :param perms: permissions
    :return: list of which of the page levels were created list[0] is True if it used the addess `def0` as a new page in the hierarchy
    """
    if dbg_prn:
        print(
            "insert_page_tables(vm,\n  virt_addr = 0x%016X,\n  priv_lvl = %u,\n  alloc = %r\n  perms = %u,\n  dbg_prn = %r\n)"
            % (virt_addr, priv_lvl, alloc, perms, dbg_prn)
        )
    mem = memoryview(vm.memory)
    assert (
        vm.virt_mem_mode == VM_4_LVL_9_BIT
    ), "this function only supports VM_4_LVL_9_BIT"
    if dbg_prn:
        print("perms=", perms)
    PTE_MASK = 0xFFFFFFFFFFFFF000
    PTE_VALID_BIT = 0x001
    PTE_HUGE_BIT = 0x010
    acquired = []
    from_bytes = int.from_bytes
    try:
        tlpte = vm.sys_regs[SVSRB_TLPTR + priv_lvl]
        # TODO: copy the principal code of `VirtualMachine.walk_page`
        # TODO: instead of faulting when encountering an invalid page
        # TODO:   set the page pointer to the corresponding default the argunments to this function
        assert (tlpte & PTE_VALID_BIT) != 0
        pte_4_index = ((virt_addr >> 39) & 0x1FF) << 3
        pte_4_ptr = (tlpte & PTE_MASK) | pte_4_index
        pte_4_old = pte_4 = from_bytes(mem[pte_4_ptr : pte_4_ptr + 8], "little")
        if (pte_4 & PTE_VALID_BIT) == 0:
            def0 = alloc.alloc()
            pte_4 = def0 | PTE_VALID_BIT
            acquired.append((pte_4_ptr, pte_4_ptr + 8, def0, pte_4_old))
            if dbg_prn:
                print("Injecting PTE_4 0x%016X at address 0x%016X" % (pte_4, pte_4_ptr))
            mem[pte_4_ptr : pte_4_ptr + 8] = pte_4.to_bytes(8, "little")
        assert pte_4 & PTE_HUGE_BIT == 0
        pte_3_index = ((virt_addr >> 30) & 0x1FF) << 3
        pte_3_ptr = (pte_4 & PTE_MASK) | pte_3_index
        pte_3_old = pte_3 = from_bytes(mem[pte_3_ptr : pte_3_ptr + 8], "little")
        if (pte_3 & PTE_VALID_BIT) == 0:
            def1 = alloc.alloc()
            pte_3 = def1 | PTE_VALID_BIT
            acquired.append((pte_3_ptr, pte_3_ptr + 8, def1, pte_3_old))
            if dbg_prn:
                print("Injecting PTE_3 0x%016X at address 0x%016X" % (pte_3, pte_3_ptr))
            mem[pte_3_ptr : pte_3_ptr + 8] = pte_3.to_bytes(8, "little")
        assert pte_3 & PTE_HUGE_BIT == 0
        pte_2_index = ((virt_addr >> 21) & 0x1FF) << 3
        pte_2_ptr = (pte_3 & PTE_MASK) | pte_2_index
        pte_2_old = pte_2 = from_bytes(mem[pte_2_ptr : pte_2_ptr + 8], "little")
        if (pte_2 & PTE_VALID_BIT) == 0:
            def2 = alloc.alloc()
            pte_2 = def2 | PTE_VALID_BIT
            acquired.append((pte_2_ptr, pte_2_ptr + 8, def2, pte_2_old))
            if dbg_prn:
                print("Injecting PTE_2 0x%016X at address 0x%016X" % (pte_2, pte_2_ptr))
            mem[pte_2_ptr : pte_2_ptr + 8] = pte_2.to_bytes(8, "little")
        assert pte_2 & PTE_HUGE_BIT == 0
        pte_1_index = ((virt_addr >> 12) & 0x1FF) << 3
        pte_1_ptr = (pte_2 & PTE_MASK) | pte_1_index
        pte_1_old = pte_1 = from_bytes(mem[pte_1_ptr : pte_1_ptr + 8], "little")
        if (pte_1 & PTE_VALID_BIT) == 0 or force_new_pte_1:
            def3 = alloc.alloc()
            pte_1 = def3 | PTE_VALID_BIT | perms
            acquired.append((pte_1_ptr, pte_1_ptr + 8, def3, pte_1_old))
            if dbg_prn:
                print("Injecting PTE_1 0x%016X at address 0x%016X" % (pte_1, pte_1_ptr))
            mem[pte_1_ptr : pte_1_ptr + 8] = pte_1.to_bytes(8, "little")
        elif pte_1 & 0xFFF != perms:
            pte_1 &= perms | PTE_MASK
            pte_1 |= perms
            mem[pte_1_ptr : pte_1_ptr + 8] = pte_1.to_bytes(8, "little")
            if dbg_prn:
                print("WARNING using existing PTE_1\n  Updating PTE_1 permissions")
        else:
            if dbg_prn:
                print("WARNING using existing PTE_1")
        assert pte_1 & PTE_HUGE_BIT == 0
        if dbg_prn:
            lst_pte = [
                (pte_4_old, pte_4),
                (pte_3_old, pte_3),
                (pte_2_old, pte_2),
                (pte_1_old, pte_1),
            ]
            for c in range(len(lst_pte)):
                old, cur = lst_pte[c]
                if old != cur:
                    print("PTE%u old: %016X new: %016X" % (4 - c, old, cur))
    except ValueError:
        if dbg_prn:
            print("Failed to allocate, rolling back")
            for start, end, new, old in acquired:
                print("restoring mem[0x%016X:0x%016X] to 0x%016X" % (start, end, old))
                mem[start:end] = old.to_bytes(end - start, "little")
                alloc.free(new)
        else:
            for start, end, old in acquired:
                mem[start:end] = old.to_bytes(end - start, "little")
        return False
    return True


# insert_page_tables(vm1, 0xFFFFFFFFFFFFF000, 1, 0x6000, 0x7000, 0x8000, 0x9000, 0x6)
# # No Error, returns [True, True, True, True]
# vm1.get(8, 0xFFFFFFFFFFFFF000)
# # No Error, returns 0
# vm1.get(8, 0xFFFFFFFFFFFFEFFF)
# # Error PAGE_FAULT
# vm1.set(8, 0xFFFFFFFFFFFFF000, 12288)
# # No Error, returns True
# vm1.set(8, 8, 0xDEADDEADBEEF)
# # Error PROTECT_FAULT


if __name__ == "__main__":
    run_stack_vm_tests()
    vm = stack_vm_syscall_tests()
    vm1 = stack_vm_virt_mem_tests()
# my_stack_vm = VM()
# my_stack_vm.load_program(cmpl_obj.memory, 0)
# my_stack_vm.execute()


class BitMapInt(object):
    __slots__ = ["num", "sz"]

    def __init__(self, num: int, sz: int):
        self.sz = sz
        self.num = num

    def __getitem__(self, index):
        if isinstance(index, slice):
            bits = 0
            for idx in range(*index.indices(self.sz)):
                bits <<= 1
                bits |= self.__getitem__(idx)
        else:
            return (self.num >> index) & 1

    def __setitem__(self, index, v):
        v = int(v)
        if isinstance(index, slice):
            for idx in range(*index.indices(self.sz)):
                self.__setitem__(idx, v & 1)
                v >>= 1
        else:
            num = self.num
            mask = 1 << index
            v1 = num & mask
            if (v1 and not v) or (not v1 and v):
                self.num = num ^ mask


class PageAllocator(object):
    def __init__(self, end_index: int):
        """
        :param end_index: the last valid bit index + 1
        """
        self.byts = bytearray((end_index + 7) // 8)
        self.max_addr = end_index

    def get_next_false(self) -> Optional[int]:
        for c, x in enumerate(self.byts):
            if x != 0xFF:
                for i in range(8):
                    if x & (1 << i) == 0:
                        return i | (c << 3)
        return None

    def get_and_alloc_next_false(self) -> int:
        i = self.get_next_false()
        if i is None:
            raise IndexError("Out of allocation space")
        self[i] = True
        return i

    def __getitem__(self, i: int) -> bool:
        bit_index = i & 7
        byt_index = i >> 3
        return bool(self.byts[byt_index] & (1 << bit_index))

    def __setitem__(self, i: int, v: bool):
        bit_index = i & 7
        byt_index = i >> 3
        if v:
            self.byts[byt_index] |= 1 << bit_index
        else:
            self.byts[byt_index] &= 0xFF ^ (1 << bit_index)

    def __len__(self):
        return self.max_addr


def enable_virt_mem(
    vm: VirtualMachine,
    alloc: PageAllocator,
    priv_lvl: int,
    code_segment_start: int,
    code_segment_end: int,
    data_segment_start,
    data_segment_end: Optional[int],
    dbg_prn: bool = False,
):
    PTE_VALID_BIT = 0x001
    PTE_WRITE_BIT = 0x002
    PTE_EXEC_BIT = 0x004
    PTE_DIRTY_BIT = 0x008
    vm.set_mem_mode(VM_4_LVL_9_BIT)
    tlpte = (alloc.get_and_alloc_next_false() << 12) | PTE_VALID_BIT
    adv_alloc = AdvPageAlloc(memoryview(alloc.byts), 0, alloc.max_addr, 4096)
    vm.sys_regs[SVSRB_TLPTR + priv_lvl] = tlpte
    assert code_segment_start & 0xFFF == 0, "page alignment"
    assert code_segment_end & 0xFFF == 0, "page alignment"
    assert data_segment_start & 0xFFF == 0, "page alignment"
    assert data_segment_end is None or data_segment_end & 0xFFF == 0, "page alignment"
    if data_segment_end is not None:
        assert (
            code_segment_end <= data_segment_start
            or code_segment_start >= data_segment_end
        ), "code and data segments cannot overlap"
    else:
        if code_segment_start > data_segment_start:
            data_segment_end = code_segment_start
        else:
            assert code_segment_end <= data_segment_start
    for addr in range(code_segment_start, code_segment_end, 4096):
        assert insert_page_tables_1(
            vm,
            addr,
            priv_lvl,
            adv_alloc,
            PTE_VALID_BIT | PTE_EXEC_BIT,
            dbg_prn=dbg_prn,
            force_new_pte_1=True,
        )
    if data_segment_end is not None:
        for addr in range(data_segment_start, data_segment_end, 4096):
            assert insert_page_tables_1(
                vm,
                addr,
                priv_lvl,
                adv_alloc,
                PTE_VALID_BIT | PTE_WRITE_BIT | PTE_DIRTY_BIT,
                dbg_prn=dbg_prn,
                force_new_pte_1=True,
            )
        vm.sp = data_segment_end
    else:
        addr = data_segment_start
        while insert_page_tables_1(
            vm,
            addr,
            priv_lvl,
            adv_alloc,
            PTE_VALID_BIT | PTE_WRITE_BIT | PTE_DIRTY_BIT,
            dbg_prn=dbg_prn,
            force_new_pte_1=True,
        ):
            addr += 4096
        vm.sp = addr
