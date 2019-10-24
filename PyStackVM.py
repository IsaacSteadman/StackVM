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
BC_SYSRET = 14
# TODO: change BC_SYSRET
BC_INT = 15
BC_LSHIFT1 = 16
BC_LSHIFT2 = 17
BC_LSHIFT4 = 18
BC_LSHIFT8 = 19
BC_RSHIFT1 = 20
BC_RSHIFT2 = 21
BC_RSHIFT4 = 22
BC_RSHIFT8 = 23
BC_LROT1 = 24
BC_LROT2 = 25
BC_LROT4 = 26
BC_LROT8 = 27
BC_RROT1 = 28
BC_RROT2 = 29
BC_RROT4 = 30
BC_RROT8 = 31
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
BCR_ABS_C = 0x08
BCR_REG_BP = 0x09
BCR_RES = 0x0A
BCR_EA_R_IP = 0x0B
BCR_TOS = 0x0C
BCR_SYSREG = 0x0D
BCR_SZ_1 = 0x0 << 5
BCR_SZ_2 = 0x1 << 5
BCR_SZ_4 = 0x2 << 5
BCR_SZ_8 = 0x3 << 5
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
BCCE_N_REL = 1 << 6
BCCE_S_SYSN_SZ1 = 0 << 5
BCCE_S_SYSN_SZ2 = 1 << 5
BCCE_S_SYSN_SZ4 = 2 << 5
BCCE_S_SYSN_SZ8 = 3 << 5
BCCE_S_ARG_SZ1 = 0 << 3
BCCE_S_ARG_SZ2 = 1 << 3
BCCE_S_ARG_SZ4 = 2 << 3
BCCE_S_ARG_SZ8 = 3 << 3

# StackVm SysReg
SVSRB_PTE = 0x00
SVSRB_SP = 0x04
SVSRB_SYS_FN = 0x08

SVSR_HYPER_PTE = 0x00
SVSR_KERNEL_PTE = 0x01
SVSR_USER_PTE = 0x02
SVSR_WEB_PTE = 0x03
SVSR_HYPER_SP = 0x04
SVSR_KERNEL_SP = 0x05
SVSR_USER_SP = 0x06
SVSR_WEB_SP = 0x07
SVSR_HYPER_SYS_FN = 0x08
SVSR_KERNEL_SYS_FN = 0x09
SVSR_USER_SYS_FN = 0x0A
SVSR_WEB_SYS_FN = 0x0B
SVSR_FLAGS = 0x0C
# MISSING allocation for 0x0D
SVSR_HYPER_ISR = 0x0E
SVSR_KERNEL_ISR = 0x0F

StackVM_SVSR_Codes = {
    "HYPER_PTE": 0x00, "KERNEL_PTE": 0x01, "USER_PTE": 0x02, "WEB_PTE": 0x03,
    "HYPER_SP": 0x04, "KERNEL_SP": 0x05, "USER_SP": 0x06, "WEB_SP": 0x07,
    "HYPER_SYS_FN": 0x08, "KERNEL_SYS_FN": 0x09, "USER_SYS_FN": 0x0A, "WEB_SYS_FN": 0x0B,
    "FLAGS": 0x0C, "HYPER_ISR": 0x0E, "KERNEL_ISR": 0x0F
}

INT_INVAL_OPCODE = 6
INT_PROTECT_FAULT = 13
INT_PAGE_FAULT = 14
INT_INVAL_SYSCALL = 15
INT_LST = [
    "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN",
    "UNKNOWN", "UNKNOWN", "INVAL_OPCODE", "UNKNOWN",
    "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN",
    "UNKNOWN", "PROTECT_FAULT", "PAGE_FAULT", "INVAL_SYSCALL"
] + ["UNKNOWN"] * 240

MRQ_DONT_CHECK = 0
MRQ_READ = 1
MRQ_WRITE = 2
MRQ_EXEC = 3

StackVM_BCRE_Codes = {
    "RST_SP_SZ1": 0x00, "RST_SP_SZ2": 0x20, "RST_SP_SZ4": 0x40, "RST_SP_SZ8": 0x60,
    "RES_SZ1": 0x0, "RES_SZ2": 0x8, "RES_SZ4": 0x10, "RES_SZ8": 0x18
}

LstStackVM_Codes = [
    "NOP",      "HLT",      "EQ0",      "NE0",      "LT0",      "LE0",      "GT0",      "GE0",
    "CONV",     "SWAP",     "LOAD",     "STOR",     "CALL_E",   "RET_E",    "SYSRET",   "INT",
    "LSHIFT1",  "LSHIFT2",  "LSHIFT4",  "LSHIFT8",  "RSHIFT1",  "RSHIFT2",  "RSHIFT4",  "RSHIFT8",
    "LROT1",    "LROT2",    "LROT4",    "LROT8",    "RROT1",    "RROT2",    "RROT4",    "RROT8",
    "AND1",     "AND2",     "AND4",     "AND8",     "OR1",      "OR2",      "OR4",      "OR8",
    "NOT1",     "NOT2",     "NOT4",     "NOT8",     "XOR1",     "XOR2",     "XOR4",     "XOR8",
    "ADD1",     "ADD2",     "ADD4",     "ADD8",     "SUB1",     "SUB2",     "SUB4",     "SUB8",
    "ADD_SP1",  "ADD_SP2",  "ADD_SP4",  "ADD_SP8",  "RST_SP1",  "RST_SP2",  "RST_SP4",  "RST_SP8",
    "MUL1",     "MUL1S",    "MUL2",     "MUL2S",    "MUL4",     "MUL4S",    "MUL8",     "MUL8S",
    "DIV1",     "DIV1S",    "DIV2",     "DIV2S",    "DIV4",     "DIV4S",    "DIV8",     "DIV8S",
    "MOD1",     "MOD1S",    "MOD2",     "MOD2S",    "MOD4",     "MOD4S",    "MOD8",     "MOD8S",
    "CMP1",     "CMP1S",    "CMP2",     "CMP2S",    "CMP4",     "CMP4S",    "CMP8",     "CMP8S",
    "FADD_2",   "FADD_4",   "FADD_8",   "FADD_16",  "FSUB_2",   "FSUB_4",   "FSUB_8",   "FSUB_16",
    "FMUL_2",   "FMUL_4",   "FMUL_8",   "FMUL_16",  "FDIV_2",   "FDIV_4",   "FDIV_8",   "FDIV_16",
    "FMOD_2",   "FMOD_4",   "FMOD_8",   "FMOD_16",  "FCMP_2",   "FCMP_4",   "FCMP_8",   "FCMP_16",
    "JMP",      "JMPIF",    "RJMP",     "RJMPIF",   "CALL",     "RCALL",    "RET",      "RET_N2",
]

StackVM_Codes = {
    "NOP": 0, "HLT": 1, "EQ0": 2, "NE0": 3, "LT0": 4, "LE0": 5, "GT0": 6, "GE0": 7,
    "CONV": 8, "SWAP": 9, "LOAD": 10, "STOR": 11, "CALL_E": 12, "RET_E": 13, "SYSRET": 14, "INT": 15,
    "LSHIFT1": 16, "LSHIFT2": 17, "LSHIFT4": 18, "LSHIFT8": 19, "RSHIFT1": 20, "RSHIFT2": 21, "RSHIFT4": 22,
    "RSHIFT8": 23,
    "LROT1": 24, "LROT2": 25, "LROT4": 26, "LROT8": 27, "RROT1": 28, "RROT2": 29, "RROT4": 30, "RROT8": 31,
    "AND1": 32, "AND2": 33, "AND4": 34, "AND8": 35, "OR1": 36, "OR2": 37, "OR4": 38, "OR8": 39,
    "NOT1": 40, "NOT2": 41, "NOT4": 42, "NOT8": 43, "XOR1": 44, "XOR2": 45, "XOR4": 46, "XOR8": 47,
    "ADD1": 48, "ADD2": 49, "ADD4": 50, "ADD8": 51, "SUB1": 52, "SUB2": 53, "SUB4": 54, "SUB8": 55,
    "ADD_SP1": 56, "ADD_SP2": 57, "ADD_SP4": 58, "ADD_SP8": 59, "RST_SP1": 60, "RST_SP2": 61, "RST_SP4": 62,
    "RST_SP8": 63,
    "MUL1": 64, "MUL1S": 65, "MUL2": 66, "MUL2S": 67, "MUL4": 68, "MUL4S": 69, "MUL8": 70, "MUL8S": 71,
    "DIV1": 72, "DIV1S": 73, "DIV2": 74, "DIV2S": 75, "DIV4": 76, "DIV4S": 77, "DIV8": 78, "DIV8S": 79,
    "MOD1": 80, "MOD1S": 81, "MOD2": 82, "MOD2S": 83, "MOD4": 84, "MOD4S": 85, "MOD8": 86, "MOD8S": 87,
    "CMP1": 88, "CMP1S": 89, "CMP2": 90, "CMP2S": 91, "CMP4": 92, "CMP4S": 93, "CMP8": 94, "CMP8S": 95,
    "FADD_2": 96, "FADD_4": 97, "FADD_8": 98, "FADD_16": 99, "FSUB_2": 100, "FSUB_4": 101, "FSUB_8": 102,
    "FSUB_16": 103,
    "FMUL_2": 104, "FMUL_4": 105, "FMUL_8": 106, "FMUL_16": 107, "FDIV_2": 108, "FDIV_4": 109, "FDIV_8": 110,
    "FDIV_16": 111,
    "FMOD_2": 112, "FMOD_4": 113, "FMOD_8": 114, "FMOD_16": 115, "FCMP_2": 116, "FCMP_4": 117, "FCMP_8": 118,
    "FCMP_16": 119,
    "JMP": 120, "JMPIF": 121, "RJMP": 122, "RJMPIF": 123, "CALL": 124, "RCALL": 125, "RET": 126, "RET_N2": 127
}


def _test():
    for c in range(len(LstStackVM_Codes)):
        assert StackVM_Codes[LstStackVM_Codes[c]] == c, "error c = %u" % c


_test()

StackVM_BCR_Codes = {
    "ABS_A4": 0x00, "ABS_A8": 0x01, "ABS_S4": 0x02, "ABS_S8": 0x03,
    "R_BP1": 0x04, "R_BP2": 0x05, "R_BP4": 0x06, "R_BP8": 0x07,
    "ABS_C": 0x08, "REG_BP": 0x09, "RES": 0x0A, "EA_R_IP": 0x0B, "TOS": 0x0C,
    "SYSREG": 0x0D,
    "SZ_1": 0x0 << 5, "SZ_2": 0x1 << 5, "SZ_4": 0x2 << 5, "SZ_8": 0x3 << 5
}
StackVM_BCS_Codes = {
    "SZ1_A": 0x00, "SZ2_A": 0x01, "SZ4_A": 0x02, "SZ8_A": 0x03,
    "SZ16_A": 0x04, "SZ32_A": 0x05, "SZ64_A": 0x06, "SZ128_A": 0x07,
    "SZ1_B": 0x00, "SZ2_B": 0x08, "SZ4_B": 0x10, "SZ8_B": 0x18,
    "SZ16_B": 0x20, "SZ32_B": 0x28, "SZ64_B": 0x30, "SZ128_B": 0x38
}
StackVM_BCC_Codes = {
    "UI_1_I": 0x00, "SI_1_I": 0x01, "UI_2_I": 0x02, "SI_2_I": 0x03,
    "UI_4_I": 0x04, "SI_4_I": 0x05, "UI_8_I": 0x06, "SI_8_I": 0x07,
    "F_2_I": 0x08, "F_4_I": 0x09, "F_8_I": 0x0A, "F_16_I": 0x0B,
    "UI_1_O": 0x00, "SI_1_O": 0x10, "UI_2_O": 0x20, "SI_2_O": 0x30,
    "UI_4_O": 0x40, "SI_4_O": 0x50, "UI_8_O": 0x60, "SI_8_O": 0x70,
    "F_2_O": 0x80, "F_4_O": 0x90, "F_8_O": 0xA0, "F_16_O": 0xB0
}
StackVM_BCCE_Codes = {
    "SYSCALL": 0x80, "N_REL": 0x40,
    "S_SYSN_SZ1": 0x00, "S_SYSN_SZ2": 0x20, "S_SYSN_SZ4": 0x40, "S_SYSN_SZ8": 0x60,
    "S_ARG_SZ1": 0x00, "S_ARG_SZ2": 0x08, "S_ARG_SZ4": 0x10, "S_ARG_SZ8": 0x18
}
LstStackVM_BCR_Types = [
    "ABS_A4", "ABS_A8", "ABS_S4", "ABS_S8",
    "R_BP1", "R_BP2", "R_BP4", "R_BP8",
    "ABS_C", "REG_BP", "RES", "EA_R_IP",
    "TOS", "SYSREG"
]
LstStackVM_sysregs = [
    "HYPER_PTE", "KERNEL_PTE", "USER_PTE", "WEB_PTE",
    "HYPER_SP", "KERNEL_SP", "USER_SP", "WEB_SP",
    "HYPER_SYS_FN", "KERNEL_SYS_FN", "USER_SYS_FN", "WEB_SYS_FN",
    "FLAGS", "RESERVED", "HYPER_ISR", "KERNEL_ISR"
]
LstStackVM_BCS_Types = [
    "SZ1_", "SZ2_", "SZ4_", "SZ8_",
    "SZ16_", "SZ32_", "SZ64_", "SZ128_"
]
LstStackVM_BCC_Types = [
    "UI_1_", "SI_1_", "UI_2_", "SI_2_",
    "UI_4_", "SI_4_", "UI_8_", "SI_8_",
    "F_2_", "F_4_", "F_8_", "F_16_",
]
"""
typedef unsigned long long SizeL;
struct Range {
    SizeL Start, End;
};
class IdAllocator {
    Range *LstRanges;
    SizeL NumRanges, AllocRanges;
    SizeL tMin, tMax;
    // assume that an IdAllocator when fully constructed satisfies
    //   (NumRanges == 1 && AllocRanges >= NumRanges && LstRanges != 0 && LstRanges[0].End >= LstRanges[0].Start)
    IdAllocator(Range *ArrRanges, SizeL LenArr, SizeL Min, SizeL Max) {
        NumRanges = 1;
        AllocRanges = LenArr;
        LstRanges = ArrRanges;
        LstRanges[0].Start = tMin = Min;
        LstRanges[0].End = tMax = Max;
    }
    void ReduceRanges() {
        SizeL i = 1;
        for (SizeL c = 1; c < NumRanges; ++c) {
            if (i != c) LstRanges[i] = LstRanges[c];
            if (LstRanges[i - 1].End >= LstRanges[i].Start) {
                LstRanges[i - 1].End = LstRanges[i].End;
                LstRanges[i].Start = LstRanges[i].End;
            } else if (LstRanges[i - 1].Start != LstRanges[i - 1].End) ++i;
        }
        NumRanges = i;
    }
    Range GetRange(SizeL Length) {
        if (Length == 0) return {LstRanges[0].Start, LstRanges[0].Start};
        Range Rtn = {0, 0};
        for (SizeL c = 0; c < NumRanges; ++c) {
            if (LstRanges[c].Start - LstRanges[c].End >= Length) {
                Rtn.Start = LstRanges[c].Start;
                Rtn.End = Rtn.Start + Length;
                break;
            }
        }
        return Rtn;
    }
    bool FreeRange(SizeL Start, SizeL Length) {
        if (Start < tMin) return false; // outside of range
        SizeL End = Start + Length;
        if (End > tMax) return false; // outside of range
        SizeL c;
        for (c = 0; c < NumRanges; ++c) {
            if (LstRanges[c].Start <= End) {
                LstRanges[c].Start = Start;
                ReduceRanges();
                return true;
            } else if (LstRanges[c].End >= Start) {
                if (LstRanges[c].End <= End) LstRanges[c].End = End;
                ReduceRanges();
                return true;
            } else if (LstRanges[c].Start > End) {
                break;
            }
        }
        if (c >= NumRanges) return false; // outsize range?
        {
            SizeL iPos = c;
            c = NumRanges;
            if (c + 1 > AllocRanges) return false; // not enough static memory
            while (c-- > iPos) {
                LstRanges[c + 1] = LstRanges[c];
            }
            ++NumRanges;
            c = iPos;
        }
        LstRanges[c] = {Start, End};
        ReduceRanges();
        return true;
    }
}
Range MallocRanges[1024];

IdAllocator MemAlloc(MallocRanges, 1024, __malloc_heap_begin, __malloc_heap_end);

void *malloc(SizeL nBytes) {
    Range Res = MemAlloc.GetRange(nBytes + sizeof(nBytes));
    if (Res.Start == 0 && Res.End == 0) {
        return 0;
    }
    void *Rtn = (void *)(Res.Start);
    *(SizeL *)Rtn = nBytes;
    return (void *) ((SizeL) Rtn + sizeof(nBytes));
}
bool free(void *ptr) {
    ptr = (void *)((SizeL)ptr - sizeof(SizeL));
    return MemAlloc.FreeRange((SizeL)ptr, *(SizeL *)ptr);
}
"""


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
    elif typ & BCR_R_BP_MASK == BCR_R_BP_VAL:  # BCR_R_BP1, BCR_R_BP2, BCR_R_BP4, BCR_R_BP8
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
    else:
        raise ValueError(
            "Unsupported BCR code for BC_LOAD instruction: %u at 0x%X" % (typ, vm_inst.ip))


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
    elif typ & BCR_R_BP_MASK == BCR_R_BP_VAL:  # BCR_R_BP1, BCR_R_BP2, BCR_R_BP4, BCR_R_BP8
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
        vm_inst.sys_regs[which] = reg_v
        if which == 0xC:
            vm_inst.priv_lvl = (reg_v >> 8) & 3
            vm_inst.priority = reg_v & 0xFF
    elif typ == BCR_ABS_C:
        raise ValueError("BCR_ABS_C is unsupported on store instruction at 0x%X" % vm_inst.ip)
    elif typ == BCR_REG_BP:
        vm_inst.bp = vm_inst.pop(8)
    elif typ == BCR_EA_R_IP:
        raise ValueError("BCR_EA_R_IP is unsupported on store instruction at 0x%X" % vm_inst.ip)
    else:
        raise ValueError(
            "Unsupported BCR code for BC_STOR instruction: %u at 0x%X" % (typ, vm_inst.ip))


def vm_exit(vm_inst):
    """
    :param VirtualMachine vm_inst:
    """
    vm_inst.running = 0


def get_vm_sz_type(conv_typ):
    if conv_typ >= 0xC:
        raise NotImplementedError("Not Implemented")
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
        '''sys_num = vm_inst.pop()
        if vm_inst.cr4 & 0x3 == vm_inst.virtual_syscalls_lvl:
            vm_inst.virt_syscall(sys_num)
        else:
            num = vm_inst.sys_fn[vm_inst.cr4 & 0x3]
            old_regs = [vm_inst.cr4, vm_inst.ip, vm_inst.sp, vm_inst.bp]  # TODO
            vm_inst.call(num)
        raise NotImplementedError("SysCall (CALL_E with IS_SYS=1) is unsupported")
        '''
    else:
        addr = vm_inst.pop(8)
        if a & 0x40:
            vm_inst.call(addr + vm_inst.ip)
        else:
            vm_inst.call(addr)


def vm_ret_ext(vm_inst):
    """
    :param VirtualMachine vm_inst:
    """
    a = vm_inst.get_instr_dat(1)
    if a & 0x80:
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
            vm_inst.set_float(8, vm_inst.sp + 13, base ** exponent)
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
            vm_inst.memory[addr: addr + real_len] = self.read_buf[:real_len]
            self.read_buf = self.read_buf[real_len:]
            vm_inst.set(8, vm_inst.sp + 17, real_len)
        elif cmd == 0x0B:  # get status [UInt64 getStatus()]
            vm_inst.set(8, vm_inst.sp + 1, self.gets_len())

    def putchar(self, ch):
        self.stdout.write(str(ch))

    def puts(self, s):
        self.stdout.write(s.decode('utf-8'))

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
    __slots__ = ["int_ready", "which_int", "arg0", "arg1", "arg2", "arg3"]

    def __init__(self):
        self.int_ready = False
        self.which_int = 0
        self.arg0 = 0
        self.arg1 = 0
        self.arg2 = 0
        self.arg3 = 0

    def trigger(self, which_int: int, arg0: int=0, arg1: int=0, arg2: int=0, arg3: int=0):
        self.int_ready = True
        self.which_int = which_int
        self.arg0 = arg0
        self.arg1 = arg1
        self.arg2 = arg2
        self.arg3 = arg3


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
        mva[:] = data[:len(mva)]
        self.mvb = data[len(mva):]

    def pack_int(self, i: int, signed=False):
        data = i.to_bytes(self.sz, "little", signed=signed)
        mva = self.mva
        mva[:] = data[:len(mva)]
        self.mvb = data[len(mva):]

    def unpack_int(self, signed=False) -> int:
        data = bytearray(self.mva)
        data.extend(self.mvb)
        return int.from_bytes(data, "little", signed=signed)

    def pack_bytes(self, data: Union[bytes, bytearray, memoryview]):
        mva = self.mva
        mva[:] = data[:len(mva)]
        self.mvb = data[len(mva):]


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
        vm_sys_ret,
        vm_interrupt,
        # Bit/Byte Manip
        lambda vm_inst: vm_inst.push(1, lshift1(vm_inst.pop(1), vm_inst.pop(1))),
        lambda vm_inst: vm_inst.push(2, lshift1(vm_inst.pop(1), vm_inst.pop(2))),
        lambda vm_inst: vm_inst.push(4, lshift1(vm_inst.pop(1), vm_inst.pop(4))),
        lambda vm_inst: vm_inst.push(8, lshift1(vm_inst.pop(1), vm_inst.pop(8))),
        lambda vm_inst: vm_inst.push(1, rshift1(vm_inst.pop(1), vm_inst.pop(1))),
        lambda vm_inst: vm_inst.push(2, rshift1(vm_inst.pop(1), vm_inst.pop(2))),
        lambda vm_inst: vm_inst.push(4, rshift1(vm_inst.pop(1), vm_inst.pop(4))),
        lambda vm_inst: vm_inst.push(8, rshift1(vm_inst.pop(1), vm_inst.pop(8))),
        lambda vm_inst: vm_inst.push(1, lrot1(vm_inst.pop(1), vm_inst.pop(1), 8)),
        lambda vm_inst: vm_inst.push(2, lrot1(vm_inst.pop(1), vm_inst.pop(2), 16)),
        lambda vm_inst: vm_inst.push(4, lrot1(vm_inst.pop(1), vm_inst.pop(4), 32)),
        lambda vm_inst: vm_inst.push(8, lrot1(vm_inst.pop(1), vm_inst.pop(8), 64)),
        lambda vm_inst: vm_inst.push(1, rrot1(vm_inst.pop(1), vm_inst.pop(1), 8)),
        lambda vm_inst: vm_inst.push(2, rrot1(vm_inst.pop(1), vm_inst.pop(2), 16)),
        lambda vm_inst: vm_inst.push(4, rrot1(vm_inst.pop(1), vm_inst.pop(4), 32)),
        lambda vm_inst: vm_inst.push(8, rrot1(vm_inst.pop(1), vm_inst.pop(8), 64)),
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
        lambda vm_inst: vm_inst.push(16, add1(vm_inst.pop(16, 2), vm_inst.pop(16, 2)), 2),
        lambda vm_inst: vm_inst.push(2, sub1(vm_inst.pop(2, 2), vm_inst.pop(2, 2)), 2),
        lambda vm_inst: vm_inst.push(4, sub1(vm_inst.pop(4, 2), vm_inst.pop(4, 2)), 2),
        lambda vm_inst: vm_inst.push(8, sub1(vm_inst.pop(8, 2), vm_inst.pop(8, 2)), 2),
        lambda vm_inst: vm_inst.push(16, sub1(vm_inst.pop(16, 2), vm_inst.pop(16, 2)), 2),
        lambda vm_inst: vm_inst.push(2, mul1(vm_inst.pop(2, 2), vm_inst.pop(2, 2)), 2),
        lambda vm_inst: vm_inst.push(4, mul1(vm_inst.pop(4, 2), vm_inst.pop(4, 2)), 2),
        lambda vm_inst: vm_inst.push(8, mul1(vm_inst.pop(8, 2), vm_inst.pop(8, 2)), 2),
        lambda vm_inst: vm_inst.push(16, mul1(vm_inst.pop(16, 2), vm_inst.pop(16, 2)), 2),
        lambda vm_inst: vm_inst.push(2, fdiv(vm_inst.pop(2, 2), vm_inst.pop(2, 2)), 2),
        lambda vm_inst: vm_inst.push(4, fdiv(vm_inst.pop(4, 2), vm_inst.pop(4, 2)), 2),
        lambda vm_inst: vm_inst.push(8, fdiv(vm_inst.pop(8, 2), vm_inst.pop(8, 2)), 2),
        lambda vm_inst: vm_inst.push(16, fdiv(vm_inst.pop(16, 2), vm_inst.pop(16, 2)), 2),
        lambda vm_inst: vm_inst.push(2, mod1(vm_inst.pop(2, 2), vm_inst.pop(2, 2)), 2),
        lambda vm_inst: vm_inst.push(4, mod1(vm_inst.pop(4, 2), vm_inst.pop(4, 2)), 2),
        lambda vm_inst: vm_inst.push(8, mod1(vm_inst.pop(8, 2), vm_inst.pop(8, 2)), 2),
        lambda vm_inst: vm_inst.push(16, mod1(vm_inst.pop(16, 2), vm_inst.pop(16, 2)), 2),
        lambda vm_inst: vm_inst.push(1, cmp1(vm_inst.pop(2), vm_inst.pop(2)), 1),
        lambda vm_inst: vm_inst.push(1, cmp1(vm_inst.pop(4), vm_inst.pop(4)), 1),
        lambda vm_inst: vm_inst.push(1, cmp1(vm_inst.pop(8), vm_inst.pop(8)), 1),
        lambda vm_inst: vm_inst.push(1, cmp1(vm_inst.pop(16), vm_inst.pop(16)), 1),
        # Control Flow
        lambda vm_inst: vm_inst.set_ip(vm_inst.pop(8)),
        lambda vm_inst: vm_inst.set_ip_if(vm_inst.pop(8), vm_inst.pop(1)),
        lambda vm_inst: vm_inst.set_ip(vm_inst.pop(8, 1) + vm_inst.ip),
        lambda vm_inst: vm_inst.set_ip_if(vm_inst.pop(8, 1) + vm_inst.ip, vm_inst.pop(1)),
        lambda vm_inst: vm_inst.call(vm_inst.pop(8)),
        lambda vm_inst: vm_inst.call(vm_inst.pop(8, 1) + vm_inst.ip),
        lambda vm_inst: vm_inst.ret(),
        lambda vm_inst: vm_inst.ret(vm_inst.get_instr_dat(2)),
    ]
    assert BC_Dispatch[BC_LOAD] is vm_load
    assert BC_Dispatch[BC_STOR] is vm_store
    assert BC_Dispatch[BC_HLT] is vm_exit
    assert len(BC_Dispatch) == 128

    def __init__(self, heap_sz=16384, stack_sz=4096):
        self.api = InterruptApi()
        self.sys_regs = array.array('Q', [0] * 16)
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
        self.virt_mem_mode = VM_DISABLED
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
        self.virtual_syscalls_lvl = 1  # level at which syscalls are virtualized by the host
        # (the processor can syscall from this level into the host)
        self.watch_data = []

    def check_perm_set_or_clr_error(self, pte_top: int, pte_index: int, pte_ptr: int, pte: int, virt_addr: int, mem_req_perms: int):
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
                    self.memory[pte_ptr:pte_ptr + 8] = pte.to_bytes(8, "little")
            elif mem_req_perms == MRQ_EXEC:
                if pte & PTE_EXEC_BIT == 0:
                    self.virt_error_code = VME_PAGE_BAD_PERMS
                    self.virt_error_data = (pte_top, pte_index, (2 << 3) | 4, virt_addr)
                    return
        self.virt_error_code = VME_NONE
        self.virt_error_data = (0, 0, 0, 0)

    def walk_page(self, virt_addr, tlpte, virt_mode=VM_4_LVL_9_BIT, mem_req_perms=MRQ_DONT_CHECK) -> Optional[int]:
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
            PTE_MASK = 0xfffffffffffff000
            PTE4_HMASK, PTE4_LMASK = 0xffffff8000000000, 0x7fffffffff
            PTE3_HMASK, PTE3_LMASK = 0xffffffffc0000000, 0x3fffffff
            PTE2_HMASK, PTE2_LMASK = 0xffffffffffe00000, 0x1fffff
            if dbg_walk_page:
                print("resolving from tlpte")
            if (tlpte & PTE_VALID_BIT) == 0:
                self.virt_error_code = VME_PAGE_NOT_PRESENT
                self.virt_error_data = (0, tlpte, (0 << 3) | 0, virt_addr)
                # self.trap(INT_PAGE_FAULT, 0, virt_addr, 0)
                return
            pte_4_index = ((virt_addr >> 39) & 0x1ff) << 3
            pte_4_ptr = (tlpte & PTE_MASK) | pte_4_index
            if dbg_walk_page:
                print("resolved pte_4_ptr=%016X from tlpte" % pte_4_ptr)
            pte_4 = from_bytes(mem[pte_4_ptr:pte_4_ptr + 8], "little")
            if dbg_walk_page:
                print("resolved pte_4=%016X" % pte_4)
            if (pte_4 & PTE_VALID_BIT) == 0:
                self.virt_error_code = VME_PAGE_NOT_PRESENT
                self.virt_error_data = (tlpte, pte_4_index, (0 << 3) | 1, virt_addr)
                # self.trap(INT_PAGE_FAULT, pte_4_ptr, virt_addr, 1)
                return
            elif pte_4 & PTE_HUGE_BIT:
                self.check_perm_set_or_clr_error(tlpte, pte_4_ptr, pte_4_index, pte_4, virt_addr, mem_req_perms)
                return (pte_4 & PTE4_HMASK) | (virt_addr & PTE4_LMASK)
            pte_3_index = ((virt_addr >> 30) & 0x1ff) << 3
            pte_3_ptr = (pte_4 & PTE_MASK) | pte_3_index
            if dbg_walk_page:
                print("resolved pte_3_ptr=%016X from pte_4" % pte_3_ptr)
            pte_3 = from_bytes(mem[pte_3_ptr:pte_3_ptr + 8], "little")
            if dbg_walk_page:
                print("resolved pte_3=%016X" % pte_3)
            if (pte_3 & PTE_VALID_BIT) == 0:
                self.virt_error_code = VME_PAGE_NOT_PRESENT
                self.virt_error_data = (pte_4, pte_3_index, (0 << 3) | 2, virt_addr)
                # self.trap(INT_PAGE_FAULT, pte_3_ptr, virt_addr, 2)
                return
            elif pte_3 & PTE_HUGE_BIT:
                self.check_perm_set_or_clr_error(pte_4, pte_3_ptr, pte_3_index, pte_3, virt_addr, mem_req_perms)
                return (pte_3 & PTE3_HMASK) | (virt_addr & PTE3_LMASK)
            pte_2_index = ((virt_addr >> 21) & 0x1ff) << 3
            pte_2_ptr = (pte_3 & PTE_MASK) | pte_2_index
            if dbg_walk_page:
                print("resolved pte_2_ptr=%016X from pte_3" % pte_2_ptr)
            pte_2 = from_bytes(mem[pte_2_ptr:pte_2_ptr + 8], "little")
            if dbg_walk_page:
                print("resolved pte_2=%016X" % pte_2)
            if (pte_2 & PTE_VALID_BIT) == 0:
                self.virt_error_code = VME_PAGE_NOT_PRESENT
                self.virt_error_data = (pte_3, pte_2_index, (0 << 3) | 3, virt_addr)
                # self.trap(INT_PAGE_FAULT, pte_2_ptr, virt_addr, 3)
                return
            elif pte_2 & PTE_HUGE_BIT:
                self.check_perm_set_or_clr_error(pte_3, pte_2_ptr, pte_2_index, pte_2, virt_addr, mem_req_perms)
                return (pte_2 & PTE2_HMASK) | (virt_addr & PTE2_LMASK)
            pte_1_index = ((virt_addr >> 12) & 0x1ff) << 3
            pte_1_ptr = (pte_2 & PTE_MASK) | pte_1_index
            if dbg_walk_page:
                print("resolved pte_1_ptr=%016X from pte_2" % pte_1_ptr)
            pte_1 = from_bytes(mem[pte_1_ptr:pte_1_ptr + 8], "little")
            if dbg_walk_page:
                print("resolved pte_1=%016X" % pte_1)
            if (pte_1 & PTE_VALID_BIT) == 0:
                self.virt_error_code = VME_PAGE_NOT_PRESENT
                self.virt_error_data = (pte_2, pte_1_index, (0 << 3) | 4, virt_addr)
                # self.trap(INT_PAGE_FAULT, pte_1_ptr, virt_addr, 4)
                return
            self.check_perm_set_or_clr_error(pte_2, pte_1_ptr, pte_1_index, pte_1, virt_addr, mem_req_perms)
            return (pte_1 & PTE_MASK) | (virt_addr & 0xFFF)  # , pte_1 & 0xFFF
        elif virt_mode == VM_4_LVL_10_BIT:
            PTE_MASK = 0xffffffffffffe000
            PTE4_HMASK, PTE4_LMASK = 0xfffff80000000000, 0x7ffffffffff
            PTE3_HMASK, PTE3_LMASK = 0xfffffffe00000000, 0x1ffffffff
            PTE2_HMASK, PTE2_LMASK = 0xffffffffff800000, 0x7fffff
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
            pte_4_index = ((virt_addr >> 43) & 0x3ff) << 3
            pte_4_ptr = (tlpte & PTE_MASK) | pte_4_index
            if dbg_walk_page:
                print("resolved pte_4_ptr=%016X from tlpte" % pte_4_ptr)
            pte_4 = from_bytes(mem[pte_4_ptr:pte_4_ptr + 8], "little")
            if dbg_walk_page:
                print("resolved pte_4=%016X" % pte_4)
            if (pte_4 & PTE_VALID_BIT) == 0:
                self.virt_error_code = VME_PAGE_NOT_PRESENT
                self.virt_error_data = (tlpte, pte_4_index, (0 << 3) | 1, virt_addr)
                # self.trap(INT_PAGE_FAULT, pte_4_ptr, virt_addr, 1)
                return
            elif pte_4 & PTE_HUGE_BIT:
                self.check_perm_set_or_clr_error(tlpte, pte_4_ptr, pte_4_index, pte_4, virt_addr, mem_req_perms)
                return (pte_4 & PTE4_HMASK) | (virt_addr & PTE4_LMASK)
            pte_3_index = ((virt_addr >> 33) & 0x3ff) << 3
            pte_3_ptr = (pte_4 & PTE_MASK) | pte_3_index
            if dbg_walk_page:
                print("resolved pte_3_ptr=%016X from pte_4" % pte_3_ptr)
            pte_3 = from_bytes(mem[pte_3_ptr:pte_3_ptr + 8], "little")
            if dbg_walk_page:
                print("resolved pte_3=%016X" % pte_3)
            if (pte_3 & PTE_VALID_BIT) == 0:
                self.virt_error_code = VME_PAGE_NOT_PRESENT
                self.virt_error_data = (pte_4, pte_3_index, (0 << 3) | 2, virt_addr)
                # self.trap(INT_PAGE_FAULT, pte_3_ptr, virt_addr, 2)
                return
            elif pte_3 & PTE_HUGE_BIT:
                self.check_perm_set_or_clr_error(pte_4, pte_3_ptr, pte_3_index, pte_3, virt_addr, mem_req_perms)
                return (pte_3 & PTE3_HMASK) | (virt_addr & PTE3_LMASK)
            pte_2_index = ((virt_addr >> 23) & 0x3ff) << 3
            pte_2_ptr = (pte_3 & PTE_MASK) | pte_2_index
            if dbg_walk_page:
                print("resolved pte_2_ptr=%016X from pte_3" % pte_2_ptr)
            pte_2 = from_bytes(mem[pte_2_ptr:pte_2_ptr + 8], "little")
            if dbg_walk_page:
                print("resolved pte_2=%016X" % pte_2)
            if (pte_2 & PTE_VALID_BIT) == 0:
                self.virt_error_code = VME_PAGE_NOT_PRESENT
                self.virt_error_data = (pte_3, pte_2_index, (0 << 3) | 3, virt_addr)
                # self.trap(INT_PAGE_FAULT, pte_2_ptr, virt_addr, 3)
                return
            elif pte_2 & PTE_HUGE_BIT:
                self.check_perm_set_or_clr_error(pte_3, pte_2_ptr, pte_2_index, pte_2, virt_addr, mem_req_perms)
                return (pte_2 & PTE2_HMASK) | (virt_addr & PTE2_LMASK)
            pte_1_index = ((virt_addr >> 13) & 0x3ff) << 3
            pte_1_ptr = (pte_2 & PTE_MASK) | pte_1_index
            if dbg_walk_page:
                print("resolved pte_1_ptr=%016X from pte_2" % pte_1_ptr)
            pte_1 = from_bytes(mem[pte_1_ptr:pte_1_ptr + 8], "little")
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
                        self.virt_error_data = (pte_2, pte_1_index, (1 << 3) | 4, virt_addr)
                        return
                    elif pte_1 & PTE_DIRTY_BIT == 0:
                        pte_1 |= PTE_DIRTY_BIT
                        if dbg_walk_page:
                            print("write back page table DIRTY")
                        mem[pte_1_ptr:pte_1_ptr + 8] = pte_1.to_bytes(8, "little")
                elif mem_req_perms == MRQ_EXEC:
                    if pte_1 & PTE_EXEC_BIT == 0:
                        self.virt_error_code = VME_PAGE_BAD_PERMS
                        self.virt_error_data = (pte_2, pte_1_index, (2 << 3) | 4, virt_addr)
            self.virt_error_code = VME_NONE
            self.virt_error_data = (0, 0, 0, 0)
            return (pte_1 & PTE_MASK) | (virt_addr & 0x1FFF)  # , pte_1 & 0x1FFF

    def syscall(self, n: int):
        if self.priv_lvl == 0:
            self.trap(INT_INVAL_SYSCALL, 1)
            return
        if self.virtual_syscalls_lvl == self.priv_lvl:
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
        mem[tgt:tgt + size] = mem[src:src + size]

    def trap(self, int_n: int, arg0: int=0, arg1: int=0, arg2: int=0, arg3: int=0):
        raise Exception("interrupt %u (%s), reasons: %016X, %016X, %016X, %016X" % (int_n, INT_LST[int_n], arg0, arg1, arg2, arg3))

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
            b = self.get(8, self.sp + 16)  # color/flags  LO-DWORD: color 0x??RRGGBB, HI-DWORD: flags
            c = self.get(8, self.sp + 24)  # rect left, top
            d = self.get(8, self.sp + 32)  # rect width, height
            # import pygame
            pygame = self.objects[self.pyg_index]
            surf = self.objects[a]
            assert isinstance(surf, pygame.Surface)
            # print("in_virt: b = 0x%08X" % b)
            color = (
                (b & 0xFF0000) >> 16,
                (b & 0xFF00) >> 8,
                b & 0xFF
            )
            # print("in_virt: color =", color)
            flags = b >> 32
            surf.fill(color, pygame.Rect(c & 0xFFFFFFFF, c >> 32, d & 0xFFFFFFFF, d >> 32))
        elif n == 0x07:  # pygame.display.update
            a = self.get(8, self.sp + 8)  # pygame
            b = self.get(8, self.sp + 16)  # pointer to array of rects to update
            c = self.get(8, self.sp + 24)  # length of array of rects to update
            pygame = self.objects[a]
            if c:
                lst_rects = [
                    pygame.Rect(self.get(4, off), self.get(4, off + 4), self.get(4, off + 8), self.get(4, off + 12))
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
            self.set(8, self.sp + 32, self.objects.put(pygame.event.wait()))  # return idx as the object id
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
                self.set(4, c + 12, ord(evt.unicode))
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
            page_size = {
                VM_4_LVL_9_BIT: 4096,
                VM_4_LVL_10_BIT: 8192
            }[self.virt_mem_mode]
            page_mask = (page_size - 1)
            assert at_addr & page_mask == 0, "must load progam at page boundary"
            end = at_addr + len(memory)
            end1 = (end | page_mask) ^ page_mask
            for addr in range(at_addr, end1, page_size):
                mv = self.get_mv_as_priv(self.priv_lvl, page_size, addr, MRQ_DONT_CHECK)
                mv[:] = mem_v[addr: addr + page_size]
            if end1 != end:
                mv = self.get_mv_as_priv(self.priv_lvl, end - end1, end1, MRQ_DONT_CHECK)
                mv[:] = mem_v[end1:]
        else:
            a = len(memory)
            b = len(self.memory)
            if a > b:
                raise ValueError("Not Enough memory (given %u bytes when only %u are available" % (a, b))
            a += at_addr
            if a > b:
                raise ValueError("Not Enough memory (given %u minus offset bytes when only %u are available" % (a, b))
            self.memory[at_addr:a] = memory

    def get_mv_as_priv(self, priv_lvl: int, sz: int, addr: int, permissions: int) -> Optional[Union[memoryview, SplitMemView]]:
        vmd = self.virt_mem_mode
        if vmd == VM_4_LVL_10_BIT:
            assert sz <= 8192
        elif vmd == VM_4_LVL_10_BIT:
            assert sz <= 4096
        if vmd:
            phys_addr = self.walk_page(addr, self.sys_regs[priv_lvl], vmd, permissions)
            err_code = self.virt_error_code
            if err_code:
                if err_code == VME_PAGE_NOT_PRESENT:
                    self.trap(INT_PAGE_FAULT, *self.virt_error_data)
                elif err_code == VME_PAGE_BAD_PERMS:
                    self.trap(INT_PROTECT_FAULT, *self.virt_error_data)
                return
            page_mask = [0, 0xfffffffffffff000, 0xffffffffffffe000, 0xfffff000][vmd]
            if sz > 1 and (addr & page_mask) != ((addr + sz - 1) & page_mask):
                index_mask = [0, 0xFFF, 0x1FFF, 0xFFF][vmd]
                index_mask_p1 = index_mask + 1
                addr1 = self.walk_page(addr + index_mask_p1, self.sys_regs[priv_lvl], vmd, permissions)
                err_code = self.virt_error_code
                if err_code:
                    if err_code == VME_PAGE_NOT_PRESENT:
                        self.trap(INT_PAGE_FAULT, *self.virt_error_data)
                    elif err_code == VME_PAGE_BAD_PERMS:
                        self.trap(INT_PROTECT_FAULT, *self.virt_error_data)
                    return
                sz0 = index_mask_p1 - (addr1 & index_mask)
                sz1 = (addr1 + sz) & index_mask
                addr = phys_addr
                mem = memoryview(self.memory)
                if addr + sz0 > len(mem):
                    raise IndexError("Memory address out of bounds (Sz = %u, addr = %u)" % (sz0, addr))
                elif addr1 + sz1 > len(mem):
                    raise IndexError("Memory address out of bounds (Sz = %u, addr = %u)" % (sz1, addr1))
                if self.watch_memory:
                    assert self.watch_memory == 1, "Only Exceptional watchpoints are supported"
                    for i, (perm, pt) in enumerate(self.watch_points):
                        if perm != permissions:
                            continue
                        if addr <= pt < addr + sz0 or addr1 <= pt < addr1 + sz1:
                            raise Warning("Watchpoint %u encountered (perm = %u, pt = %u)" % (i, perm, pt))
                return SplitMemView(mem[addr: addr + sz0], mem[addr1: addr1 + sz1])
            addr = phys_addr
        mem = memoryview(self.memory)
        assert isinstance(addr, int)
        assert isinstance(sz, int)
        if addr + sz > len(mem):
            raise IndexError("Memory address out of bounds (Sz = %u, addr = %u)" % (sz, addr))
        if self.watch_memory:
            assert self.watch_memory == 1, "Only Exceptional watchpoints are supported"
            for i, (perm, pt) in enumerate(self.watch_points):
                if perm != permissions:
                    continue
                if addr <= pt < addr + sz:
                    raise Warning("Watchpoint %u encountered (perm = %u, pt = %u)" % (i, perm, pt))
        return mem[addr: addr + sz]

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

    def ret(self, n: int=0, r_sz: int=0):
        self.ax = bytes(self.memory[self.sp:self.sp + r_sz])
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

    def _push(self, sz: int, val: Union[int,float], typ: int=0) -> bool:
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

    def get_instr_dat(self, sz: int, typ: int=0) -> Optional[Union[int, float]]:
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

    def _pop(self, sz: int, typ: int=0) -> Optional[Union[int, float]]:
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

    def execute_with_interrupts(self, apic: AdvProgIntCtl):
        BC_Dispatch = self.BC_Dispatch
        get_instr_dat = self.get_instr_dat
        self.apic = apic
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
            if apic.int_ready:
                self.switch_to_interrupt_direct(apic.which_int, apic.arg0, apic.arg1, apic.arg2, apic.arg3)

    def switch_to_interrupt(self, int_n: int):
        old_sp = self.sp
        arg0 = self.get(8, old_sp)
        arg1 = self.get(8, old_sp + 8)
        arg2 = self.get(8, old_sp + 16)
        arg3 = self.get(8, old_sp + 24)
        old_ip = self.ip
        old_bp = self.bp
        self.sys_regs[SVSRB_SP | self.priv_lvl] = old_sp
        isr_ptr_k = self.sys_regs[SVSR_KERNEL_ISR]
        isr_ptr_h = self.sys_regs[SVSR_HYPER_ISR]
        assert isr_ptr_k & 0x7FF == 0, "expected isr table to be aligned to 2048 bytes"
        assert isr_ptr_h & 0x7FF == 0, "expected isr table to be aligned to 2048 bytes"
        isr_tgt = (
            0
            if self.priv_lvl != 0 and isr_ptr_k == 0 else
            self.get_as_priv(1, 8, isr_ptr_k | (int_n << 3))
        )
        isr_priv = 1
        if isr_tgt == 0 and isr_ptr_h != 0:
            isr_tgt = self.get_as_priv(0, 8, isr_ptr_h | (int_n << 3))
            isr_priv = 0
        if isr_tgt == 0 or isr_priv < self.virtual_syscalls_lvl:
            return
        old_flags = self.sys_regs[SVSR_FLAGS]
        self.set_flags_pri_priv(self.priority, isr_priv)
        self.sp = self.sys_regs[SVSRB_SP | isr_priv]
        self.push(8, arg3)
        self.push(8, arg2)
        self.push(8, arg1)
        self.push(8, arg0)
        self.push(8, old_flags)  # TODO: note that these flags will be checked to prevent privilege escalation
        self.push(8, old_bp)
        self.push(8, old_ip)
        self.ip = isr_tgt
        self.bp = self.sp

    def switch_to_interrupt_direct(self, int_n: int, arg0: int, arg1: int, arg2: int, arg3: int, target_hyper: bool=False):
        old_ip = self.ip
        old_bp = self.bp
        old_sp = self.sp
        self.sys_regs[SVSRB_SP | self.priv_lvl] = old_sp
        isr_ptr_k = self.sys_regs[SVSR_KERNEL_ISR]
        isr_ptr_h = self.sys_regs[SVSR_HYPER_ISR]
        assert isr_ptr_k & 0x7FF == 0, "expected isr table to be aligned to 2048 bytes"
        assert isr_ptr_h & 0x7FF == 0, "expected isr table to be aligned to 2048 bytes"
        isr_tgt = (
            0
            if self.priv_lvl != 0 and isr_ptr_k == 0 and not target_hyper else
            self.get_as_priv(1, 8, isr_ptr_k | (int_n << 3))
        )
        isr_priv = 1
        if isr_tgt == 0 and isr_ptr_h != 0:
            isr_tgt = self.get_as_priv(0, 8, isr_ptr_h | (int_n << 3))
            isr_priv = 0
        if isr_tgt == 0 or isr_priv < self.virtual_syscalls_lvl:
            return
        old_flags = self.sys_regs[SVSR_FLAGS]
        self.set_flags_pri_priv(self.priority, isr_priv)
        self.sp = self.sys_regs[SVSRB_SP | isr_priv]
        self.push(8, arg3)
        self.push(8, arg2)
        self.push(8, arg1)
        self.push(8, arg0)
        self.push(8, old_flags)  # TODO: note that these flags will be checked to prevent privilege escalation
        self.push(8, old_bp)
        self.push(8, old_ip)
        self.ip = isr_tgt
        self.bp = self.sp
        # TODO: if this is the last interrupt being handled then the return instruction acts like a sysret
        # TODO:   if not then the return instruction acts like a regular return

    def return_from_interrupt(self):
        sp = self.sp
        old_ip = self.get(8, sp)
        old_bp = self.get(8, sp + 8)
        old_flags = self.get(8, sp + 16)
        self.reset_stack(56)
        self.sys_regs[SVSRB_SP | self.priv_lvl] = self.sp
        if ((old_flags >> 8) & 3) < self.priv_lvl:
            self.switch_to_interrupt_direct(INT_PROTECT_FAULT, self.ip, old_flags, sp, self.bp, True)
            return
        self.set_flags(old_flags)
        self.bp = old_bp
        self.ip = old_ip
        self.sp = self.sys_regs[SVSRB_SP | self.priv_lvl]

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

    def debug_with_interrupts(self, brk_points, apic: AdvProgIntCtl):
        BC_Dispatch = self.BC_Dispatch
        get_instr_dat = self.get_instr_dat
        self.apic = apic
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
            if apic.int_ready:
                self.switch_to_interrupt_direct(apic.which_int, apic.arg0, apic.arg1, apic.arg2, apic.arg3)
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
        return True

    def get_stack_list(self, most_recent_call_last=False):
        ip = self.ip
        bp = self.bp
        rtn = [
            (ip, bp)
        ]
        while bp < len(self.memory):
            ip = self.get(8, bp)
            bp = self.get(8, bp + 8)
            rtn.append((ip, bp))
        if most_recent_call_last:
            rtn.reverse()
        return rtn

    def print_stack_trace(self, most_recent_call_last=False):
        print("\n".join([
            "CodeAddr = 0x%04X, BasePointer = 0x%04X" % (ip, bp)
            for ip, bp in self.get_stack_list(most_recent_call_last)]))

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
        mem_mode = self.sys_regs[SVSR_FLAGS] & 0x3c00
        self.sys_regs[SVSR_FLAGS] = priority | (priv_lvl << 8) | mem_mode
        self.priv_lvl = priv_lvl
        self.priority = priority

    def set_flags_pri_priv_mmd(self, priority: int, priv_lvl: int, mem_mode: int):
        self.sys_regs[SVSR_FLAGS] = priority | (priv_lvl << 8) | (mem_mode << 10)
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
        self.virt_mem_mode = (flags >> 10) & 0xF


VM = VirtualMachine


def run_stack_vm_tests():
    vm = VM(512, 256)
    try:
        vm.load_program(bytearray([
            BC_LOAD, BCR_EA_R_IP | BCR_SZ_1, 12,
            BC_HLT
        ]))
        vm.execute()
        v = vm.pop(8)
        assert v == 15, "got %u" % v
        vm.load_program(bytearray([
            BC_LOAD, BCR_ABS_C | BCR_SZ_1, 13,
            BC_LOAD, BCR_ABS_C | BCR_SZ_1, 21,
            BC_ADD1,
            BC_HLT
        ]))
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
    print("\n  ".join([
        "BEFORE:",
        "sys_regs = %r" % vm.sys_regs,
        "ip: %u, bp: %u, sp: %u" % (vm.ip, vm.bp, vm.sp),
        "priority = %u" % vm.priority,
        "priv_lvl = %u" % vm.priv_lvl
    ]))
    vm.execute()
    print("\n  ".join([
        "AFTER:",
        "sys_regs = %r" % vm.sys_regs,
        "ip: %u, bp: %u, sp: %u" % (vm.ip, vm.bp, vm.sp),
        "priority = %u" % vm.priority,
        "priv_lvl = %u" % vm.priv_lvl
    ]))
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
    print("\n  ".join([
        "BEFORE(sysret):",
        "sys_regs = %r" % vm.sys_regs,
        "ip: %u, bp: %u, sp: %u" % (vm.ip, vm.bp, vm.sp),
        "priority = %u" % vm.priority,
        "priv_lvl = %u" % vm.priv_lvl
    ]))
    vm.execute()
    print("\n  ".join([
        "AFTER(sysret):",
        "sys_regs = %r" % vm.sys_regs,
        "ip: %u, bp: %u, sp: %u" % (vm.ip, vm.bp, vm.sp),
        "priority = %u" % vm.priority,
        "priv_lvl = %u" % vm.priv_lvl
    ]))
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
        vm.sys_regs[SVSR_KERNEL_PTE] = 0x1000 | PTE_VALID_BIT
        mem[0x1000: 0x1008] = (PTE_VALID_BIT | 0x2000).to_bytes(8, "little")
        for c in range(0x1008, 0x2000, 8):
            mem[c: c + 8] = b"\0" * 8
        mem[0x2000: 0x2008] = (PTE_VALID_BIT | 0x3000).to_bytes(8, "little")
        for c in range(0x2008, 0x3000, 8):
            mem[c: c + 8] = b"\0" * 8
        mem[0x3000: 0x3008] = (PTE_VALID_BIT | 0x4000).to_bytes(8, "little")
        for c in range(0x3008, 0x4000, 8):
            mem[c: c + 8] = b"\0" * 8
        mem[0x4000: 0x4008] = (PTE_VALID_BIT | 0x5000).to_bytes(8, "little")
        for c in range(0x4008, 0x5000, 8):
            mem[c: c + 8] = b"\0" * 8
        num = 12345678987654321
        mem[0x5000: 0x5008] = num.to_bytes(8, "little")
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
        insert_page_tables(vm, 0xFFFFFFFFFFFFF000, 1, 0x6000, 0x7000, 0x8000, 0x9000, 0xF)  # SHOULD NOT FAIL
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
    mem[0x500A:0x500A + 8] = (12288 + 65536 + 16777219).to_bytes(8, "little")
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


def insert_page_tables(vm: VirtualMachine, virt_addr: int, priv_lvl: int, def0: int, def1: int, def2: int, def3: int, perms: int, dbg_prn: bool=True, force_new_pte_1: bool=False):
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
    assert vm.virt_mem_mode == VM_4_LVL_9_BIT, "this function only supports VM_4_LVL_9_BIT"
    assert def0 & 0xFFF == 0
    assert def1 & 0xFFF == 0
    assert def2 & 0xFFF == 0
    assert def3 & 0xFFF == 0
    if dbg_prn:
        print("perms=", perms)
    PTE_MASK = 0xfffffffffffff000
    PTE_VALID_BIT = 0x001
    PTE_HUGE_BIT = 0x010
    tlpte = vm.sys_regs[priv_lvl]
    from_bytes = int.from_bytes
    # TODO: copy the principal code of `VirtualMachine.walk_page`
    # TODO: instead of faulting when encountering an invalid page
    # TODO:   set the page pointer to the corresponding default the argunments to this function
    assert (tlpte & PTE_VALID_BIT) != 0
    lst_new = [False] * 4
    pte_4_index = ((virt_addr >> 39) & 0x1ff) << 3
    pte_4_ptr = (tlpte & PTE_MASK) | pte_4_index
    pte_4_old = pte_4 = from_bytes(mem[pte_4_ptr:pte_4_ptr + 8], "little")
    if (pte_4 & PTE_VALID_BIT) == 0:
        pte_4 = def0 | PTE_VALID_BIT
        mem[pte_4_ptr: pte_4_ptr + 8] = pte_4.to_bytes(8, "little")
        lst_new[0] = True
    assert pte_4 & PTE_HUGE_BIT == 0
    pte_3_index = ((virt_addr >> 30) & 0x1ff) << 3
    pte_3_ptr = (pte_4 & PTE_MASK) | pte_3_index
    pte_3_old = pte_3 = from_bytes(mem[pte_3_ptr:pte_3_ptr + 8], "little")
    if (pte_3 & PTE_VALID_BIT) == 0:
        pte_3 = def1 | PTE_VALID_BIT
        mem[pte_3_ptr: pte_3_ptr + 8] = pte_3.to_bytes(8, "little")
        lst_new[1] = True
    assert pte_3 & PTE_HUGE_BIT == 0
    pte_2_index = ((virt_addr >> 21) & 0x1ff) << 3
    pte_2_ptr = (pte_3 & PTE_MASK) | pte_2_index
    pte_2_old = pte_2 = from_bytes(mem[pte_2_ptr:pte_2_ptr + 8], "little")
    if (pte_2 & PTE_VALID_BIT) == 0:
        pte_2 = def2 | PTE_VALID_BIT
        mem[pte_2_ptr: pte_2_ptr + 8] = pte_2.to_bytes(8, "little")
        lst_new[2] = True
    assert pte_2 & PTE_HUGE_BIT == 0
    pte_1_index = ((virt_addr >> 12) & 0x1ff) << 3
    pte_1_ptr = (pte_2 & PTE_MASK) | pte_1_index
    pte_1_old = pte_1 = from_bytes(mem[pte_1_ptr:pte_1_ptr + 8], "little")
    if pte_1 & 0xFFF != perms:
        pte_1 &= perms | PTE_MASK
        pte_1 |= perms
    if (pte_1 & PTE_VALID_BIT) == 0 or force_new_pte_1:
        pte_1 = def3 | PTE_VALID_BIT
    else:
        print("WARNING using existing PTE_1")
    assert pte_1 & PTE_HUGE_BIT == 0
    if pte_1_old != pte_1:
        mem[pte_1_ptr: pte_1_ptr + 8] = pte_1.to_bytes(8, "little")
        lst_new[3] = True
    lst_pte = [
        (pte_4_old, pte_4),
        (pte_3_old, pte_3),
        (pte_2_old, pte_2),
        (pte_1_old, pte_1)
    ]
    if dbg_prn:
        for c, b in enumerate(lst_new):
            old, cur = lst_pte[c]
            print("PTE%u old: %016X new: %016X" % (4 - c, old, cur))
    return lst_new


class AdvPageAlloc(object):
    def __init__(self, mv: Optional[Union[memoryview, bytearray]], mn: int, mx: int, pgsize: int):
        if mv is not None:
            assert (mx - mn + 7) // 8 <= len(mv), "memory view is not big enough to hold allocation bits"
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


def insert_page_tables_1(vm: VirtualMachine, virt_addr: int, priv_lvl: int, alloc: AdvPageAlloc, perms: int, dbg_prn: bool=True, force_new_pte_1: bool=False):
    """
    :param vm: virtual machine
    :param virt_addr: virtual address
    :param priv_lvl: privilege level of the address space
    :param alloc: an allocator with an `alloc()` method that can fail with a ValueError
    :param perms: permissions
    :return: list of which of the page levels were created list[0] is True if it used the addess `def0` as a new page in the hierarchy
    """
    if dbg_prn:
        print("insert_page_tables(vm,\n  virt_addr = 0x%016X,\n  priv_lvl = %u,\n  alloc = %r\n  perms = %u,\n  dbg_prn = %r\n)" % (
            virt_addr,
            priv_lvl,
            alloc,
            perms,
            dbg_prn
        ))
    mem = memoryview(vm.memory)
    assert vm.virt_mem_mode == VM_4_LVL_9_BIT, "this function only supports VM_4_LVL_9_BIT"
    if dbg_prn:
        print("perms=", perms)
    PTE_MASK = 0xfffffffffffff000
    PTE_VALID_BIT = 0x001
    PTE_HUGE_BIT = 0x010
    acquired = []
    from_bytes = int.from_bytes
    try:
        tlpte = vm.sys_regs[priv_lvl]
        # TODO: copy the principal code of `VirtualMachine.walk_page`
        # TODO: instead of faulting when encountering an invalid page
        # TODO:   set the page pointer to the corresponding default the argunments to this function
        assert (tlpte & PTE_VALID_BIT) != 0
        pte_4_index = ((virt_addr >> 39) & 0x1ff) << 3
        pte_4_ptr = (tlpte & PTE_MASK) | pte_4_index
        pte_4_old = pte_4 = from_bytes(mem[pte_4_ptr:pte_4_ptr + 8], "little")
        if (pte_4 & PTE_VALID_BIT) == 0:
            def0 = alloc.alloc()
            pte_4 = def0 | PTE_VALID_BIT
            acquired.append((pte_4_ptr, pte_4_ptr + 8, def0, pte_4_old))
            if dbg_prn:
                print("Injecting PTE_4 0x%016X at address 0x%016X" % (pte_4, pte_4_ptr))
            mem[pte_4_ptr: pte_4_ptr + 8] = pte_4.to_bytes(8, "little")
        assert pte_4 & PTE_HUGE_BIT == 0
        pte_3_index = ((virt_addr >> 30) & 0x1ff) << 3
        pte_3_ptr = (pte_4 & PTE_MASK) | pte_3_index
        pte_3_old = pte_3 = from_bytes(mem[pte_3_ptr:pte_3_ptr + 8], "little")
        if (pte_3 & PTE_VALID_BIT) == 0:
            def1 = alloc.alloc()
            pte_3 = def1 | PTE_VALID_BIT
            acquired.append((pte_3_ptr, pte_3_ptr + 8, def1, pte_3_old))
            if dbg_prn:
                print("Injecting PTE_3 0x%016X at address 0x%016X" % (pte_3, pte_3_ptr))
            mem[pte_3_ptr: pte_3_ptr + 8] = pte_3.to_bytes(8, "little")
        assert pte_3 & PTE_HUGE_BIT == 0
        pte_2_index = ((virt_addr >> 21) & 0x1ff) << 3
        pte_2_ptr = (pte_3 & PTE_MASK) | pte_2_index
        pte_2_old = pte_2 = from_bytes(mem[pte_2_ptr:pte_2_ptr + 8], "little")
        if (pte_2 & PTE_VALID_BIT) == 0:
            def2 = alloc.alloc()
            pte_2 = def2 | PTE_VALID_BIT
            acquired.append((pte_2_ptr, pte_2_ptr + 8, def2, pte_2_old))
            if dbg_prn:
                print("Injecting PTE_2 0x%016X at address 0x%016X" % (pte_2, pte_2_ptr))
            mem[pte_2_ptr: pte_2_ptr + 8] = pte_2.to_bytes(8, "little")
        assert pte_2 & PTE_HUGE_BIT == 0
        pte_1_index = ((virt_addr >> 12) & 0x1ff) << 3
        pte_1_ptr = (pte_2 & PTE_MASK) | pte_1_index
        pte_1_old = pte_1 = from_bytes(mem[pte_1_ptr:pte_1_ptr + 8], "little")
        if (pte_1 & PTE_VALID_BIT) == 0 or force_new_pte_1:
            def3 = alloc.alloc()
            pte_1 = def3 | PTE_VALID_BIT | perms
            acquired.append((pte_1_ptr, pte_1_ptr + 8, def3, pte_1_old))
            if dbg_prn:
                print("Injecting PTE_1 0x%016X at address 0x%016X" % (pte_1, pte_1_ptr))
            mem[pte_1_ptr: pte_1_ptr + 8] = pte_1.to_bytes(8, "little")
        elif pte_1 & 0xFFF != perms:
            pte_1 &= perms | PTE_MASK
            pte_1 |= perms
            mem[pte_1_ptr: pte_1_ptr + 8] = pte_1.to_bytes(8, "little")
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
                (pte_1_old, pte_1)
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
                mem[start: end] = old.to_bytes(end - start, "little")
                alloc.free(new)
        else:
            for start, end, old in acquired:
                mem[start: end] = old.to_bytes(end - start, "little")
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


def enable_virt_mem(vm: VirtualMachine, alloc: PageAllocator, priv_lvl: int, code_segment_start: int, code_segment_end: int, data_segment_start, data_segment_end: Optional[int], dbg_prn: bool=False):
    PTE_VALID_BIT = 0x001
    PTE_WRITE_BIT = 0x002
    PTE_EXEC_BIT = 0x004
    PTE_DIRTY_BIT = 0x008
    vm.set_mem_mode(VM_4_LVL_9_BIT)
    tlpte = (alloc.get_and_alloc_next_false() << 12) | PTE_VALID_BIT
    adv_alloc = AdvPageAlloc(memoryview(alloc.byts), 0, alloc.max_addr, 4096)
    vm.sys_regs[priv_lvl] = tlpte
    assert code_segment_start & 0xFFF == 0, "page alignment"
    assert code_segment_end & 0xFFF == 0, "page alignment"
    assert data_segment_start & 0xFFF == 0, "page alignment"
    assert data_segment_end is None or data_segment_end & 0xFFF == 0, "page alignment"
    if data_segment_end is not None:
        assert code_segment_end <= data_segment_start or code_segment_start >= data_segment_end, "code and data segments cannot overlap"
    else:
        if code_segment_start > data_segment_start:
            data_segment_end = code_segment_start
        else:
            assert code_segment_end <= data_segment_start
    for addr in range(code_segment_start, code_segment_end, 4096):
        assert insert_page_tables_1(
            vm, addr, priv_lvl,
            adv_alloc,
            PTE_VALID_BIT | PTE_EXEC_BIT,
            dbg_prn=dbg_prn, force_new_pte_1=True
        )
    if data_segment_end is not None:
        for addr in range(data_segment_start, data_segment_end, 4096):
            assert insert_page_tables_1(
                vm, addr, priv_lvl,
                adv_alloc,
                PTE_VALID_BIT | PTE_WRITE_BIT | PTE_DIRTY_BIT,
                dbg_prn=dbg_prn, force_new_pte_1=True
            )
        vm.sp = data_segment_end
    else:
        addr = data_segment_start
        while insert_page_tables_1(
                vm, addr, priv_lvl,
                adv_alloc,
                PTE_VALID_BIT | PTE_WRITE_BIT | PTE_DIRTY_BIT,
                dbg_prn=dbg_prn, force_new_pte_1=True
            ):
            addr += 4096
        vm.sp = addr
