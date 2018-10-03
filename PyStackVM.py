import struct
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
    "TOS"
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
    typ = a & BCR_TYP_MASK
    sz = 1 << ((a & BCR_SZ_MASK) >> 5)
    if typ == BCR_ABS_A4:
        addr = vm_inst.get_instr_dat(4)
        vm_inst.push(sz, vm_inst.get(sz, addr))
    elif typ == BCR_ABS_A8:
        addr = vm_inst.get_instr_dat(8)
        vm_inst.push(sz, vm_inst.get(sz, addr))
    elif typ == BCR_ABS_S4:
        addr = vm_inst.pop(4)
        vm_inst.push(sz, vm_inst.get(sz, addr))
    elif typ == BCR_ABS_S8:
        addr = vm_inst.pop(8)
        vm_inst.push(sz, vm_inst.get(sz, addr))
    elif typ & BCR_R_BP_MASK == BCR_R_BP_VAL:  # BCR_R_BP1, BCR_R_BP2, BCR_R_BP4, BCR_R_BP8
        n_bytes = 1 << (typ & 0x03)
        addr = vm_inst.get_instr_dat(n_bytes, 1)
        addr += vm_inst.bp
        vm_inst.push(sz, vm_inst.get(sz, addr))
    elif typ == BCR_ABS_C:
        vm_inst.push(sz, vm_inst.get_instr_dat(sz))
    elif typ == BCR_REG_BP:
        vm_inst.push(8, vm_inst.bp)
    elif typ == BCR_EA_R_IP:
        vm_inst.push(8, vm_inst.get_instr_dat(sz, 1) + vm_inst.ip)
    elif typ == BCR_TOS:
        vm_inst.push(sz, vm_inst.get(sz, vm_inst.sp))
    else:
        raise ValueError(
            "Unsupported BCR code for BC_LOAD instruction: %u at 0x%X" % (typ, vm_inst.ip))


def vm_store(vm_inst):
    """
    :param VirtualMachine vm_inst:
    """
    a = vm_inst.get_instr_dat(1)
    typ = a & BCR_TYP_MASK
    sz = 1 << ((a & BCR_SZ_MASK) >> 5)
    if typ == BCR_ABS_A4:
        addr = vm_inst.get_instr_dat(4)
        vm_inst.set(sz, addr, vm_inst.pop(sz))
    elif typ == BCR_ABS_A8:
        addr = vm_inst.get_instr_dat(8)
        vm_inst.set(sz, addr, vm_inst.pop(sz))
    elif typ == BCR_ABS_S4:
        addr = vm_inst.pop(4)
        vm_inst.set(sz, addr, vm_inst.pop(sz))
    elif typ == BCR_ABS_S8:
        addr = vm_inst.pop(8)
        vm_inst.set(sz, addr, vm_inst.pop(sz))
    elif typ & BCR_R_BP_MASK == BCR_R_BP_VAL:  # BCR_R_BP1, BCR_R_BP2, BCR_R_BP4, BCR_R_BP8
        n_bytes = 1 << (typ & 0x03)
        addr = vm_inst.get_instr_dat(n_bytes, 1)
        addr += vm_inst.bp
        vm_inst.set(sz, addr, vm_inst.pop(sz))
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
        sys_num = vm_inst.pop(4)
        if vm_inst.cr4 & 0x3 == vm_inst.virtual_syscalls_lvl:
            vm_inst.virt_syscall(sys_num)
        else:
            num = vm_inst.sys_fn[vm_inst.cr4 & 0x3]
            old_regs = [vm_inst.cr4, vm_inst.ip, vm_inst.sp, vm_inst.bp]  # TODO
            vm_inst.call(num)
        raise NotImplementedError("SysCall (CALL_E with IS_SYS=1) is unsupported")
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
        raise NotImplementedError("SysCall (CALL_E with IS_SYS=1) is unsupported")
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
    del vm_inst
    raise NotImplementedError("SysCall (CALL_E with IS_SYS=1) is unsupported")


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
            ch = ch(ch) if ch > 0xFF else ch(ch)
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


def vm_interrupt(vm_inst):
    """
    :param VirtualMachine vm_inst:
    """
    a = vm_inst.get_instr_dat(1)
    if a > 0x3F:
        raise NotImplementedError("Not Implemented")
    vm_inst.api.interrupt(vm_inst, a)


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
        lambda vm_inst: vm_inst.push(2, lshift1(vm_inst.pop(2), vm_inst.pop(2))),
        lambda vm_inst: vm_inst.push(4, lshift1(vm_inst.pop(4), vm_inst.pop(4))),
        lambda vm_inst: vm_inst.push(8, lshift1(vm_inst.pop(8), vm_inst.pop(8))),
        lambda vm_inst: vm_inst.push(1, rshift1(vm_inst.pop(1), vm_inst.pop(1))),
        lambda vm_inst: vm_inst.push(2, rshift1(vm_inst.pop(2), vm_inst.pop(2))),
        lambda vm_inst: vm_inst.push(4, rshift1(vm_inst.pop(4), vm_inst.pop(4))),
        lambda vm_inst: vm_inst.push(8, rshift1(vm_inst.pop(8), vm_inst.pop(8))),
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
        self.memory = bytearray(heap_sz + stack_sz)
        self.ip = 0
        self.sp = len(self.memory)
        self.bp = self.sp
        self.ax = 0
        self.running = 1
        # CR4 is the control register #4
        #   bit map is as follows
        #   [a a]
        #   a: 0,1
        #     this is the Privilege level (0: hypervisor, 1: kernel, 2: userspace, 3: webspace)
        # as such there are 4 separate top-level page table entries
        #   PTE hyper
        #   PTE kernel
        #   PTE user
        #   PTE web
        self.cr4 = 1
        self.virtual_syscalls_lvl = 1
        self.sys_fn = [0] * 4
        self.watch_data = []

    def virt_syscall(self, n: int):
        pass

    def load_program(self, memory, at_addr=0):
        """
        :param bytearray memory:
        :param int at_addr:
        """
        a = len(memory)
        b = len(self.memory)
        if a > b:
            raise ValueError("Not Enough memory (given %u bytes when only %u are available" % (a, b))
        a += at_addr
        if a > b:
            raise ValueError("Not Enough memory (given %u minus offset bytes when only %u are available" % (a, b))
        self.memory[at_addr:a] = memory

    def get(self, sz, addr):
        if addr + sz > len(self.memory):
            raise IndexError("Memory address out of bounds (Sz = %u, addr = %u)" % (sz, addr))
        rtn = 0
        for c in range(addr, addr + sz):
            rtn |= self.memory[c] << ((c - addr) * 8)
        return rtn

    def get_float(self, sz, addr):
        if addr + sz > len(self.memory):
            raise IndexError("Memory address out of bounds (Sz = %u, addr = %u)" % (sz, addr))
        assert sz in [2, 4, 8, 16]
        if sz == 8:
            return double_t.unpack_from(self.memory, addr)[0]
        elif sz == 4:
            return float_t.unpack_from(self.memory, addr)[0]
        else:
            raise NotImplementedError("Not Implemented")

    def set(self, sz, addr, v):
        if addr + sz > len(self.memory):
            raise IndexError("Memory address out of bounds (Sz = %u, addr = %u)" % (sz, addr))
        for c in range(addr, addr + sz):
            self.memory[c] = v & 0xFF
            v >>= 8

    def set_float(self, sz, addr, v):
        if addr + sz > len(self.memory):
            raise IndexError("Memory address out of bounds (Sz = %u, addr = %u)" % (sz, addr))
        assert sz in [2, 4, 8, 16]
        if sz == 8:
            double_t.pack_into(self.memory, addr, v)
        elif sz == 4:
            float_t.pack_into(self.memory, addr, v)
        else:
            raise NotImplementedError("Not Implemented")

    def set_bytes(self, addr, data):
        """
        :param int addr:
        :param bytes|bytearray data:
        """
        sz = len(data)
        if addr + sz > len(self.memory):
            raise IndexError("Memory address out of bounds (Sz = %u, addr = %u)" % (sz, addr))
        self.memory[addr:addr + sz] = data

    def set_ip(self, v):
        self.ip = v

    def set_ip_if(self, v, b):
        if b:
            self.ip = v

    def call(self, addr):
        self.push(8, self.bp)
        self.push(8, self.ip)
        self.ip = addr
        self.bp = self.sp

    def ret(self, n=0, r_sz=0):
        self.ax = bytes(self.memory[self.sp:self.sp + r_sz])
        self.sp = self.bp
        self.ip = self.pop(8)
        self.bp = self.pop(8)
        if n > 0:
            self.sp += n

    def reset_stack(self, n):
        self.sp += n

    def add_stack(self, n):
        self.sp -= n

    def swap(self, sz):
        a = self.pop(sz)
        b = self.pop(sz)
        self.push(sz, a)
        self.push(sz, b)

    def _push(self, sz, val, typ=0):
        self.sp -= sz
        if typ == 0 or typ == 1:
            if val < 0:
                val += 1 << (sz * 8)
            for c in range(self.sp, self.sp + sz):
                self.memory[c] = val & 0xFF
                val >>= 8
        elif typ == 2:
            if sz == 4:
                self.memory[self.sp: self.sp + sz] = float_t.pack(val)
            elif sz == 8:
                self.memory[self.sp: self.sp + sz] = double_t.pack(val)
            else:
                raise TypeError("Cannot have a %u byte float" % sz)
        else:
            raise ValueError("Unrecognized TypeId %u" % typ)

    def get_instr_dat(self, sz, typ=0):
        if self.ip >= len(self.memory):
            raise IndexError("Memory address out of bounds (Sz = %u, ip = %u)" % (sz, self.ip))
        data = self.memory[self.ip: self.ip + sz]
        rtn = 0
        if typ == 0:
            for c in range(sz):
                rtn |= data[c] << (c * 8)
        elif typ == 1:
            for c in range(sz):
                rtn |= data[c] << (c * 8)
            if data[sz - 1] & 0x80:
                rtn -= 1 << (sz * 8)
        elif typ == 2:
            if sz == 4:
                rtn = float_t.unpack(data)[0]
            elif sz == 8:
                rtn = double_t.unpack(data)[0]
            else:
                raise TypeError("Cannot have a %u byte float" % sz)
        else:
            raise ValueError("Unrecognized TypeId %u" % typ)
        self.ip += sz
        return rtn

    def _pop(self, sz, typ=0):
        if self.sp + sz > len(self.memory):
            raise IndexError("Memory address out of bounds (Sz = %u, sp = %u)" % (sz, self.sp))
        data = self.memory[self.sp: self.sp + sz]
        self.sp += sz
        rtn = 0
        if typ == 0:
            for c in range(sz):
                rtn |= data[c] << (c * 8)
        elif typ == 1:
            for c in range(sz):
                rtn |= data[c] << (c * 8)
            if data[sz - 1] & 0x80:
                rtn -= 1 << (sz * 8)
        elif typ == 2:
            if sz == 4:
                rtn = float_t.unpack(data)[0]
            elif sz == 8:
                rtn = double_t.unpack(data)[0]
            else:
                raise TypeError("Cannot have a %u byte float" % sz)
        else:
            raise ValueError("Unrecognized TypeId %u" % typ)
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
        while self.running:
            code = self.get_instr_dat(1, 0)
            self.BC_Dispatch[code](self)

    def debug(self, brk_points):
        while self.running:
            if self.ip in brk_points:
                return True
            code = self.get_instr_dat(1, 0)
            self.BC_Dispatch[code](self)
        return False

    def step(self):
        if not self.running:
            return False
        code = self.get_instr_dat(1, 0)
        self.BC_Dispatch[code](self)
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


run_stack_vm_tests()
# my_stack_vm = VM()
# my_stack_vm.load_program(cmpl_obj.memory, 0)
# my_stack_vm.execute()
