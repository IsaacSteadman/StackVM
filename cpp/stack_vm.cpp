#include <cstdint>
#include <limits>
#include <utility>
#include <cmath>
#include <type_traits>
#include <iostream>
#include <vector>
#include <memory>
#ifdef defined(_WIN64) || (defined(_WIN32) && !defined(__CYGWIN__))
#define STACK_VM_EXPORT __declspec(dllexport)
#else
#define STACK_VM_EXPORT
#endif

using std::vector;

enum StackVM_BC
{
  BC_NOP = 0,
  BC_HLT = 1,
  BC_EQ0 = 2,
  BC_NE0 = 3,
  BC_LT0 = 4,
  BC_LE0 = 5,
  BC_GT0 = 6,
  BC_GE0 = 7,
  BC_CONV = 8,
  BC_SWAP = 9,
  BC_LOAD = 10,
  BC_STOR = 11,
  BC_CALL_E = 12,
  BC_RET_E = 13,
  BC_INT128 = 14, // Extended 128-bit / BITOP group (opcode 0x0E)
  BC_INVTLB = 15, // TLB invalidation group (opcode 0x0F)
  BC_LSHIFT1 = 16,
  BC_LSHIFT2 = 17,
  BC_LSHIFT4 = 18,
  BC_LSHIFT8 = 19,
  BC_RSHIFT1 = 20,
  BC_RSHIFT2 = 21,
  BC_RSHIFT4 = 22,
  BC_RSHIFT8 = 23,
  BC_CLZ1 = 24, // Count Leading Zeros (1-byte)
  BC_CLZ2 = 25,
  BC_CLZ4 = 26,
  BC_CLZ8 = 27,
  BC_CTZ1 = 28, // Count Trailing Zeros (1-byte)
  BC_CTZ2 = 29,
  BC_CTZ4 = 30,
  BC_CTZ8 = 31,
  BC_AND1 = 32,
  BC_AND2 = 33,
  BC_AND4 = 34,
  BC_AND8 = 35,
  BC_OR1 = 36,
  BC_OR2 = 37,
  BC_OR4 = 38,
  BC_OR8 = 39,
  BC_NOT1 = 40,
  BC_NOT2 = 41,
  BC_NOT4 = 42,
  BC_NOT8 = 43,
  BC_XOR1 = 44,
  BC_XOR2 = 45,
  BC_XOR4 = 46,
  BC_XOR8 = 47,
  BC_ADD1 = 48,
  BC_ADD2 = 49,
  BC_ADD4 = 50,
  BC_ADD8 = 51,
  BC_SUB1 = 52,
  BC_SUB2 = 53,
  BC_SUB4 = 54,
  BC_SUB8 = 55,
  BC_ADD_SP1 = 56,
  BC_ADD_SP2 = 57,
  BC_ADD_SP4 = 58,
  BC_ADD_SP8 = 59,
  BC_RST_SP1 = 60,
  BC_RST_SP2 = 61,
  BC_RST_SP4 = 62,
  BC_RST_SP8 = 63,
  BC_MUL1 = 64,
  BC_MUL1S = 65,
  BC_MUL2 = 66,
  BC_MUL2S = 67,
  BC_MUL4 = 68,
  BC_MUL4S = 69,
  BC_MUL8 = 70,
  BC_MUL8S = 71,
  BC_DIV1 = 72,
  BC_DIV1S = 73,
  BC_DIV2 = 74,
  BC_DIV2S = 75,
  BC_DIV4 = 76,
  BC_DIV4S = 77,
  BC_DIV8 = 78,
  BC_DIV8S = 79,
  BC_MOD1 = 80,
  BC_MOD1S = 81,
  BC_MOD2 = 82,
  BC_MOD2S = 83,
  BC_MOD4 = 84,
  BC_MOD4S = 85,
  BC_MOD8 = 86,
  BC_MOD8S = 87,
  BC_CMP1 = 88,
  BC_CMP1S = 89,
  BC_CMP2 = 90,
  BC_CMP2S = 91,
  BC_CMP4 = 92,
  BC_CMP4S = 93,
  BC_CMP8 = 94,
  BC_CMP8S = 95,
  BC_FADD_2 = 96,
  BC_FADD_4 = 97,
  BC_FADD_8 = 98,
  BC_FADD_16 = 99,
  BC_FSUB_2 = 100,
  BC_FSUB_4 = 101,
  BC_FSUB_8 = 102,
  BC_FSUB_16 = 103,
  BC_FMUL_2 = 104,
  BC_FMUL_4 = 105,
  BC_FMUL_8 = 106,
  BC_FMUL_16 = 107,
  BC_FDIV_2 = 108,
  BC_FDIV_4 = 109,
  BC_FDIV_8 = 110,
  BC_FDIV_16 = 111,
  BC_FMOD_2 = 112,
  BC_FMOD_4 = 113,
  BC_FMOD_8 = 114,
  BC_FMOD_16 = 115,
  BC_FCMP_2 = 116,
  BC_FCMP_4 = 117,
  BC_FCMP_8 = 118,
  BC_FCMP_16 = 119,
  BC_JMP = 120,
  BC_JMPIF = 121,
  BC_RJMP = 122,
  BC_RJMPIF = 123,
  BC_CALL = 124,
  BC_RCALL = 125,
  BC_RET = 126,
  BC_RET_N2 = 127
};
// ByteCodeReference
enum StackVM_BCR
{
  BCR_ABS_A4 = 0x00,
  BCR_ABS_A8 = 0x01,
  BCR_ABS_S4 = 0x02,
  BCR_ABS_S8 = 0x03,
  BCR_R_BP1 = 0x04,
  BCR_R_BP2 = 0x05,
  BCR_R_BP4 = 0x06,
  BCR_R_BP8 = 0x07,
  BCR_ABS_C = 0x08,
  BCR_REG_BP = 0x09,
  BCR_RES = 0x0A,
  BCR_EA_R_IP = 0x0B,
  BCR_TOS = 0x0C,
  BCR_SYSREG = 0x0D,
  // LOAD-only atomic BCR codes (each followed by 1 ordering byte: 0=RELAXED,1=ACQUIRE,2=RELEASE,3=SEQ_CST)
  BCR_ATOMIC_LOAD = 0x0E,
  BCR_ATOMIC_XCHG = 0x0F,
  BCR_ATOMIC_CAS = 0x10,
  BCR_ATOMIC_FADD = 0x11,
  BCR_ATOMIC_FSUB = 0x12,
  BCR_ATOMIC_FAND = 0x13,
  BCR_ATOMIC_FOR = 0x14,
  BCR_ATOMIC_FXOR = 0x15,
  // STOR-only BCR codes (same numeric space, different context)
  BCR_ATOMIC_STORE = 0x08, // STOR: atomic store (== BCR_ABS_C numeric; used on STOR path)
  BCR_FENCE_ALL = 0x0A,    // STOR: full memory fence (MFENCE)
  BCR_FENCE_LOAD = 0x0B,   // STOR: load fence (LFENCE)
  BCR_FENCE_STORE = 0x0C,  // STOR: store fence (SFENCE)
  BCR_SZ_16 = 0x4 << 5,
  BCR_SZ_2 = 0x1 << 5,
  BCR_SZ_4 = 0x2 << 5,
  BCR_SZ_8 = 0x3 << 5,
  BCR_TYP_MASK = 0x1F, // low 5 bits
  BCR_SZ_MASK = 0xE0,  // high 3 bits 0:1, 1:2, 2:4, 3:8
  BCR_R_BP_MASK = 0x1C,
  BCR_R_BP_VAL = 0x04
};
// ByteCodeSize
enum StackVM_BCS
{
  BCS_SZ1_A = 0x00,
  BCS_SZ2_A = 0x01,
  BCS_SZ4_A = 0x02,
  BCS_SZ8_A = 0x03,
  BCS_SZ16_A = 0x04,
  BCS_SZ32_A = 0x05,
  BCS_SZ64_A = 0x06,
  BCS_SZ128_A = 0x07,
  BCS_SZ1_B = 0x00,
  BCS_SZ2_B = 0x08,
  BCS_SZ4_B = 0x10,
  BCS_SZ8_B = 0x18,
  BCS_SZ16_B = 0x20,
  BCS_SZ32_B = 0x28,
  BCS_SZ64_B = 0x30,
  BCS_SZ128_B = 0x38,
  BCS_SZ_A_MASK = 0x07,
  BCS_SZ_B_MASK = 0x38
};
// ByteCode Conv
enum StackVM_BCC
{
  BCC_I_MASK = 0x0F,
  BCC_O_MASK = 0xF0,
  BCC_UI_1_I = 0x00,
  BCC_SI_1_I = 0x01,
  BCC_UI_2_I = 0x02,
  BCC_SI_2_I = 0x03,
  BCC_UI_4_I = 0x04,
  BCC_SI_4_I = 0x05,
  BCC_UI_8_I = 0x06,
  BCC_SI_8_I = 0x07,
  BCC_F_2_I = 0x08,
  BCC_F_4_I = 0x09,
  BCC_F_8_I = 0x0A,
  BCC_F_16_I = 0x0B,
  BCC_UI_1_O = 0x00,
  BCC_SI_1_O = 0x10,
  BCC_UI_2_O = 0x20,
  BCC_SI_2_O = 0x30,
  BCC_UI_4_O = 0x40,
  BCC_SI_4_O = 0x50,
  BCC_UI_8_O = 0x60,
  BCC_SI_8_O = 0x70,
  BCC_F_2_O = 0x80,
  BCC_F_4_O = 0x90,
  BCC_F_8_O = 0xA0,
  BCC_F_16_O = 0xB0
};
// ByteCode Return Extension
enum StackVM_BCRE
{
  BCRE_SYS = 0x1 << 7,
  BCRE_IS_INT = 1 << 6, // IRET when IS_SYS=1
  BCRE_RST_SP_SZ1 = 0x0 << 5,
  BCRE_RST_SP_SZ2 = 0x1 << 5,
  BCRE_RST_SP_SZ4 = 0x2 << 5,
  BCRE_RST_SP_SZ8 = 0x3 << 5,
  BCRE_RST_SP_SZ_MASK = 0x3 << 5,
  BCRE_RES_SZ1 = 0x0 << 3,
  BCRE_RES_SZ2 = 0x1 << 3,
  BCRE_RES_SZ4 = 0x2 << 3,
  BCRE_RES_SZ8 = 0x3 << 3,
  BCRE_RES_SZ_MASK = 0x3 << 3
};
// ByteCode Call Extension
enum StackVM_BCCE
{
  BCCE_SYSCALL = 1 << 7,
  BCCE_IS_REL = 1 << 6,
  BCCE_IS_INT = 1 << 5, // software interrupt when IS_SYS=0: reads inline int_n byte
  BCCE_S_SYSN_SZ1 = 0 << 5,
  BCCE_S_SYSN_SZ2 = 1 << 5,
  BCCE_S_SYSN_SZ4 = 2 << 5,
  BCCE_S_SYSN_SZ8 = 3 << 5,
  BCCE_S_ARG_SZ1 = 0 << 3,
  BCCE_S_ARG_SZ2 = 1 << 3,
  BCCE_S_ARG_SZ4 = 2 << 3,
  BCCE_S_ARG_SZ8 = 3 << 3
};

// StackVM SysReg(Base)
enum StackVM_SVSR
{
  SVSR_FLAGS = 0x00,
  SVSR_ISR = 0x01,
  SVSR_SDP = 0x02,
  SVSR_SYS_FN = 0x03,
  SVSRB_SP = 0x04,
  SVSR_KERNEL_SP = 0x04,
  SVSR_USER_SP = 0x05,
  SVSRB_BP = 0x06,
  SVSR_KERNEL_BP = 0x06,
  SVSR_USER_BP = 0x07,
  SVSRB_TLPTR = 0x08,
  SVSR_KERNEL_TLPTR = 0x08,
  SVSR_USER_TLPTR = 0x09,
  SVSR_CORE_ID = 0x0A,        // R/kernel: hardware core identifier
  SVSR_IPI = 0x0B,            // W/kernel: inter-processor interrupt
  SVSR_CYCLE_COUNT = 0x0C,    // R/kernel: hardware cycle counter
  SVSR_PAGE_FAULT_ADDR = 0x0D // R/kernel: virtual addr of last page fault
};

// INT128 sub-operation codes (byte following BC_INT128 opcode)
enum StackVM_BC128
{
  BC128_ADD128U = 0x00,
  BC128_ADD128S = 0x01,
  BC128_SUB128U = 0x02,
  BC128_SUB128S = 0x03,
  BC128_MUL128U = 0x04,
  BC128_MUL128S = 0x05,
  BC128_DIV128U = 0x06,
  BC128_DIV128S = 0x07,
  BC128_MOD128U = 0x08,
  BC128_MOD128S = 0x09,
  BC128_AND128 = 0x0A,
  BC128_OR128 = 0x0B,
  BC128_XOR128 = 0x0C,
  BC128_NOT128 = 0x0D,
  BC128_LSHIFT128 = 0x0E,
  BC128_RSHIFT128U = 0x0F,
  BC128_RSHIFT128S = 0x10,
  BC128_CMP128U = 0x11,
  BC128_CMP128S = 0x12,
  BC128_POPCNT1 = 0x13,
  BC128_POPCNT2 = 0x14,
  BC128_POPCNT4 = 0x15,
  BC128_POPCNT8 = 0x16,
  BC128_BSWAP2 = 0x17,
  BC128_BSWAP4 = 0x18,
  BC128_BSWAP8 = 0x19
};

enum StackVM_INT
{
  INT_DIV_BY_ZERO = 0x00,
  INT_DEBUG = 0x01,
  INT_NMI = 0x02,
  INT_BREAKPOINT = 0x03,
  INT_OVERFLOW = 0x04,
  INT_BOUNDS_CHECK = 0x05,
  INT_INVAL_OPCODE = 0x06,
  INT_FPU_FAULT = 0x07,
  INT_DOUBLE_FAULT = 0x08,
  INT_PROTECT_FAULT = 0x0D,
  INT_PAGE_FAULT = 0x0E,
  INT_INVAL_SYSCALL = 0x0F,
  INT_HW_IO = 0x10,
  INT_TIMER = 0x11,
  INT_TLB_SHOOTDOWN = 0x1F
};

enum StackVM_MRQ
{
  MRQ_DONT_CHECK = 0,
  MRQ_READ = 1,
  MRQ_WRITE = 2,
  MRQ_EXEC = 4
};

class StackVM;

class BaseStackVM_Env
{
public:
  // when an interrupt is loaded into the queue the environment will set
  //   int_ready to true on all stackvm instances registered with it
  // load_interrupt loads the interrupt in the memory that was installed on
  //   the stackvm instance and returns true if there actually was an
  //   interrupt available for the processor
  virtual bool load_interrupt(StackVM *vm_inst) = 0;

  // responsible for installing the memory on stackvm
  virtual void initialize_on_vm(StackVM *vm_inst) = 0;
  virtual void prepare_for_boot(StackVM *vm_inst) = 0;
  virtual void handle_virtual_interrupt(StackVM *vm_inst, uint8_t n) = 0;
  virtual void handle_virtual_syscall(StackVM *vm_inst, uint64_t sysn) = 0;
};

class MemoryView
{
private:
  size_t size_first, size_next;
  uint8_t *first, *next;

public:
  MemoryView()
      : first(nullptr), size_first(0), next(nullptr), size_next(0)
  {
  }
  MemoryView(uint8_t *first, size_t size_first)
      : first(first), size_first(size_first), next(nullptr), size_next(0)
  {
  }
  MemoryView(uint8_t *first, size_t size_first, uint8_t *next, size_t size_next)
      : first(first), size_first(size_first), next(next), size_next(size_next)
  {
  }
  inline uint8_t &operator[](size_t idx)
  {
    if (idx < size_first)
    {
      return first[idx];
    }
    idx -= size_first;
    if (idx < size_next)
    {
      return next[idx];
    }
    throw std::range_error("MemoryView index out of bounds");
  }
  inline size_t length() const
  {
    return size_first + size_next;
  }
  inline void writefrom(uint8_t *buf)
  {
    if (size_first)
    {
      memcpy(first, buf, size_first);
      buf += size_first;
    }
    if (size_next)
    {
      memcpy(next, buf, size_next);
    }
  }
  inline void readinto(uint8_t *buf)
  {
    if (size_first)
    {
      memcpy(buf, first, size_first);
      buf += size_first;
    }
    if (size_next)
    {
      memcpy(buf, next, size_next);
    }
  }
  inline void readatinto(size_t off, uint8_t *buf, size_t bufsize)
  {
    if (off + bufsize < size_first)
    {
      memcpy(buf, first + off, bufsize);
    }
    else if (off >= size_first)
    {
      memcpy(buf, next + (off - size_first), bufsize);
    }
    else if (off < size_first)
    {
      memcpy(buf, first + off, size_first - off);
      buf += size_first - off;
      bufsize -= size_first - off;
      memcpy(buf, next, bufsize);
    }
  }
  template <typename T>
  inline void write(T data, size_t idx = 0)
  {
    if (idx + sizeof(T) >= (size_first + size_next))
    {
      throw std::range_error("MemoryView index out of bounds");
    }
    if (idx < size_first && idx + sizeof(T) < size_first)
    {
      *(T *)(first + idx) = data;
    }
    else if (idx >= size_first)
    {
      idx -= size_first;
      *(T *)(next + idx) = data;
    }
    else
    {
      size_t off = size_first - idx;
      for (size_t i = idx; i < size_first; ++i)
      {
        first[i] = ((uint8_t *)&data)[i - idx];
      }
      idx -= size_first;
      for (size_t i = idx; i < sizeof(T) - off; ++i)
      {
        next[i] = ((uint8_t *)&data)[i + off];
      }
    }
  }
  template <typename T>
  inline T read(size_t idx = 0)
  {
    if (idx + sizeof(T) >= (size_first + size_next))
    {
      throw std::range_error("MemoryView index out of bounds");
    }
    if (idx < size_first && idx + sizeof(T) < size_first)
    {
      return *(T *)(first + idx);
    }
    else if (idx >= size_first)
    {
      idx -= size_first;
      return *(T *)(next + idx);
    }
    else
    {
      T data;
      size_t off = size_first - idx;
      for (size_t i = idx; i < size_first; ++i)
      {
        ((uint8_t *)&data)[i - idx] = first[i];
      }
      idx -= size_first;
      for (size_t i = idx; i < sizeof(T) - off; ++i)
      {
        ((uint8_t *)&data)[i + off] = next[i];
      }
      return data;
    }
  }
};

class StackVM_TrapException
{
public:
  uint8_t int_n;
  uint64_t arg0, arg1, arg2, arg3;
  struct SimpleStruct
  {
    uint64_t arg0, arg1, arg2, arg3;
  };
  StackVM_TrapException(uint8_t int_n, uint64_t arg0 = 0, uint64_t arg1 = 0, uint64_t arg2 = 0, uint64_t arg3 = 0)
      : int_n(int_n), arg0(arg0), arg1(arg1), arg2(arg2), arg3(arg3) {}
};

template <typename T>
inline int8_t stack_vm_cmp(T a, T b)
{
  return a < b ? -1 : (a == b ? 0 : 1);
}

const uint64_t pte_lmasks[] = {
    0,
    (1 << 12) - 1,
    (1 << 13) - 1,
    (1 << 12) - 1,
    (1 << 14) - 1,
    (1 << 15) - 1};

const uint64_t pte_hmasks[] = {
    0,
    ~uint64_t(pte_lmasks[1]),
    ~uint64_t(pte_lmasks[2]),
    ~uint32_t(pte_lmasks[3]),
    ~uint64_t(pte_lmasks[4]),
    ~uint64_t(pte_lmasks[5])};
enum VirtMemMode
{
  VM_DISABLED = 0,
  VM_4_LVL_9_BIT,
  VM_4_LVL_10_BIT,
  VM_2_LVL_10_BIT_LEGACY,
  VM_4_LVL_11_BIT,
  VM_4_LVL_12_BIT
};

enum VirtMemErrors : uint8_t
{
  VME_NONE = 0,
  VME_PAGE_NOT_PRESENT = 1,
  VME_PAGE_BAD_PERMS = 2,
  VME_PHYS_MEMORY_ACCESS_DENIED = 3,
};

enum VirtMemErrorsPermissionViolationReason : uint64_t
{
  VME_PVR_NO_EXEC = 1,
  VME_PVR_NO_WRITE = 2,
  VME_PVR_NO_READ = 3,
};

enum PtePermissions : uint64_t
{
  PTE_VALID_BIT = 0x001,
  PTE_WRITE_BIT = 0x002,
  PTE_EXEC_BIT = 0x004,
  PTE_DIRTY_BIT = 0x008,
  PTE_HUGE_BIT = 0x010
};

enum SvsrFlagsMasks
{
  SVSR_FLAGS_PRI_SHFT = 0,
  SVSR_FLAGS_PRIV_SHFT = 8,
  SVSR_FLAGS_VADDR_MSB_EQ_PRIV_SHFT = 9,
  SVSR_FLAGS_VIRT_MEM_MD_SHFT = 10,
  SVSR_FLAGS_PRI_MASK = 0b00000011111111,
  SVSR_FLAGS_PRIV_MASK = 0b00000100000000,
  SVSR_FLAGS_VADDR_MSB_EQ_PRIV_MASK = 0b00001000000000,
  SVSR_FLAGS_VIRT_MEM_MD_MASK = 0b11110000000000
};

enum PrivLvl
{
  PRIV_KERNEL = 0,
  PRIV_USER = 1
};

constexpr bool dbg_walk_page = false;

constexpr bool is_host_little_endian = false;
constexpr bool watch_memory = false;

const uint8_t SVSR_REGISTER_PERMS[] = {
    // bits: [write user][write kernel][read user][read kernel]
    0b1111, // 0x00 FLAGS
    0b0101, // 0x01 ISR
    0b0001, // 0x02 SDP
    0b0101, // 0x03 KERNEL_SYS_FN
    0b0101, // 0x04 KERNEL_SP
    0b1111, // 0x05 USER_SP
    0b0101, // 0x06 KERNEL_BP
    0b1111, // 0x07 USER_BP
    0b0101, // 0x08 KERNEL_TLPTR
    0b0101, // 0x09 USER_TLPTR
    0b0001, // 0x0A CORE_ID (R/kernel only)
    0b0100, // 0x0B IPI (W/kernel only)
    0b0001, // 0x0C CYCLE_COUNT (R/kernel only)
    0b0001, // 0x0D PAGE_FAULT_ADDR (R/kernel only)
};

const uint64_t SVSR_FLAGS_ILLEGAL_BITS_WRITE_MASK[] = {
    0b1111'1111'1111'1111'1111'1111'1111'1111'1111'1111'1111'1111'1000'0000'0000'0000, // KERNEL
    0b1111'1111'1111'1111'1111'1111'1111'1111'1111'1111'1111'1111'1111'1111'1111'1111  // USER
};

class StackVM
{
protected:
  uint64_t sp, bp, ip;
  uint8_t *memory;
  size_t memsize;
  uint8_t running;
  uint8_t priority;
  uint8_t priv_lvl;
  bool vaddr_msb_eq_priv;
  uint8_t virt_mem_mode;
  uint64_t virt_error_data[4]; // virt_error_data[0] & 0xFF is the virt_error_code
  uint64_t sys_regs[14];
  BaseStackVM_Env *env;
  uint64_t ax;
  typedef void (*VirtSyscall)(uint64_t syscall_n, StackVM_TrapException::SimpleStruct *err);
  VirtSyscall virt_syscall;

public:
  volatile bool int_ready;

  StackVM(VirtSyscall virt_syscall)
      : memory(nullptr),
        sp(0),
        bp(0),
        ip(0),
        running(1),
        priority(255),
        priv_lvl(1),
        virt_syscall(virt_syscall),
        virt_mem_mode(0)
  {
    for (uint64_t &reg : sys_regs)
    {
      reg = 0;
    }
    calc_flags();
  }
  void set_memory(uint8_t *mem, size_t size)
  {
    memory = mem;
    sp = size;
    bp = size;
  }
  void init_environment(BaseStackVM_Env *env)
  {
    this->env = env;
    env->initialize_on_vm(this);
  }

protected:
  inline static uint64_t build_virt_error0(uint8_t virt_error_code, uint8_t pte_lvl, uint64_t reason_extra)
  {
    return virt_error_code | ((uint64_t)pte_lvl << 8) | (reason_extra << 11);
  }
  void check_perm_set_or_clr_error(uint64_t pte_top, uint64_t pte_index, uint64_t pte_ptr, uint64_t pte, uint64_t virt_addr, uint8_t mrq_perms, uint8_t pte_lvl)
  {
    if (mrq_perms != MRQ_DONT_CHECK && mrq_perms != MRQ_READ)
    {
      if constexpr (dbg_walk_page)
      {
        printf("dbg_walk_page: checking permissions\n");
      }
      if (mrq_perms == MRQ_WRITE)
      {
        if ((pte & PTE_WRITE_BIT) == 0)
        {
          if constexpr (dbg_walk_page)
          {
            printf("dbg_walk_page: bad permissions\n");
          }
          virt_error_data[0] = build_virt_error0(VME_PAGE_BAD_PERMS, pte_lvl, mrq_perms | (VME_PVR_NO_WRITE << 3));
          virt_error_data[1] = virt_addr;
          virt_error_data[2] = pte_top;
          virt_error_data[3] = pte_index;
          return;
        }
        else if ((pte & PTE_DIRTY_BIT) == 0)
        {
          pte |= PTE_DIRTY_BIT;
          if constexpr (dbg_walk_page)
          {
            printf("dbg_walk_page: write back page table DIRTY\n");
          }
          *(uint64_t *)(memory + pte_ptr) = pte;
        }
      }
      else if (mrq_perms == MRQ_EXEC)
      {
        if ((pte & PTE_EXEC_BIT) == 0)
        {
          virt_error_data[0] = build_virt_error0(VME_PAGE_BAD_PERMS, pte_lvl, mrq_perms | (VME_PVR_NO_EXEC << 3));
          virt_error_data[1] = virt_addr;
          virt_error_data[2] = pte_top;
          virt_error_data[3] = pte_index;
          return;
        }
      }
    }
    virt_error_data[0] = 0;
    virt_error_data[1] = 0;
    virt_error_data[2] = 0;
    virt_error_data[3] = 0;
  }
  template <uint64_t n_bits>
  inline uint64_t vm_4_lvl_n_bit_walk_page(uint64_t virt_addr, uint64_t tlpte, uint8_t mrq_perms)
  {
    enum Masks : uint64_t
    {
      NUM_BITS_IDX = n_bits,
      NUM_BITS_ADDR = 5 * NUM_BITS_IDX + 3,
      PTE_IDX_MASK = (1 << NUM_BITS_IDX) - 1,
      PTE1_IDX_SHIFT = NUM_BITS_ADDR - NUM_BITS_IDX,
      PTE2_IDX_SHIFT = NUM_BITS_ADDR - 2 * NUM_BITS_IDX,
      PTE3_IDX_SHIFT = NUM_BITS_ADDR - 3 * NUM_BITS_IDX,
      PTE4_IDX_SHIFT = NUM_BITS_ADDR - 4 * NUM_BITS_IDX,
      PTE1_HMASK = ((~(uint64_t)0) >> PTE1_IDX_SHIFT) << PTE1_IDX_SHIFT, // 0xffffff8000000000 for 4 lvl 9 bit
      PTE1_LMASK = (~(uint64_t)0) ^ PTE1_HMASK,                          // 0x7fffffffff for 4 lvl 9 bit
      PTE2_HMASK = ((~(uint64_t)0) >> PTE2_IDX_SHIFT) << PTE2_IDX_SHIFT, // 0xffffffffc0000000 for 4 lvl 9 bit
      PTE2_LMASK = (~(uint64_t)0) ^ PTE2_HMASK,                          // 0x3fffffff,
      PTE3_HMASK = ((~(uint64_t)0) >> PTE3_IDX_SHIFT) << PTE3_IDX_SHIFT, // 0xffffffffffe00000 for 4 lvl 9 bit
      PTE3_LMASK = (~(uint64_t)0) ^ PTE3_HMASK,                          // 0x1fffff for 4 lvl 9 bit
      PTE4_HMASK = ((~(uint64_t)0) >> PTE4_IDX_SHIFT) << PTE4_IDX_SHIFT, // 0xfffffffffffff000 for 4 lvl 9 bit
      PTE4_LMASK = (~(uint64_t)0) ^ PTE4_HMASK,                          // 0xfff for 4 lvl 9 bit
    };
    if constexpr (dbg_walk_page)
    {
      printf("dbg_walk_page: resolving from tlpte\n");
    }
    if ((tlpte & PTE_VALID_BIT) == 0)
    {
      virt_error_data[0] = build_virt_error0(VME_PAGE_NOT_PRESENT, 0, mrq_perms);
      virt_error_data[1] = virt_addr;
      virt_error_data[2] = 0;
      virt_error_data[3] = tlpte;
      return 0;
    }
    size_t pte1_index = ((virt_addr >> PTE1_IDX_SHIFT) & PTE_IDX_MASK) * 8;
    uint64_t pte1_ptr = (tlpte & PTE4_HMASK) | pte1_index;
    if constexpr (dbg_walk_page)
    {
      printf("dbg_walk_page: resolved pte1_ptr=0x%016X from tlpte\n", pte1_ptr);
    }
    if (pte1_ptr + 8 > memsize)
    {
      virt_error_data[0] = build_virt_error0(VME_PHYS_MEMORY_ACCESS_DENIED, 1, mrq_perms);
      virt_error_data[1] = virt_addr;
      virt_error_data[2] = tlpte;
      virt_error_data[3] = pte1_ptr;
      return 0;
    }
    uint64_t pte1 = *(uint64_t *)(memory + pte1_ptr);
    if ((pte1 & PTE_VALID_BIT) == 0)
    {
      virt_error_data[0] = build_virt_error0(VME_PAGE_NOT_PRESENT, 1, mrq_perms);
      virt_error_data[1] = virt_addr;
      virt_error_data[2] = tlpte;
      virt_error_data[3] = pte1_index;
      return 0;
    }
    else if (pte1 & PTE_HUGE_BIT)
    {
      check_perm_set_or_clr_error(tlpte, pte1_index, pte1_ptr, pte1, virt_addr, mrq_perms, 1);
      return (pte1 & PTE1_HMASK) | (virt_addr & PTE1_LMASK);
    }
    uint64_t pte2_index = ((virt_addr >> PTE2_IDX_SHIFT) & PTE_IDX_MASK) * 8;
    uint64_t pte2_ptr = (pte1 & PTE4_HMASK) | pte2_index;
    if constexpr (dbg_walk_page)
    {
      printf("dbg_walk_page: resolved pte2_ptr=0x%016X from pte1\n", pte2_ptr);
    }
    if (pte2_ptr + 8 > memsize)
    {
      virt_error_data[0] = build_virt_error0(VME_PHYS_MEMORY_ACCESS_DENIED, 2, mrq_perms);
      virt_error_data[1] = virt_addr;
      virt_error_data[2] = pte1;
      virt_error_data[3] = pte2_ptr;
      return 0;
    }
    uint64_t pte2 = *(uint64_t *)(memory + pte2_ptr);
    if constexpr (dbg_walk_page)
    {
      printf("dbg_walk_page: resolved pte2=0x%016X\n", pte2);
    }
    if ((pte2 & PTE_VALID_BIT) == 0)
    {
      virt_error_data[0] = build_virt_error0(VME_PAGE_NOT_PRESENT, 2, mrq_perms);
      virt_error_data[1] = virt_addr;
      virt_error_data[2] = pte1;
      virt_error_data[3] = pte2_index;
      return 0;
    }
    else if (pte2 & PTE_HUGE_BIT)
    {
      check_perm_set_or_clr_error(pte1, pte2_index, pte2_ptr, pte2, virt_addr, mrq_perms, 2);
      return (pte2 & PTE2_HMASK) | (virt_addr & PTE2_LMASK);
    }
    uint64_t pte3_index = ((virt_addr >> PTE3_IDX_SHIFT) & PTE_IDX_MASK) * 8;
    uint64_t pte3_ptr = (pte2 & PTE4_HMASK) | pte3_index;
    if constexpr (dbg_walk_page)
    {
      printf("dbg_walk_page: resolved pte3_ptr=0x%016X from pte2\n", pte3_ptr);
    }
    if (pte3_ptr + 8 > memsize)
    {
      virt_error_data[0] = build_virt_error0(VME_PHYS_MEMORY_ACCESS_DENIED, 3, mrq_perms);
      virt_error_data[1] = virt_addr;
      virt_error_data[2] = pte2;
      virt_error_data[3] = pte3_ptr;
      return 0;
    }
    uint64_t pte3 = *(uint64_t *)(memory + pte3_ptr);
    if constexpr (dbg_walk_page)
    {
      printf("dbg_walk_page: resolved pte3=0x%016X\n", pte3);
    }
    if ((pte3 & PTE_VALID_BIT) == 0)
    {
      virt_error_data[0] = build_virt_error0(VME_PAGE_NOT_PRESENT, 3, mrq_perms);
      virt_error_data[1] = virt_addr;
      virt_error_data[2] = pte2;
      virt_error_data[3] = pte3_index;
      return 0;
    }
    else if (pte3 & PTE_HUGE_BIT)
    {
      check_perm_set_or_clr_error(pte2, pte3_index, pte3_ptr, pte3, virt_addr, mrq_perms, 3);
      return (pte3 & PTE3_HMASK) | (virt_addr & PTE3_LMASK);
    }
    uint64_t pte4_index = ((virt_addr >> PTE4_IDX_SHIFT) & PTE_IDX_MASK) * 8;
    uint64_t pte4_ptr = (pte3 & PTE4_HMASK) | pte4_index;
    if constexpr (dbg_walk_page)
    {
      printf("dbg_walk_page: resolved pte4_ptr=0x%016X from pte3\n", pte4_ptr);
    }
    if (pte4_ptr + 8 > memsize)
    {
      virt_error_data[0] = build_virt_error0(VME_PHYS_MEMORY_ACCESS_DENIED, 4, mrq_perms);
      virt_error_data[1] = virt_addr;
      virt_error_data[2] = pte3;
      virt_error_data[3] = pte4_ptr;
      return 0;
    }
    uint64_t pte4 = *(uint64_t *)(memory + pte4_ptr);
    if constexpr (dbg_walk_page)
    {
      printf("dbg_walk_page: resolved pte4=0x%016X\n", pte4);
    }
    if ((pte4 & PTE_VALID_BIT) == 0)
    {
      virt_error_data[0] = build_virt_error0(VME_PAGE_NOT_PRESENT, 4, mrq_perms);
      virt_error_data[1] = virt_addr;
      virt_error_data[2] = pte3;
      virt_error_data[3] = pte4_index;
      return 0;
    }
    check_perm_set_or_clr_error(pte3, pte4_index, pte4_ptr, pte4, virt_addr, mrq_perms, 4);
    return (pte4 & PTE4_HMASK) | (virt_addr & PTE4_LMASK);
  }
  inline uint64_t walk_page(uint64_t virt_addr, uint64_t tlpte, uint8_t mrq_perms)
  {
    // Later_TODO: use __m256i _mm256_cmpeq_epi64 (__m256i a, __m256i b) or some other
    //   similar vector intrinsic to emulate TLB for fast vaddr translation
    if (virt_mem_mode == VM_DISABLED)
    {
      return virt_addr;
    }
    if (virt_mem_mode == VM_4_LVL_9_BIT)
    {
      return vm_4_lvl_n_bit_walk_page<9>(virt_addr, tlpte, mrq_perms);
    }
    else if (virt_mem_mode == VM_4_LVL_10_BIT)
    {
      return vm_4_lvl_n_bit_walk_page<10>(virt_addr, tlpte, mrq_perms);
    }
    else if (virt_mem_mode == VM_4_LVL_11_BIT)
    {
      return vm_4_lvl_n_bit_walk_page<11>(virt_addr, tlpte, mrq_perms);
    }
    else if (virt_mem_mode == VM_4_LVL_12_BIT)
    {
      return vm_4_lvl_n_bit_walk_page<12>(virt_addr, tlpte, mrq_perms);
    }
    else
    {
      throw std::runtime_error("Unsupported virtual memory mode");
    }
  }
  inline uint64_t walk_page(uint64_t virt_addr, uint8_t mrq_perms)
  {
    bool msb = virt_addr >> 63;
    uint64_t phys_addr = 0;
    if (vaddr_msb_eq_priv)
    {
      uint64_t page_size_m1 = 0x7FFF'FFFF'FFFF'FFFF;
      if (priv_lvl == PRIV_USER)
      {
        if (msb)
        {
          phys_addr = walk_page(virt_addr, sys_regs[SVSR_USER_TLPTR], mrq_perms);
        }
        else
        {
          virt_error_data[0] = build_virt_error0(VME_PAGE_BAD_PERMS, 0, mrq_perms | (VME_PVR_NO_READ << 3));
          virt_error_data[1] = virt_addr;
          virt_error_data[2] = 0;
          virt_error_data[3] = 0;
        }
      }
      else // priv_lvl == PRIV_KERNEL
      {
        if (msb)
        {
          phys_addr = walk_page(virt_addr, sys_regs[SVSR_USER_TLPTR], mrq_perms);
        }
        else
        {
          phys_addr = walk_page(virt_addr, sys_regs[SVSR_KERNEL_TLPTR], mrq_perms);
        }
      }
    }
    else
    {
      uint64_t page_size_m1 = 0xFFFF'FFFF'FFFF'FFFF;
      if (priv_lvl == PRIV_USER)
      {
        phys_addr = walk_page(virt_addr, sys_regs[SVSR_USER_TLPTR], mrq_perms);
      }
      else // priv_lvl == PRIV_KERNEL
      {
        phys_addr = walk_page(virt_addr, sys_regs[SVSR_KERNEL_TLPTR], mrq_perms);
        if (virt_error_data[0])
        {
          phys_addr = walk_page(virt_addr, sys_regs[SVSR_USER_TLPTR], mrq_perms);
        }
      }
    }
    if (virt_error_data[0])
    {
      throw StackVM_TrapException(
          INT_PAGE_FAULT,
          virt_error_data[0],
          virt_error_data[1],
          virt_error_data[2],
          virt_error_data[3]);
    }
    return phys_addr;
  }
  MemoryView get_memory_view(uint64_t addr, size_t size, uint8_t mrq_perms)
  {
    // the contract of this function/method is undefined for when size == 0
    uint64_t phys_addr = walk_page(addr, mrq_perms);
    if (virt_mem_mode)
    {
      const uint64_t page_mask = pte_hmasks[virt_mem_mode];
      const uint64_t index_mask = pte_lmasks[virt_mem_mode];
      if ((addr & page_mask) != ((addr + size - 1) & page_mask))
      {
        const uint64_t index_mask_p1 = index_mask + 1;
        const uint64_t phys_addr1 = walk_page(addr + index_mask_p1, mrq_perms);
        if ((phys_addr | index_mask) >= memsize)
        {
          throw StackVM_TrapException(
              INT_PAGE_FAULT,
              build_virt_error0(VME_PHYS_MEMORY_ACCESS_DENIED, 4, mrq_perms),
              addr,
              0,
              phys_addr);
        }
        uint64_t size0 = index_mask_p1 - (phys_addr1 & index_mask);
        uint64_t size1 = (phys_addr1 + size) & index_mask;
        if ((phys_addr1 + size1) > memsize)
        {
          throw StackVM_TrapException(
              INT_PAGE_FAULT,
              build_virt_error0(VME_PHYS_MEMORY_ACCESS_DENIED, 4, mrq_perms),
              addr,
              0,
              phys_addr1);
        }
        return MemoryView(memory + phys_addr, size0, memory + phys_addr1, size1);
      }
      else
      {
        if (phys_addr + size > memsize)
        {
          throw StackVM_TrapException(
              INT_PAGE_FAULT,
              build_virt_error0(VME_PHYS_MEMORY_ACCESS_DENIED, 4, mrq_perms),
              addr,
              0,
              phys_addr);
        }
      }
    }
    else
    {
      if (vaddr_msb_eq_priv && priv_lvl == PRIV_USER)
      {
        throw StackVM_TrapException(
            INT_PAGE_FAULT,
            build_virt_error0(VME_PHYS_MEMORY_ACCESS_DENIED, 4, mrq_perms),
            addr,
            0,
            addr);
      }
      if (phys_addr + size > memsize)
      {
        throw StackVM_TrapException(
            INT_PAGE_FAULT,
            build_virt_error0(VME_PHYS_MEMORY_ACCESS_DENIED, 4, mrq_perms),
            addr,
            0,
            phys_addr);
      }
    }
    return MemoryView(memory + phys_addr, size);
  }
  uint8_t get_uint8(uint64_t addr)
  {
    const uint8_t mrq_perms = MRQ_READ;
    if (virt_mem_mode == 0 && vaddr_msb_eq_priv && priv_lvl == PRIV_USER)
    {
      throw StackVM_TrapException(
          INT_PAGE_FAULT,
          build_virt_error0(VME_PHYS_MEMORY_ACCESS_DENIED, 4, mrq_perms),
          addr,
          0,
          addr);
    }
    uint64_t phys_addr = walk_page(addr, mrq_perms);
    if (phys_addr >= memsize)
    {
      throw StackVM_TrapException(
          INT_PAGE_FAULT,
          build_virt_error0(VME_PHYS_MEMORY_ACCESS_DENIED, 4, mrq_perms),
          addr,
          0,
          phys_addr);
    }
    return *(memory + phys_addr);
  }
  void set(uint64_t addr, uint8_t val)
  {
    const uint8_t mrq_perms = MRQ_READ;
    if (virt_mem_mode == 0 && vaddr_msb_eq_priv && priv_lvl == PRIV_USER)
    {
      throw StackVM_TrapException(
          INT_PAGE_FAULT,
          build_virt_error0(VME_PHYS_MEMORY_ACCESS_DENIED, 4, mrq_perms),
          addr,
          0,
          addr);
    }
    uint64_t phys_addr = walk_page(addr, mrq_perms);
    if (phys_addr >= memsize)
    {
      throw StackVM_TrapException(
          INT_PAGE_FAULT,
          build_virt_error0(VME_PHYS_MEMORY_ACCESS_DENIED, 4, mrq_perms),
          addr,
          0,
          phys_addr);
    }
    *(memory + phys_addr) = val;
  }
  int8_t get_int8(uint64_t addr)
  {
    const uint8_t mrq_perms = MRQ_READ;
    if (virt_mem_mode == 0 && vaddr_msb_eq_priv && priv_lvl == PRIV_USER)
    {
      throw StackVM_TrapException(
          INT_PAGE_FAULT,
          build_virt_error0(VME_PHYS_MEMORY_ACCESS_DENIED, 4, mrq_perms),
          addr,
          0,
          addr);
    }
    uint64_t phys_addr = walk_page(addr, mrq_perms);
    if (phys_addr >= memsize)
    {
      throw StackVM_TrapException(
          INT_PAGE_FAULT,
          build_virt_error0(VME_PHYS_MEMORY_ACCESS_DENIED, 4, mrq_perms),
          addr,
          0,
          phys_addr);
    }
    return *(int8_t *)(memory + phys_addr);
  }
  void set(uint64_t addr, int8_t val)
  {
    const uint8_t mrq_perms = MRQ_READ;
    if (virt_mem_mode == 0 && vaddr_msb_eq_priv && priv_lvl == PRIV_USER)
    {
      throw StackVM_TrapException(
          INT_PAGE_FAULT,
          build_virt_error0(VME_PHYS_MEMORY_ACCESS_DENIED, 4, mrq_perms),
          addr,
          0,
          addr);
    }
    uint64_t phys_addr = walk_page(addr, mrq_perms);
    if (phys_addr >= memsize)
    {
      throw StackVM_TrapException(
          INT_PAGE_FAULT,
          build_virt_error0(VME_PHYS_MEMORY_ACCESS_DENIED, 4, mrq_perms),
          addr,
          0,
          phys_addr);
    }
    *(int8_t *)(memory + phys_addr) = val;
  }
  uint8_t get_instr_uint8()
  {
    const uint8_t mrq_perms = MRQ_EXEC;
    if (virt_mem_mode == 0 && vaddr_msb_eq_priv && priv_lvl == PRIV_USER)
    {
      throw StackVM_TrapException(
          INT_PAGE_FAULT,
          build_virt_error0(VME_PHYS_MEMORY_ACCESS_DENIED, 4, mrq_perms),
          ip,
          0,
          ip);
    }
    uint64_t phys_addr = walk_page(ip, mrq_perms);
    if (phys_addr >= memsize)
    {
      throw StackVM_TrapException(
          INT_PAGE_FAULT,
          build_virt_error0(VME_PHYS_MEMORY_ACCESS_DENIED, 4, mrq_perms),
          ip,
          0,
          phys_addr);
    }
    ++ip;
    return *(memory + phys_addr);
  }
  int8_t get_instr_int8()
  {
    const uint8_t mrq_perms = MRQ_EXEC;
    if (virt_mem_mode == 0 && vaddr_msb_eq_priv && priv_lvl == PRIV_USER)
    {
      throw StackVM_TrapException(
          INT_PAGE_FAULT,
          build_virt_error0(VME_PHYS_MEMORY_ACCESS_DENIED, 4, mrq_perms),
          ip,
          0,
          ip);
    }
    uint64_t phys_addr = walk_page(ip, mrq_perms);
    if (phys_addr >= memsize)
    {
      throw StackVM_TrapException(
          INT_PAGE_FAULT,
          build_virt_error0(VME_PHYS_MEMORY_ACCESS_DENIED, 4, mrq_perms),
          ip,
          0,
          phys_addr);
    }
    ++ip;
    return *(int8_t *)(memory + phys_addr);
  }
  uint16_t get_uint16(uint64_t addr)
  {
    return get_memory_view(addr, sizeof(uint16_t), MRQ_READ).read<uint16_t>();
  }
  void set(uint64_t addr, uint16_t val)
  {
    get_memory_view(addr, sizeof(val), MRQ_WRITE).write(val);
  }
  int16_t get_int16(uint64_t addr)
  {
    return get_memory_view(addr, sizeof(int16_t), MRQ_READ).read<int16_t>();
  }
  void set(uint64_t addr, int16_t val)
  {
    get_memory_view(addr, sizeof(val), MRQ_WRITE).write(val);
  }
  uint16_t get_instr_uint16()
  {
    auto res = get_memory_view(ip, sizeof(uint16_t), MRQ_EXEC).read<uint16_t>();
    ip += sizeof(res);
    return res;
  }
  int16_t get_instr_int16()
  {
    auto res = get_memory_view(ip, sizeof(int16_t), MRQ_EXEC).read<int16_t>();
    ip += sizeof(res);
    return res;
  }
  uint32_t get_uint32(uint64_t addr)
  {
    return get_memory_view(addr, sizeof(uint32_t), MRQ_READ).read<uint32_t>();
  }
  void set(uint64_t addr, uint32_t val)
  {
    get_memory_view(addr, sizeof(val), MRQ_WRITE).write(val);
  }
  int32_t get_int32(uint64_t addr)
  {
    return get_memory_view(addr, sizeof(int32_t), MRQ_READ).read<int32_t>();
  }
  void set(uint64_t addr, int32_t val)
  {
    get_memory_view(addr, sizeof(val), MRQ_WRITE).write(val);
  }
  uint32_t get_instr_uint32()
  {
    auto res = get_memory_view(ip, sizeof(uint32_t), MRQ_EXEC).read<uint32_t>();
    ip += sizeof(res);
    return res;
  }
  int32_t get_instr_int32()
  {
    auto res = get_memory_view(ip, sizeof(int32_t), MRQ_EXEC).read<int32_t>();
    ip += sizeof(res);
    return res;
  }
  uint64_t get_uint64(uint64_t addr)
  {
    return get_memory_view(addr, sizeof(uint64_t), MRQ_READ).read<uint64_t>();
  }
  void set(uint64_t addr, uint64_t val)
  {
    get_memory_view(addr, sizeof(val), MRQ_WRITE).write(val);
  }
  int64_t get_int64(uint64_t addr)
  {
    return get_memory_view(addr, sizeof(int64_t), MRQ_READ).read<int64_t>();
  }
  void set(uint64_t addr, int64_t val)
  {
    get_memory_view(addr, sizeof(val), MRQ_WRITE).write(val);
  }
  uint64_t get_instr_uint64()
  {
    auto res = get_memory_view(ip, sizeof(uint64_t), MRQ_EXEC).read<uint64_t>();
    ip += sizeof(res);
    return res;
  }
  int64_t get_instr_int64()
  {
    auto res = get_memory_view(ip, sizeof(int64_t), MRQ_EXEC).read<int64_t>();
    ip += sizeof(res);
    return res;
  }
  // half get_float16(uint64_t addr)=0;
  // void set(uint64_t addr, half val)=0;
  // half get_instr_float16();
  float get_float32(uint64_t addr)
  {
    return get_memory_view(addr, sizeof(float), MRQ_READ).read<float>();
  }
  void set(uint64_t addr, float val)
  {
    get_memory_view(addr, sizeof(val), MRQ_WRITE).write(val);
  }
  float get_instr_float32()
  {
    auto res = get_memory_view(ip, sizeof(float), MRQ_EXEC).read<float>();
    ip += sizeof(res);
    return res;
  }
  double get_float64(uint64_t addr)
  {
    return get_memory_view(addr, sizeof(double), MRQ_READ).read<double>();
  }
  void set(uint64_t addr, double val)
  {
    get_memory_view(addr, sizeof(val), MRQ_WRITE).write(val);
  }
  double get_instr_float64()
  {
    auto res = get_memory_view(ip, sizeof(double), MRQ_EXEC).read<double>();
    ip += sizeof(res);
    return res;
  }
  // quadruple get_float128(uint64_t addr)=0;
  // void set(uint64_t addr, quadruple val)=0;
  // quadruple get_instr_float128();
  void set_from(uint64_t addr, uint8_t *buf, size_t size)
  {
    get_memory_view(addr, size, MRQ_WRITE).writefrom(buf);
  }
  void get_into(uint64_t addr, uint8_t *buf, size_t size)
  {
    get_memory_view(addr, size, MRQ_READ).readinto(buf);
  }
  void get_instr_data_into(uint8_t *buf, size_t size)
  {
    get_memory_view(ip, size, MRQ_EXEC).readinto(buf);
    ip += size;
  }
  void get_into(uint64_t addr, uint8_t *buf, size_t size, uint8_t mrq_perms)
  {
    get_memory_view(addr, size, mrq_perms).readinto(buf);
  }
  uint8_t pop_uint8()
  {
    auto res = get_uint8(sp);
    sp += 1;
    return res;
  }
  uint16_t pop_uint16()
  {
    auto res = get_uint16(sp);
    sp += 2;
    return res;
  }
  uint32_t pop_uint32()
  {
    auto res = get_uint32(sp);
    sp += 4;
    return res;
  }
  uint64_t pop_uint64()
  {
    auto res = get_uint64(sp);
    sp += 8;
    return res;
  }
  int8_t pop_int8()
  {
    auto res = get_int8(sp);
    sp += 1;
    return res;
  }
  int16_t pop_int16()
  {
    auto res = get_int16(sp);
    sp += 2;
    return res;
  }
  int32_t pop_int32()
  {
    auto res = get_int32(sp);
    sp += 4;
    return res;
  }
  int64_t pop_int64()
  {
    auto res = get_int64(sp);
    sp += 8;
    return res;
  }
  // half pop_float16()
  float pop_float32()
  {
    auto res = get_float32(sp);
    sp += 4;
    return res;
  }
  double pop_float64()
  {
    auto res = get_float64(sp);
    sp += 8;
    return res;
  }
  // quadruple pop_float128()
  void push(uint8_t val)
  {
    set(sp -= 1, val);
  }
  void push(uint16_t val)
  {
    set(sp -= 2, val);
  }
  void push(uint32_t val)
  {
    set(sp -= 4, val);
  }
  void push(uint64_t val)
  {
    set(sp -= 8, val);
  }
  void push(int8_t val)
  {
    set(sp -= 1, val);
  }
  void push(int16_t val)
  {
    set(sp -= 2, val);
  }
  void push(int32_t val)
  {
    set(sp -= 4, val);
  }
  void push(int64_t val)
  {
    set(sp -= 8, val);
  }
  // void push(half val)
  void push(float val)
  {
    set(sp -= 4, val);
  }
  void push(double val)
  {
    set(sp -= 8, val);
  }
  // void push(quadruple val)
  void pop_into(uint8_t *buf, size_t size)
  {
    get_into(sp, buf, size);
    sp += size;
  }
  void push_from(uint8_t *buf, size_t size)
  {
    set_from(sp -= size, buf, size);
  }
  void trap(uint8_t int_n, uint64_t prev_ip, uint64_t prev_bp, uint64_t prev_sp, uint64_t prev_flags, uint64_t error_code = 0)
  {
    uint64_t isr_table_ptr = sys_regs[SVSR_ISR];
    if (isr_table_ptr == 0)
    {
      running = false;
      printf("NO ISR TABLE provided. dumping error report\n  int_n = 0x%02X", int_n);
      printf("\n  prev_ip = 0x%016llX\n  prev_bp = 0x%016llX\n  prev_sp = 0x%016llX\n  prev_flags = 0x%016llX", prev_ip, prev_bp, prev_sp, prev_flags);
      printf("\n  error_code = 0x%016llX\n", error_code);
      return;
    }

    // Read 16-byte ISR entry: [8B isr_flags][8B handler_addr]
    uint64_t isr_entry[2] = {0, 0};
    {
      uint8_t saved_priv = priv_lvl;
      priv_lvl = PRIV_KERNEL;
      calc_flags();
      MemoryView mv = get_memory_view(isr_table_ptr + int_n * 16, 16, MRQ_READ);
      mv.readatinto(0, (uint8_t *)isr_entry, 16);
      priv_lvl = saved_priv;
      calc_flags();
    }
    uint64_t isr_flags = isr_entry[0];
    uint64_t handler_addr = isr_entry[1];
    uint8_t isr_priv = (isr_flags >> 8) & 1; // privilege for this handler

    // Save caller's sp, switch to ISR privilege's stack
    sys_regs[SVSRB_SP + priv_lvl] = prev_sp;
    sp = sys_regs[SVSRB_SP + isr_priv];

    // Push v3 interrupt frame (TOS = lowest address = int_n):
    //   [bp+0] int_n  [bp+8] error_code  [bp+16] saved_flags
    //   [bp+24] user_bp  [bp+32] user_sp  [bp+40] user_ip
    push((uint64_t)prev_ip);    // user_ip  at [bp+40]
    push((uint64_t)prev_sp);    // user_sp  at [bp+32]
    push((uint64_t)prev_bp);    // user_bp  at [bp+24]
    push((uint64_t)prev_flags); // saved_flags at [bp+16]
    push((uint64_t)error_code); // error_code at [bp+8]
    push((uint64_t)int_n);      // int_num  at [bp+0]  <- TOS
    bp = sp;

    // Apply ISR flags: sets privilege level, priority, virt_mem_mode
    sys_regs[SVSR_FLAGS] = isr_flags;
    calc_from_flags();

    // Jump to ISR handler
    ip = handler_addr;
  }

  inline void calc_from_flags()
  {
    uint64_t flags = sys_regs[SVSR_FLAGS];
    priority = (flags & SVSR_FLAGS_PRI_MASK) >> SVSR_FLAGS_PRI_SHFT;
    priv_lvl = (flags & SVSR_FLAGS_PRIV_MASK) >> SVSR_FLAGS_PRIV_SHFT;
    vaddr_msb_eq_priv = (flags & SVSR_FLAGS_VADDR_MSB_EQ_PRIV_MASK) >> SVSR_FLAGS_VADDR_MSB_EQ_PRIV_SHFT;
    virt_mem_mode = (flags & SVSR_FLAGS_VIRT_MEM_MD_MASK) >> SVSR_FLAGS_VIRT_MEM_MD_SHFT;
  }

  inline void calc_flags()
  {
    uint64_t flags = ((priority << SVSR_FLAGS_PRI_SHFT) & SVSR_FLAGS_PRI_MASK);
    flags |= (priv_lvl << SVSR_FLAGS_PRIV_SHFT) & SVSR_FLAGS_PRIV_MASK;
    flags |= (vaddr_msb_eq_priv << SVSR_FLAGS_VADDR_MSB_EQ_PRIV_SHFT) & SVSR_FLAGS_VADDR_MSB_EQ_PRIV_MASK;
    flags |= (virt_mem_mode << SVSR_FLAGS_VIRT_MEM_MD_SHFT) & SVSR_FLAGS_VIRT_MEM_MD_MASK;
    sys_regs[SVSR_FLAGS] = flags;
  }

  inline void call(uint64_t addr)
  {
    push(bp);
    push(ip);
    ip = addr;
    bp = sp;
  }

  inline void ret()
  {
    sp = bp;
    ip = pop_uint64();
    bp = pop_uint64();
  }
  // Switches from the current privilege level to new_priv_lvl.
  // Saves current sp to sys_regs[SVSRB_SP + priv_lvl] and
  // loads sys_regs[SVSRB_SP + new_priv_lvl] into sp.
  // Updates FLAGS and broken-out fields via calc_from_flags().
  // Throws INT_PROTECT_FAULT if already at new_priv_lvl.
  inline void switch_to_priv_simple(int new_priv_lvl)
  {
    if (this->priv_lvl == new_priv_lvl)
    {
      throw StackVM_TrapException(INT_PROTECT_FAULT);
    }
    sys_regs[SVSRB_SP + this->priv_lvl] = sp;
    sp = sys_regs[SVSRB_SP + new_priv_lvl];
    uint64_t flags = sys_regs[SVSR_FLAGS];
    flags = (flags & ~SVSR_FLAGS_PRIV_MASK) | ((uint64_t)new_priv_lvl << SVSR_FLAGS_PRIV_SHFT);
    sys_regs[SVSR_FLAGS] = flags;
    calc_from_flags();
  }
  inline void set_flags_switch_to_priv(uint64_t new_flags)
  {
    uint64_t old_flags = sys_regs[SVSR_FLAGS];
    if ((old_flags & SVSR_FLAGS_PRIV_MASK) != (new_flags & SVSR_FLAGS_PRIV_MASK))
    {
      int new_priv_lvl = (new_flags & SVSR_FLAGS_PRIV_MASK) >> SVSR_FLAGS_PRIV_SHFT;
      sys_regs[SVSRB_SP + this->priv_lvl] = sp;
      sp = sys_regs[SVSRB_SP + new_priv_lvl];
    }
    sys_regs[SVSR_FLAGS] = new_flags;
    calc_from_flags();
  }
  inline void execute_once()
  {
    const uint8_t code = get_instr_uint8();
    const uint8_t extra = ((code & 0b11111000) == 0b00001000) ? get_instr_uint8() : 0;
    if (code > 0x7F)
    {
      throw StackVM_TrapException(INT_INVAL_OPCODE, code);
    }

    switch (code)
    {
    case BC_NOP:
      break;
    case BC_HLT:
      if (priv_lvl == 0)
      {
        running = false;
      }
      else
      {
        throw StackVM_TrapException(INT_INVAL_OPCODE, code | (extra << 8));
      }
      break;
    case BC_EQ0:
      push(uint8_t(pop_int8() == 0));
      break;
    case BC_NE0:
      push(uint8_t(pop_int8() != 0));
      break;
    case BC_LT0:
      push(uint8_t(pop_int8() < 0));
      break;
    case BC_LE0:
      push(uint8_t(pop_int8() <= 0));
      break;
    case BC_GT0:
      push(uint8_t(pop_int8() > 0));
      break;
    case BC_GE0:
      push(uint8_t(pop_int8() >= 0));
      break;
    case BC_CONV:
      switch (extra)
      {
      case 0x00:
      {
        const uint8_t inp = pop_uint8();
        push(inp);
      }
      break;
      case 0x01:
      {
        const uint8_t inp = pop_int8();
        push(inp);
      }
      break;
      case 0x02:
      {
        const uint8_t inp = pop_uint16();
        push(inp);
      }
      break;
      case 0x03:
      {
        const uint8_t inp = pop_int16();
        push(inp);
      }
      break;
      case 0x04:
      {
        const uint8_t inp = pop_uint32();
        push(inp);
      }
      break;
      case 0x05:
      {
        const uint8_t inp = pop_int32();
        push(inp);
      }
      break;
      case 0x06:
      {
        const uint8_t inp = pop_uint64();
        push(inp);
      }
      break;
      case 0x07:
      {
        const uint8_t inp = pop_int64();
        push(inp);
      }
      break;
      case 0x09:
      {
        const uint8_t inp = pop_float32();
        push(inp);
      }
      break;
      case 0x0A:
      {
        const uint8_t inp = pop_float64();
        push(inp);
      }
      break;

      case 0x10:
      {
        const int8_t inp = pop_uint8();
        push(inp);
      }
      break;
      case 0x11:
      {
        const int8_t inp = pop_int8();
        push(inp);
      }
      break;
      case 0x12:
      {
        const int8_t inp = pop_uint16();
        push(inp);
      }
      break;
      case 0x13:
      {
        const int8_t inp = pop_int16();
        push(inp);
      }
      break;
      case 0x14:
      {
        const int8_t inp = pop_uint32();
        push(inp);
      }
      break;
      case 0x15:
      {
        const int8_t inp = pop_int32();
        push(inp);
      }
      break;
      case 0x16:
      {
        const int8_t inp = pop_uint64();
        push(inp);
      }
      break;
      case 0x17:
      {
        const int8_t inp = pop_int64();
        push(inp);
      }
      break;
      case 0x19:
      {
        const int8_t inp = pop_float32();
        push(inp);
      }
      break;
      case 0x1A:
      {
        const int8_t inp = pop_float64();
        push(inp);
      }
      break;

      case 0x20:
      {
        const uint16_t inp = pop_uint8();
        push(inp);
      }
      break;
      case 0x21:
      {
        const uint16_t inp = pop_int8();
        push(inp);
      }
      break;
      case 0x22:
      {
        const uint16_t inp = pop_uint16();
        push(inp);
      }
      break;
      case 0x23:
      {
        const uint16_t inp = pop_int16();
        push(inp);
      }
      break;
      case 0x24:
      {
        const uint16_t inp = pop_uint32();
        push(inp);
      }
      break;
      case 0x25:
      {
        const uint16_t inp = pop_int32();
        push(inp);
      }
      break;
      case 0x26:
      {
        const uint16_t inp = pop_uint64();
        push(inp);
      }
      break;
      case 0x27:
      {
        const uint16_t inp = pop_int64();
        push(inp);
      }
      break;
      case 0x29:
      {
        const uint16_t inp = pop_float32();
        push(inp);
      }
      break;
      case 0x2A:
      {
        const uint16_t inp = pop_float64();
        push(inp);
      }
      break;

      case 0x30:
      {
        const int16_t inp = pop_uint8();
        push(inp);
      }
      break;
      case 0x31:
      {
        const int16_t inp = pop_int8();
        push(inp);
      }
      break;
      case 0x32:
      {
        const int16_t inp = pop_uint16();
        push(inp);
      }
      break;
      case 0x33:
      {
        const int16_t inp = pop_int16();
        push(inp);
      }
      break;
      case 0x34:
      {
        const int16_t inp = pop_uint32();
        push(inp);
      }
      break;
      case 0x35:
      {
        const int16_t inp = pop_int32();
        push(inp);
      }
      break;
      case 0x36:
      {
        const int16_t inp = pop_uint64();
        push(inp);
      }
      break;
      case 0x37:
      {
        const int16_t inp = pop_int64();
        push(inp);
      }
      break;
      case 0x39:
      {
        const int16_t inp = pop_float32();
        push(inp);
      }
      break;
      case 0x3A:
      {
        const int16_t inp = pop_float64();
        push(inp);
      }
      break;

      case 0x40:
      {
        const uint32_t inp = pop_uint8();
        push(inp);
      }
      break;
      case 0x41:
      {
        const uint32_t inp = pop_int8();
        push(inp);
      }
      break;
      case 0x42:
      {
        const uint32_t inp = pop_uint16();
        push(inp);
      }
      break;
      case 0x43:
      {
        const uint32_t inp = pop_int16();
        push(inp);
      }
      break;
      case 0x44:
      {
        const uint32_t inp = pop_uint32();
        push(inp);
      }
      break;
      case 0x45:
      {
        const uint32_t inp = pop_int32();
        push(inp);
      }
      break;
      case 0x46:
      {
        const uint32_t inp = pop_uint64();
        push(inp);
      }
      break;
      case 0x47:
      {
        const uint32_t inp = pop_int64();
        push(inp);
      }
      break;
      case 0x49:
      {
        const uint32_t inp = pop_float32();
        push(inp);
      }
      break;
      case 0x4A:
      {
        const uint32_t inp = pop_float64();
        push(inp);
      }
      break;

      case 0x50:
      {
        const int32_t inp = pop_uint8();
        push(inp);
      }
      break;
      case 0x51:
      {
        const int32_t inp = pop_int8();
        push(inp);
      }
      break;
      case 0x52:
      {
        const int32_t inp = pop_uint16();
        push(inp);
      }
      break;
      case 0x53:
      {
        const int32_t inp = pop_int16();
        push(inp);
      }
      break;
      case 0x54:
      {
        const int32_t inp = pop_uint32();
        push(inp);
      }
      break;
      case 0x55:
      {
        const int32_t inp = pop_int32();
        push(inp);
      }
      break;
      case 0x56:
      {
        const int32_t inp = pop_uint64();
        push(inp);
      }
      break;
      case 0x57:
      {
        const int32_t inp = pop_int64();
        push(inp);
      }
      break;
      case 0x59:
      {
        const int32_t inp = pop_float32();
        push(inp);
      }
      break;
      case 0x5A:
      {
        const int32_t inp = pop_float64();
        push(inp);
      }
      break;

      case 0x60:
      {
        const uint64_t inp = pop_uint8();
        push(inp);
      }
      break;
      case 0x61:
      {
        const uint64_t inp = pop_int8();
        push(inp);
      }
      break;
      case 0x62:
      {
        const uint64_t inp = pop_uint16();
        push(inp);
      }
      break;
      case 0x63:
      {
        const uint64_t inp = pop_int16();
        push(inp);
      }
      break;
      case 0x64:
      {
        const uint64_t inp = pop_uint32();
        push(inp);
      }
      break;
      case 0x65:
      {
        const uint64_t inp = pop_int32();
        push(inp);
      }
      break;
      case 0x66:
      {
        const uint64_t inp = pop_uint64();
        push(inp);
      }
      break;
      case 0x67:
      {
        const uint64_t inp = pop_int64();
        push(inp);
      }
      break;
      case 0x69:
      {
        const uint64_t inp = pop_float32();
        push(inp);
      }
      break;
      case 0x6A:
      {
        const uint64_t inp = pop_float64();
        push(inp);
      }
      break;

      case 0x70:
      {
        const int64_t inp = pop_uint8();
        push(inp);
      }
      break;
      case 0x71:
      {
        const int64_t inp = pop_int8();
        push(inp);
      }
      break;
      case 0x72:
      {
        const int64_t inp = pop_uint16();
        push(inp);
      }
      break;
      case 0x73:
      {
        const int64_t inp = pop_int16();
        push(inp);
      }
      break;
      case 0x74:
      {
        const int64_t inp = pop_uint32();
        push(inp);
      }
      break;
      case 0x75:
      {
        const int64_t inp = pop_int32();
        push(inp);
      }
      break;
      case 0x76:
      {
        const int64_t inp = pop_uint64();
        push(inp);
      }
      break;
      case 0x77:
      {
        const int64_t inp = pop_int64();
        push(inp);
      }
      break;
      case 0x79:
      {
        const int64_t inp = pop_float32();
        push(inp);
      }
      break;
      case 0x7A:
      {
        const int64_t inp = pop_float64();
        push(inp);
      }
      break;

      case 0x90:
      {
        const float inp = pop_uint8();
        push(inp);
      }
      break;
      case 0x91:
      {
        const float inp = pop_int8();
        push(inp);
      }
      break;
      case 0x92:
      {
        const float inp = pop_uint16();
        push(inp);
      }
      break;
      case 0x93:
      {
        const float inp = pop_int16();
        push(inp);
      }
      break;
      case 0x94:
      {
        const float inp = pop_uint32();
        push(inp);
      }
      break;
      case 0x95:
      {
        const float inp = pop_int32();
        push(inp);
      }
      break;
      case 0x96:
      {
        const float inp = pop_uint64();
        push(inp);
      }
      break;
      case 0x97:
      {
        const float inp = pop_int64();
        push(inp);
      }
      break;
      case 0x99:
      {
        const float inp = pop_float32();
        push(inp);
      }
      break;
      case 0x9A:
      {
        const float inp = pop_float64();
        push(inp);
      }
      break;

      case 0xA0:
      {
        const double inp = pop_uint8();
        push(inp);
      }
      break;
      case 0xA1:
      {
        const double inp = pop_int8();
        push(inp);
      }
      break;
      case 0xA2:
      {
        const double inp = pop_uint16();
        push(inp);
      }
      break;
      case 0xA3:
      {
        const double inp = pop_int16();
        push(inp);
      }
      break;
      case 0xA4:
      {
        const double inp = pop_uint32();
        push(inp);
      }
      break;
      case 0xA5:
      {
        const double inp = pop_int32();
        push(inp);
      }
      break;
      case 0xA6:
      {
        const double inp = pop_uint64();
        push(inp);
      }
      break;
      case 0xA7:
      {
        const double inp = pop_int64();
        push(inp);
      }
      break;
      case 0xA9:
      {
        const double inp = pop_float32();
        push(inp);
      }
      break;
      case 0xAA:
      {
        const double inp = pop_float64();
        push(inp);
      }
      break;
      default:
        throw StackVM_TrapException(INT_INVAL_OPCODE, code | (extra << 8));
      }
      break;
    case BC_SWAP:
    {
      // BC_SWAP
      uint8_t a[128];
      uint8_t b[128];
      const uint8_t ref_code_b = (extra >> 3) & 3;
      const uint8_t ref_code_a = extra & 3;
      pop_into(b, 1 << ref_code_b);
      pop_into(a, 1 << ref_code_a);
      push_from(a, 1 << ref_code_a);
      push_from(b, 1 << ref_code_b);
    }
    break;
    case BC_LOAD:
    {
      const size_t size = 1 << (extra >> 5);
      if (size > 16)
      {
        throw StackVM_TrapException(INT_INVAL_OPCODE, code | (extra << 8));
      }
      uint8_t buf[16];
      uint64_t addr;
      switch (extra & 0x1F)
      {
      case BCR_ABS_A4:
        addr = get_instr_uint32();
        get_into(addr, buf, size);
        push_from(buf, size);
        break;
      case BCR_ABS_A8:
        addr = get_instr_uint64();
        get_into(addr, buf, size);
        push_from(buf, size);
        break;
      case BCR_ABS_S4:
        addr = pop_uint32();
        get_into(addr, buf, size);
        push_from(buf, size);
        break;
      case BCR_ABS_S8:
        addr = pop_uint64();
        get_into(addr, buf, size);
        push_from(buf, size);
        break;
      case BCR_R_BP1:
        addr = bp + get_instr_int8();
        get_into(addr, buf, size);
        push_from(buf, size);
        break;
      case BCR_R_BP2:
        addr = bp + get_instr_int16();
        get_into(addr, buf, size);
        push_from(buf, size);
        break;
      case BCR_R_BP4:
        addr = bp + get_instr_int32();
        get_into(addr, buf, size);
        push_from(buf, size);
        break;
      case BCR_R_BP8:
        addr = bp + get_instr_int64();
        get_into(addr, buf, size);
        push_from(buf, size);
        break;
      case BCR_ABS_C:
        get_instr_data_into(buf, size);
        push_from(buf, size);
        break;
      case BCR_REG_BP:
        push(bp);
        break;
      case BCR_RES:
        if (size == 1)
        {
          push((uint8_t)ax);
        }
        else if (size == 2)
        {
          push((uint16_t)ax);
        }
        else if (size == 4)
        {
          push((uint32_t)ax);
        }
        else
        {
          push(ax);
        }
        break;
      case BCR_EA_R_IP:
        if (size == 1)
        {
          push(ip + get_instr_int8());
        }
        else if (size == 2)
        {
          push(ip + get_instr_int16());
        }
        else if (size == 4)
        {
          push(ip + get_instr_int32());
        }
        else
        {
          push(ip + get_instr_int64());
        }
        break;
      case BCR_TOS:
        get_into(sp, buf, size);
        push_from(buf, size);
        break;
      case BCR_SYSREG:
      {
        uint8_t which = get_instr_uint8();
        if (which >= 14 || ((SVSR_REGISTER_PERMS[which] & (1 << priv_lvl)) == 0))
        {
          throw StackVM_TrapException(INT_PROTECT_FAULT);
        }
        if (which == priv_lvl + SVSRB_SP)
        {
          sys_regs[which] = sp;
        }
        push(sys_regs[which]);
      }
      break;
      // Atomic LOAD BCR codes (single-core: behave as regular loads)
      case BCR_ATOMIC_LOAD:
      case BCR_ATOMIC_XCHG:
      case BCR_ATOMIC_CAS:
      case BCR_ATOMIC_FADD:
      case BCR_ATOMIC_FSUB:
      case BCR_ATOMIC_FAND:
      case BCR_ATOMIC_FOR:
      case BCR_ATOMIC_FXOR:
      {
        // Consume ordering byte (ignored on single-core)
        get_instr_uint8();
        // For simplicity on single-core, treat as regular LOAD ABS_S8
        addr = pop_uint64();
        get_into(addr, buf, size);
        push_from(buf, size);
      }
      break;
      default:
        throw StackVM_TrapException(INT_INVAL_OPCODE, code | (extra << 8));
      }
    }
    break;
    case BC_STOR:
    {
      const size_t size = 1 << (extra >> 5);
      if (size > 16)
      {
        throw StackVM_TrapException(INT_INVAL_OPCODE, true);
      }
      uint8_t buf[16];
      uint64_t addr;
      switch (extra & 0x1F)
      {
      case BCR_ABS_A4:
        addr = get_instr_uint32();
        pop_into(buf, size);
        set_from(addr, buf, size);
        break;
      case BCR_ABS_A8:
        addr = get_instr_uint64();
        pop_into(buf, size);
        set_from(addr, buf, size);
        break;
      case BCR_ABS_S4:
        addr = pop_uint32();
        pop_into(buf, size);
        set_from(addr, buf, size);
        break;
      case BCR_ABS_S8:
        addr = pop_uint64();
        pop_into(buf, size);
        set_from(addr, buf, size);
        break;
      case BCR_R_BP1:
        addr = bp + get_instr_int8();
        pop_into(buf, size);
        set_from(addr, buf, size);
        break;
      case BCR_R_BP2:
        addr = bp + get_instr_int16();
        pop_into(buf, size);
        set_from(addr, buf, size);
        break;
      case BCR_R_BP4:
        addr = bp + get_instr_int32();
        pop_into(buf, size);
        set_from(addr, buf, size);
        break;
      case BCR_R_BP8:
        addr = bp + get_instr_int64();
        pop_into(buf, size);
        set_from(addr, buf, size);
        break;
      case BCR_REG_BP:
        bp = pop_uint64();
        break;
      case BCR_SYSREG:
      {
        uint8_t which = get_instr_uint8();
        if (which >= 14 || ((SVSR_REGISTER_PERMS[which] & (4 << priv_lvl)) == 0))
        {
          throw StackVM_TrapException(INT_PROTECT_FAULT, true);
        }
        const uint64_t val = pop_uint64();
        if (which == SVSR_FLAGS)
        {
          const uint64_t illegal_mask = SVSR_FLAGS_ILLEGAL_BITS_WRITE_MASK[priv_lvl];
          if ((illegal_mask & val) != (illegal_mask & sys_regs[SVSR_FLAGS]))
          {
            throw StackVM_TrapException(INT_PROTECT_FAULT, true);
          }
          uint8_t vmd = val >> 10 & 0xF;
          if (vmd == VM_2_LVL_10_BIT_LEGACY || vmd > VM_4_LVL_12_BIT)
          {
            throw StackVM_TrapException(INT_PROTECT_FAULT, true);
          }
          sys_regs[SVSR_FLAGS] = val;
          calc_from_flags();
        }
        else
        {
          sys_regs[which] = val;
          if (which == priv_lvl + SVSRB_SP)
          {
            sp = val;
          }
        }
      }
      break;
      // 0x08: ATOMIC_STORE (consume ordering byte; single-core behaves as normal store)
      case 0x08:
      {
        get_instr_uint8(); // ordering byte, ignored on single-core
        addr = pop_uint64();
        pop_into(buf, size);
        set_from(addr, buf, size);
      }
      break;
      // 0x0A/0x0B/0x0C: memory fences (no-op on single-core emulator)
      case 0x0A: // FENCE_ALL
      case 0x0B: // FENCE_LOAD
      case 0x0C: // FENCE_STORE
        break;
      default:
        throw StackVM_TrapException(INT_INVAL_OPCODE, true);
      }
    }
    break;
      {
        if ((extra & BCCE_SYSCALL) > 0)
        {
          // syscall
          uint64_t sys_n = 0;
          const uint64_t prev_user_sp = sys_regs[SVSR_USER_SP];
          const uint64_t prev_kernel_sp = sys_regs[SVSR_KERNEL_SP];
          switch (extra & BCCE_S_SYSN_SZ8)
          {
          case BCCE_S_SYSN_SZ1:
            sys_n = pop_uint8();
            break;
          case BCCE_S_SYSN_SZ2:
            sys_n = pop_uint16();
            break;
          case BCCE_S_SYSN_SZ4:
            sys_n = pop_uint32();
            break;
          case BCCE_S_SYSN_SZ8:
            sys_n = pop_uint64();
            break;
          }
          uint8_t num = pop_uint8();
          size_t size = ((size_t)num + 1) * 8;
          MemoryView user_mv = get_memory_view(sp, size, MRQ_READ);
          sp += size;
          if (virt_syscall)
          {
            // Virtualized syscall mode: dispatch to host-provided handler, no kernel frame setup
            StackVM_TrapException::SimpleStruct err;
            virt_syscall(sys_n, &err);
          }
          else
          {
            // Full emulation mode: set up kernel frame and jump to SVSR_SYS_FN
            switch_to_priv_simple(0);
            try
            {
              MemoryView kernel_mv = get_memory_view(sp - (size + 25), size + 25, MRQ_WRITE);
              for (size_t i = 0; i < size; ++i)
              {
                kernel_mv[i + 25] = user_mv[i];
              }
              sp -= 25 + size;
              kernel_mv.write(ip, 0);
              kernel_mv.write(bp, 8);
              kernel_mv.write(sys_n, 16);
              kernel_mv[24] = num;
              bp = sp;
              ip = sys_regs[SVSR_SYS_FN];
            }
            catch (...)
            {
              sys_regs[SVSR_USER_SP] = prev_user_sp;
              sys_regs[SVSR_KERNEL_SP] = prev_kernel_sp;
              throw;
            }
          }
        }
        else
        {
          // Non-syscall extended call
          if (extra & BCCE_IS_INT)
          {
            // Software interrupt: read inline int_n byte, build v3 interrupt frame
            uint8_t int_n = get_instr_uint8();
            uint64_t prev_ip_ = ip, prev_sp_ = sp, prev_bp_ = bp;
            uint64_t prev_flags = sys_regs[SVSR_FLAGS];
            trap(int_n, prev_ip_, prev_bp_, prev_sp_, prev_flags);
          }
          else
          {
            // Normal extended call: BCCE_IS_REL selects relative vs absolute
            uint64_t addr = pop_uint64();
            if (extra & BCCE_IS_REL)
            {
              call(ip + (int64_t)addr);
            }
            else
            {
              call(addr);
            }
          }
        }
      }
      break;
    case BC_RET_E:
    {
      if ((extra & BCRE_SYS) > 0)
      {
        if (extra & BCRE_IS_INT)
        {
          // IRET: unwind v3 interrupt frame
          // Frame layout from bp: [+0]=int_num, [+8]=error_code, [+16]=saved_flags,
          //                       [+24]=user_bp, [+32]=user_sp, [+40]=user_ip
          sp = bp;
          /* uint64_t int_num    = */ pop_uint64();
          /* uint64_t error_code = */ pop_uint64();
          uint64_t saved_flags = pop_uint64();
          uint64_t user_bp_ = pop_uint64();
          uint64_t user_sp_ = pop_uint64();
          uint64_t user_ip_ = pop_uint64();
          sys_regs[SVSR_KERNEL_SP] = sp; // save kernel sp for next trap entry
          ip = user_ip_;
          bp = user_bp_;
          sys_regs[SVSR_FLAGS] = saved_flags;
          calc_from_flags();
          sp = user_sp_;
        }
        else
        {
          // Syscall return: copy return data from kernel stack back to user stack
          uint64_t sz_copy = pop_uint64();
          if (sz_copy > 2048)
            sz_copy = 2048;
          // Read return data while still in kernel privilege
          uint8_t ret_buf[2048];
          if (sz_copy > 0)
          {
            get_into(sp, ret_buf, sz_copy);
          }
          // Restore kernel frame (sp = bp, then pop fields)
          sp = bp;
          uint64_t prev_ip = pop_uint64();
          uint64_t prev_bp = pop_uint64();
          pop_uint64(); // stored sys_n (skip)
          uint8_t num = get_uint8(sp);
          sp += 1;
          sp += ((size_t)num + 1) * 8; // skip args copied from user stack
          sys_regs[SVSR_KERNEL_SP] = sp;
          // Switch back to user privilege
          uint64_t new_flags = sys_regs[SVSR_FLAGS] | SVSR_FLAGS_PRIV_MASK;
          sys_regs[SVSR_FLAGS] = new_flags;
          calc_from_flags();
          // Copy return data onto user stack
          sp = sys_regs[SVSR_USER_SP];
          sp -= sz_copy;
          if (sz_copy > 0)
          {
            set_from(sp, ret_buf, sz_copy);
          }
          bp = prev_bp;
          ip = prev_ip;
        } // end else (SYSRET)
      }
      else
      {
        // Non-syscall extended return
        // Pop RST_SP value (size class in bits 6:5)
        uint64_t rst_sp = 0;
        switch ((extra >> 5) & 3)
        {
        case 0:
          rst_sp = pop_uint8();
          break;
        case 1:
          rst_sp = pop_uint16();
          break;
        case 2:
          rst_sp = pop_uint32();
          break;
        case 3:
          rst_sp = pop_uint64();
          break;
        }
        // Pop res_sz value (size class in bits 4:3)
        uint64_t res_sz = 0;
        switch ((extra >> 3) & 3)
        {
        case 0:
          res_sz = pop_uint8();
          break;
        case 1:
          res_sz = pop_uint16();
          break;
        case 2:
          res_sz = pop_uint32();
          break;
        case 3:
          res_sz = pop_uint64();
          break;
        }
        // Save result (up to 8 bytes) into ax; caller retrieves via LOAD BCR_RES
        ax = 0;
        if (res_sz > 0)
        {
          get_into(sp, (uint8_t *)&ax, (res_sz < 8) ? (size_t)res_sz : 8);
        }
        // Stack switch and pop return frame
        sp = bp;
        ip = pop_uint64();
        bp = pop_uint64();
        // Clear caller's args
        sp += rst_sp;
      }
    }
    break;
    case BC_INT128:
    {
      // extra = sub-operation code (BC128_*)
      switch (extra)
      {
      case BC128_ADD128U:
      {
        __uint128_t b, a;
        pop_into((uint8_t *)&b, 16);
        pop_into((uint8_t *)&a, 16);
        __uint128_t r = a + b;
        push_from((uint8_t *)&r, 16);
      }
      break;
      case BC128_ADD128S:
      {
        __int128_t b, a;
        pop_into((uint8_t *)&b, 16);
        pop_into((uint8_t *)&a, 16);
        __int128_t r = a + b;
        push_from((uint8_t *)&r, 16);
      }
      break;
      case BC128_SUB128U:
      {
        __uint128_t b, a;
        pop_into((uint8_t *)&b, 16);
        pop_into((uint8_t *)&a, 16);
        __uint128_t r = a - b;
        push_from((uint8_t *)&r, 16);
      }
      break;
      case BC128_SUB128S:
      {
        __int128_t b, a;
        pop_into((uint8_t *)&b, 16);
        pop_into((uint8_t *)&a, 16);
        __int128_t r = a - b;
        push_from((uint8_t *)&r, 16);
      }
      break;
      case BC128_MUL128U:
      {
        __uint128_t b, a;
        pop_into((uint8_t *)&b, 16);
        pop_into((uint8_t *)&a, 16);
        __uint128_t r = a * b;
        push_from((uint8_t *)&r, 16);
      }
      break;
      case BC128_MUL128S:
      {
        __int128_t b, a;
        pop_into((uint8_t *)&b, 16);
        pop_into((uint8_t *)&a, 16);
        __int128_t r = a * b;
        push_from((uint8_t *)&r, 16);
      }
      break;
      case BC128_DIV128U:
      {
        __uint128_t b, a;
        pop_into((uint8_t *)&b, 16);
        pop_into((uint8_t *)&a, 16);
        if (!b)
          throw StackVM_TrapException(INT_DIV_BY_ZERO);
        __uint128_t r = a / b;
        push_from((uint8_t *)&r, 16);
      }
      break;
      case BC128_DIV128S:
      {
        __int128_t b, a;
        pop_into((uint8_t *)&b, 16);
        pop_into((uint8_t *)&a, 16);
        if (!b)
          throw StackVM_TrapException(INT_DIV_BY_ZERO);
        __int128_t r = a / b;
        push_from((uint8_t *)&r, 16);
      }
      break;
      case BC128_MOD128U:
      {
        __uint128_t b, a;
        pop_into((uint8_t *)&b, 16);
        pop_into((uint8_t *)&a, 16);
        if (!b)
          throw StackVM_TrapException(INT_DIV_BY_ZERO);
        __uint128_t r = a % b;
        push_from((uint8_t *)&r, 16);
      }
      break;
      case BC128_MOD128S:
      {
        __int128_t b, a;
        pop_into((uint8_t *)&b, 16);
        pop_into((uint8_t *)&a, 16);
        if (!b)
          throw StackVM_TrapException(INT_DIV_BY_ZERO);
        __int128_t r = a % b;
        push_from((uint8_t *)&r, 16);
      }
      break;
      case BC128_AND128:
      {
        __uint128_t b, a;
        pop_into((uint8_t *)&b, 16);
        pop_into((uint8_t *)&a, 16);
        __uint128_t r = a & b;
        push_from((uint8_t *)&r, 16);
      }
      break;
      case BC128_OR128:
      {
        __uint128_t b, a;
        pop_into((uint8_t *)&b, 16);
        pop_into((uint8_t *)&a, 16);
        __uint128_t r = a | b;
        push_from((uint8_t *)&r, 16);
      }
      break;
      case BC128_XOR128:
      {
        __uint128_t b, a;
        pop_into((uint8_t *)&b, 16);
        pop_into((uint8_t *)&a, 16);
        __uint128_t r = a ^ b;
        push_from((uint8_t *)&r, 16);
      }
      break;
      case BC128_NOT128:
      {
        __uint128_t a;
        pop_into((uint8_t *)&a, 16);
        __uint128_t r = ~a;
        push_from((uint8_t *)&r, 16);
      }
      break;
      case BC128_LSHIFT128:
      {
        uint8_t sh = pop_uint8();
        __uint128_t a;
        pop_into((uint8_t *)&a, 16);
        __uint128_t r = a << sh;
        push_from((uint8_t *)&r, 16);
      }
      break;
      case BC128_RSHIFT128U:
      {
        uint8_t sh = pop_uint8();
        __uint128_t a;
        pop_into((uint8_t *)&a, 16);
        __uint128_t r = a >> sh;
        push_from((uint8_t *)&r, 16);
      }
      break;
      case BC128_RSHIFT128S:
      {
        uint8_t sh = pop_uint8();
        __int128_t a;
        pop_into((uint8_t *)&a, 16);
        __int128_t r = a >> sh;
        push_from((uint8_t *)&r, 16);
      }
      break;
      case BC128_CMP128U:
      {
        __uint128_t b, a;
        pop_into((uint8_t *)&b, 16);
        pop_into((uint8_t *)&a, 16);
        push((int64_t)(a < b ? -1 : a > b ? 1
                                          : 0));
      }
      break;
      case BC128_CMP128S:
      {
        __int128_t b, a;
        pop_into((uint8_t *)&b, 16);
        pop_into((uint8_t *)&a, 16);
        push((int64_t)(a < b ? -1 : a > b ? 1
                                          : 0));
      }
      break;
      case BC128_POPCNT1:
      {
        uint8_t a = pop_uint8();
        push((uint8_t)__builtin_popcount(a));
      }
      break;
      case BC128_POPCNT2:
      {
        uint16_t a = pop_uint16();
        push((uint8_t)__builtin_popcount(a));
      }
      break;
      case BC128_POPCNT4:
      {
        uint32_t a = pop_uint32();
        push((uint8_t)__builtin_popcount(a));
      }
      break;
      case BC128_POPCNT8:
      {
        uint64_t a = pop_uint64();
        push((uint8_t)__builtin_popcountll(a));
      }
      break;
      case BC128_BSWAP2:
      {
        uint16_t a = pop_uint16();
        push(__builtin_bswap16(a));
      }
      break;
      case BC128_BSWAP4:
      {
        uint32_t a = pop_uint32();
        push(__builtin_bswap32(a));
      }
      break;
      case BC128_BSWAP8:
      {
        uint64_t a = pop_uint64();
        push(__builtin_bswap64(a));
      }
      break;
      default:
        throw StackVM_TrapException(INT_INVAL_OPCODE, code | (extra << 8));
      }
    }
    break;
    case BC_INVTLB:
    {
      if (priv_lvl != PRIV_KERNEL)
        throw StackVM_TrapException(INT_PROTECT_FAULT);
      if (extra == 0x00)
      {
        // INVTLB_BEGIN: pop tlptr, vaddr_base, vaddr_size
        uint64_t vaddr_size = pop_uint64();
        uint64_t vaddr_base = pop_uint64();
        uint64_t tlptr_val = pop_uint64();
        (void)tlptr_val;
        (void)vaddr_base;
        (void)vaddr_size; // single-core: no-op
      }
      else if (extra == 0x01)
      {
        // INVTLB_COMMIT: no-op on single-core
      }
      else
      {
        throw StackVM_TrapException(INT_INVAL_OPCODE, code | (extra << 8));
      }
    }
    break;
    case BC_LSHIFT1:
    {
      uint8_t b = pop_uint8();
      uint8_t a = pop_uint8();
      push((uint8_t)(a << b));
    }
    break;
    case BC_LSHIFT2:
    {
      uint8_t b = pop_uint8();
      uint16_t a = pop_uint16();
      push((uint16_t)(a << b));
    }
    break;
    case BC_LSHIFT4:
    {
      uint8_t b = pop_uint8();
      uint32_t a = pop_uint32();
      push((uint32_t)(a << b));
    }
    break;
    case BC_LSHIFT8:
    {
      uint8_t b = pop_uint8();
      uint64_t a = pop_uint64();
      push((uint64_t)(a << b));
    }
    break;
    case BC_RSHIFT1:
    {
      uint8_t b = pop_uint8();
      uint8_t a = pop_uint8();
      push((uint8_t)(a >> b));
    }
    break;
    case BC_RSHIFT2:
    {
      uint8_t b = pop_uint8();
      uint16_t a = pop_uint16();
      push((uint16_t)(a >> b));
    }
    break;
    case BC_RSHIFT4:
    {
      uint8_t b = pop_uint8();
      uint32_t a = pop_uint32();
      push((uint32_t)(a >> b));
    }
    break;
    case BC_RSHIFT8:
    {
      uint8_t b = pop_uint8();
      uint64_t a = pop_uint64();
      push((uint64_t)(a >> b));
    }
    break;
    case BC_CLZ1:
    {
      uint8_t a = pop_uint8();
      push(a ? (uint8_t)(__builtin_clz((uint32_t)a) - 24) : (uint8_t)8);
    }
    break;
    case BC_CLZ2:
    {
      uint16_t a = pop_uint16();
      push(a ? (uint8_t)(__builtin_clz((uint32_t)a) - 16) : (uint8_t)16);
    }
    break;
    case BC_CLZ4:
    {
      uint32_t a = pop_uint32();
      push(a ? (uint8_t)__builtin_clz(a) : (uint8_t)32);
    }
    break;
    case BC_CLZ8:
    {
      uint64_t a = pop_uint64();
      push(a ? (uint8_t)__builtin_clzll(a) : (uint8_t)64);
    }
    break;
    case BC_CTZ1:
    {
      uint8_t a = pop_uint8();
      push(a ? (uint8_t)__builtin_ctz((uint32_t)a) : (uint8_t)8);
    }
    break;
    case BC_CTZ2:
    {
      uint16_t a = pop_uint16();
      push(a ? (uint8_t)__builtin_ctz((uint32_t)a) : (uint8_t)16);
    }
    break;
    case BC_CTZ4:
    {
      uint32_t a = pop_uint32();
      push(a ? (uint8_t)__builtin_ctz(a) : (uint8_t)32);
    }
    break;
    case BC_CTZ8:
    {
      uint64_t a = pop_uint64();
      push(a ? (uint8_t)__builtin_ctzll(a) : (uint8_t)64);
    }
    break;
    case BC_AND1:
    {
      uint8_t b = pop_uint8();
      uint8_t a = pop_uint8();
      push((uint8_t)(a & b));
    }
    break;
    case BC_AND2:
    {
      uint16_t b = pop_uint16();
      uint16_t a = pop_uint16();
      push((uint16_t)(a & b));
    }
    break;
    case BC_AND4:
    {
      uint32_t b = pop_uint32();
      uint32_t a = pop_uint32();
      push((uint32_t)(a & b));
    }
    break;
    case BC_AND8:
    {
      uint64_t b = pop_uint64();
      uint64_t a = pop_uint64();
      push((uint64_t)(a & b));
    }
    break;
    case BC_OR1:
    {
      uint8_t b = pop_uint8();
      uint8_t a = pop_uint8();
      push((uint8_t)(a | b));
    }
    break;
    case BC_OR2:
    {
      uint16_t b = pop_uint16();
      uint16_t a = pop_uint16();
      push((uint16_t)(a | b));
    }
    break;
    case BC_OR4:
    {
      uint32_t b = pop_uint32();
      uint32_t a = pop_uint32();
      push((uint32_t)(a | b));
    }
    break;
    case BC_OR8:
    {
      uint64_t b = pop_uint64();
      uint64_t a = pop_uint64();
      push((uint64_t)(a | b));
    }
    break;
    case BC_NOT1:
    {
      uint8_t a = pop_uint8();
      push((uint8_t)(~a));
    }
    break;
    case BC_NOT2:
    {
      uint16_t a = pop_uint16();
      push((uint16_t)(~a));
    }
    break;
    case BC_NOT4:
    {
      uint32_t a = pop_uint32();
      push((uint32_t)(~a));
    }
    break;
    case BC_NOT8:
    {
      uint64_t a = pop_uint64();
      push((uint64_t)(~a));
    }
    break;
    case BC_XOR1:
    {
      uint8_t b = pop_uint8();
      uint8_t a = pop_uint8();
      push((uint8_t)(a ^ b));
    }
    break;
    case BC_XOR2:
    {
      uint16_t b = pop_uint16();
      uint16_t a = pop_uint16();
      push((uint16_t)(a ^ b));
    }
    break;
    case BC_XOR4:
    {
      uint32_t b = pop_uint32();
      uint32_t a = pop_uint32();
      push((uint32_t)(a ^ b));
    }
    break;
    case BC_XOR8:
    {
      uint64_t b = pop_uint64();
      uint64_t a = pop_uint64();
      push((uint64_t)(a ^ b));
    }
    break;
    case BC_ADD1:
    {
      uint8_t b = pop_uint8();
      uint8_t a = pop_uint8();
      push((uint8_t)(a + b));
    }
    break;
    case BC_ADD2:
    {
      uint16_t b = pop_uint16();
      uint16_t a = pop_uint16();
      push((uint16_t)(a + b));
    }
    break;
    case BC_ADD4:
    {
      uint32_t b = pop_uint32();
      uint32_t a = pop_uint32();
      push((uint32_t)(a + b));
    }
    break;
    case BC_ADD8:
    {
      uint64_t b = pop_uint64();
      uint64_t a = pop_uint64();
      push((uint64_t)(a + b));
    }
    break;
    case BC_SUB1:
    {
      uint8_t b = pop_uint8();
      uint8_t a = pop_uint8();
      push((uint8_t)(a - b));
    }
    break;
    case BC_SUB2:
    {
      uint16_t b = pop_uint16();
      uint16_t a = pop_uint16();
      push((uint16_t)(a - b));
    }
    break;
    case BC_SUB4:
    {
      uint32_t b = pop_uint32();
      uint32_t a = pop_uint32();
      push((uint32_t)(a - b));
    }
    break;
    case BC_SUB8:
    {
      uint64_t b = pop_uint64();
      uint64_t a = pop_uint64();
      push((uint64_t)(a - b));
    }
    break;
    case BC_ADD_SP1:
    {
      uint8_t a = pop_uint8();
      sp -= a;
    }
    break;
    case BC_ADD_SP2:
    {
      uint16_t a = pop_uint16();
      sp -= a;
    }
    break;
    case BC_ADD_SP4:
    {
      uint32_t a = pop_uint32();
      sp -= a;
    }
    break;
    case BC_ADD_SP8:
    {
      uint64_t a = pop_uint64();
      sp -= a;
    }
    break;
    case BC_RST_SP1:
    {
      uint8_t a = pop_uint8();
      sp += a;
    }
    break;
    case BC_RST_SP2:
    {
      uint16_t a = pop_uint16();
      sp += a;
    }
    break;
    case BC_RST_SP4:
    {
      uint32_t a = pop_uint32();
      sp += a;
    }
    break;
    case BC_RST_SP8:
    {
      uint64_t a = pop_uint64();
      sp += a;
    }
    break;
    case BC_MUL1:
    {
      uint8_t b = pop_uint8();
      uint8_t a = pop_uint8();
      push((uint8_t)(a * b));
    }
    break;
    case BC_MUL1S:
    {
      int8_t b = pop_int8();
      int8_t a = pop_int8();
      push((int8_t)(a * b));
    }
    break;
    case BC_MUL2:
    {
      uint16_t b = pop_uint16();
      uint16_t a = pop_uint16();
      push((uint16_t)(a * b));
    }
    break;
    case BC_MUL2S:
    {
      int16_t b = pop_int16();
      int16_t a = pop_int16();
      push((int16_t)(a * b));
    }
    break;
    case BC_MUL4:
    {
      uint32_t b = pop_uint32();
      uint32_t a = pop_uint32();
      push((uint32_t)(a * b));
    }
    break;
    case BC_MUL4S:
    {
      int32_t b = pop_int32();
      int32_t a = pop_int32();
      push((int32_t)(a * b));
    }
    break;
    case BC_MUL8:
    {
      uint64_t b = pop_uint64();
      uint64_t a = pop_uint64();
      push((uint64_t)(a * b));
    }
    break;
    case BC_MUL8S:
    {
      int64_t b = pop_int64();
      int64_t a = pop_int64();
      push((int64_t)(a * b));
    }
    break;
    case BC_DIV1:
    {
      uint8_t b = pop_uint8();
      uint8_t a = pop_uint8();
      push((uint8_t)(a / b));
    }
    break;
    case BC_DIV1S:
    {
      int8_t b = pop_int8();
      int8_t a = pop_int8();
      push((int8_t)(a / b));
    }
    break;
    case BC_DIV2:
    {
      uint16_t b = pop_uint16();
      uint16_t a = pop_uint16();
      push((uint16_t)(a / b));
    }
    break;
    case BC_DIV2S:
    {
      int16_t b = pop_int16();
      int16_t a = pop_int16();
      push((int16_t)(a / b));
    }
    break;
    case BC_DIV4:
    {
      uint32_t b = pop_uint32();
      uint32_t a = pop_uint32();
      push((uint32_t)(a / b));
    }
    break;
    case BC_DIV4S:
    {
      int32_t b = pop_int32();
      int32_t a = pop_int32();
      push((int32_t)(a / b));
    }
    break;
    case BC_DIV8:
    {
      uint64_t b = pop_uint64();
      uint64_t a = pop_uint64();
      push((uint64_t)(a / b));
    }
    break;
    case BC_DIV8S:
    {
      int64_t b = pop_int64();
      int64_t a = pop_int64();
      push((int64_t)(a / b));
    }
    break;
    case BC_MOD1:
    {
      uint8_t b = pop_uint8();
      uint8_t a = pop_uint8();
      push((uint8_t)(a % b));
    }
    break;
    case BC_MOD1S:
    {
      int8_t b = pop_int8();
      int8_t a = pop_int8();
      push((int8_t)(a % b));
    }
    break;
    case BC_MOD2:
    {
      uint16_t b = pop_uint16();
      uint16_t a = pop_uint16();
      push((uint16_t)(a % b));
    }
    break;
    case BC_MOD2S:
    {
      int16_t b = pop_int16();
      int16_t a = pop_int16();
      push((int16_t)(a % b));
    }
    break;
    case BC_MOD4:
    {
      uint32_t b = pop_uint32();
      uint32_t a = pop_uint32();
      push((uint32_t)(a % b));
    }
    break;
    case BC_MOD4S:
    {
      int32_t b = pop_int32();
      int32_t a = pop_int32();
      push((int32_t)(a % b));
    }
    break;
    case BC_MOD8:
    {
      uint64_t b = pop_uint64();
      uint64_t a = pop_uint64();
      push((uint64_t)(a % b));
    }
    break;
    case BC_MOD8S:
    {
      int64_t b = pop_int64();
      int64_t a = pop_int64();
      push((int64_t)(a % b));
    }
    break;
    case BC_CMP1:
    {
      uint8_t b = pop_uint8();
      uint8_t a = pop_uint8();
      push(stack_vm_cmp(a, b));
    }
    break;
    case BC_CMP1S:
    {
      int8_t b = pop_int8();
      int8_t a = pop_int8();
      push(stack_vm_cmp(a, b));
    }
    break;
    case BC_CMP2:
    {
      uint16_t b = pop_uint16();
      uint16_t a = pop_uint16();
      push(stack_vm_cmp(a, b));
    }
    break;
    case BC_CMP2S:
    {
      int16_t b = pop_int16();
      int16_t a = pop_int16();
      push(stack_vm_cmp(a, b));
    }
    break;
    case BC_CMP4:
    {
      uint32_t b = pop_uint32();
      uint32_t a = pop_uint32();
      push(stack_vm_cmp(a, b));
    }
    break;
    case BC_CMP4S:
    {
      int32_t b = pop_int32();
      int32_t a = pop_int32();
      push(stack_vm_cmp(a, b));
    }
    break;
    case BC_CMP8:
    {
      uint64_t b = pop_uint64();
      uint64_t a = pop_uint64();
      push(stack_vm_cmp(a, b));
    }
    break;
    case BC_CMP8S:
    {
      int64_t b = pop_int64();
      int64_t a = pop_int64();
      push(stack_vm_cmp(a, b));
    }
    break;
    /*
    case BC_FADD_2:
    {
      auto b = pop_float16();
      auto a = pop_float16();
      push((decltype(a))(a + b));
    }
    break;
    */
    case BC_FADD_4:
    {
      auto b = pop_float32();
      auto a = pop_float32();
      push((decltype(a))(a + b));
    }
    break;
    case BC_FADD_8:
    {
      auto b = pop_float64();
      auto a = pop_float64();
      push((decltype(a))(a + b));
    }
    break;
    /*
    case BC_FADD_16:
    {
      auto b = pop_float128();
      auto a = pop_float128();
      push((decltype(a))(a + b));
    }
    break;
    */
    /*
    case BC_FSUB_2:
    {
      auto b = pop_float16();
      auto a = pop_float16();
      push((decltype(a))(a - b));
    }
    break;
    */
    case BC_FSUB_4:
    {
      auto b = pop_float32();
      auto a = pop_float32();
      push((decltype(a))(a - b));
    }
    break;
    case BC_FSUB_8:
    {
      auto b = pop_float64();
      auto a = pop_float64();
      push((decltype(a))(a - b));
    }
    break;
    /*
    case BC_FSUB_16:
    {
      auto b = pop_float128();
      auto a = pop_float128();
      push((decltype(a))(a - b));
    }
    break;
    */
    /*
    case BC_FMUL_2:
    {
      auto b = pop_float16();
      auto a = pop_float16();
      push((decltype(a))(a * b));
    }
    break;
    */
    case BC_FMUL_4:
    {
      auto b = pop_float32();
      auto a = pop_float32();
      push((decltype(a))(a * b));
    }
    break;
    case BC_FMUL_8:
    {
      auto b = pop_float64();
      auto a = pop_float64();
      push((decltype(a))(a * b));
    }
    break;
    /*
    case BC_FMUL_16:
    {
      auto b = pop_float128();
      auto a = pop_float128();
      push((decltype(a))(a * b));
    }
    break;
    */
    /*
    case BC_FDIV_2:
    {
      auto b = pop_float16();
      auto a = pop_float16();
      push((decltype(a))(a / b));
    }
    break;
    */
    case BC_FDIV_4:
    {
      auto b = pop_float32();
      auto a = pop_float32();
      push((decltype(a))(a / b));
    }
    break;
    case BC_FDIV_8:
    {
      auto b = pop_float64();
      auto a = pop_float64();
      push((decltype(a))(a / b));
    }
    break;
    /*
    case BC_FDIV_16:
    {
      auto b = pop_float128();
      auto a = pop_float128();
      push((decltype(a))(a / b));
    }
    break;
    */
    /*
    case BC_FMOD_2:
    {
      auto b = pop_float16();
      auto a = pop_float16();
      push((decltype(a))(fmod(a, b)));
    }
    break;
    */
    case BC_FMOD_4:
    {
      auto b = pop_float32();
      auto a = pop_float32();
      push((decltype(a))(fmod(a, b)));
    }
    break;
    case BC_FMOD_8:
    {
      auto b = pop_float64();
      auto a = pop_float64();
      push((decltype(a))(fmod(a, b)));
    }
    break;
    /*
    case BC_FMOD_16:
    {
      auto b = pop_float128();
      auto a = pop_float128();
      push((decltype(a))(fmod(a, b)));
    }
    break;
    */
    /*
    case BC_FCMP_2:
    {
      auto b = pop_float16();
      auto a = pop_float16();
      push(stack_vm_cmp(a, b));
    }
    break;
    */
    case BC_FCMP_4:
    {
      auto b = pop_float32();
      auto a = pop_float32();
      push(stack_vm_cmp(a, b));
    }
    break;
    case BC_FCMP_8:
    {
      auto b = pop_float64();
      auto a = pop_float64();
      push(stack_vm_cmp(a, b));
    }
    break;
      /*
    case BC_FCMP_16:
    {
      auto b = pop_float128();
      auto a = pop_float128();
      push(stack_vm_cmp(a, b));
    }
    break;
    */
    case BC_JMP:
      ip = pop_uint64();
      break;
    case BC_JMPIF:
    {
      uint64_t a = pop_uint64();
      uint8_t b = pop_uint8();
      if (b)
      {
        ip = a;
      }
    }
    break;
    case BC_RJMP:
      ip += pop_int64();
      break;
    case BC_RJMPIF:
    {
      int64_t a = pop_int64();
      uint8_t b = pop_uint8();
      if (b)
      {
        ip += a;
      }
    }
    break;
    case BC_CALL:
    {
      uint64_t addr = pop_uint64();
      call(addr);
    }
    break;
    case BC_RCALL:
    {
      int64_t offset = pop_int64();
      call(ip + offset);
    }
    break;
    case BC_RET:
      ret();
      break;
    case BC_RET_N2:
      // 0x7F is the invalid opcode trap in v3 ISA
      throw StackVM_TrapException(INT_INVAL_OPCODE, code | (extra << 8));
      break;
    }
  }

public:
  void execute()
  {
    while (running)
    {
      const uint64_t prev_ip = ip;
      const uint64_t prev_bp = bp;
      const uint64_t prev_sp = sp;
      const uint64_t prev_flags = sys_regs[SVSR_FLAGS];
      try
      {
        execute_once();
      }
      catch (StackVM_TrapException &exc)
      {
        ip = prev_ip;
        bp = prev_bp;
        sp = prev_sp;
        sys_regs[SVSR_FLAGS] = prev_flags;
        calc_from_flags();
        trap(exc.int_n, prev_ip, prev_bp, prev_sp, prev_flags, exc.arg0);
      }
    }
  }
};

extern "C"
{
  // StackVMExported: thin public subclass used by the C export API
  struct StackVMExported : public StackVM
  {
    std::unique_ptr<uint8_t[]> owned_memory;

    explicit StackVMExported(size_t mem_size) : StackVM(nullptr)
    {
      owned_memory = std::make_unique<uint8_t[]>(mem_size);
      set_memory(owned_memory.get(), mem_size);
      memsize = mem_size; // set_memory doesn't assign memsize
    }

    uint64_t pub_sp() { return sp; }
    void pub_set_sp(uint64_t v) { sp = v; }
    uint64_t pub_bp() { return bp; }
    void pub_set_bp(uint64_t v) { bp = v; }
    uint64_t pub_ip() { return ip; }
    void pub_set_ip(uint64_t v) { ip = v; }
    uint64_t pub_ax() { return ax; }
    uint8_t pub_running() { return running; }
    void pub_set_running(uint8_t v) { running = v; }
    uint8_t *pub_memory() { return memory; }
    size_t pub_memsize() { return memsize; }
    uint64_t pub_sysreg(uint8_t n) { return sys_regs[n]; }
    void pub_set_sysreg(uint8_t n, uint64_t v) { sys_regs[n] = v; }
    void pub_set_flags(uint64_t flags)
    {
      sys_regs[SVSR_FLAGS] = flags;
      calc_from_flags();
    }
    void pub_set_virt_syscall(VirtSyscall fn) { virt_syscall = fn; }

    void pub_step()
    {
      const uint64_t prev_ip = ip;
      const uint64_t prev_bp = bp;
      const uint64_t prev_sp = sp;
      const uint64_t prev_flags = sys_regs[SVSR_FLAGS];
      try
      {
        execute_once();
      }
      catch (StackVM_TrapException &exc)
      {
        ip = prev_ip;
        bp = prev_bp;
        sp = prev_sp;
        sys_regs[SVSR_FLAGS] = prev_flags;
        calc_from_flags();
        trap(exc.int_n, prev_ip, prev_bp, prev_sp, prev_flags, exc.arg0);
      }
    }
  };

  STACK_VM_EXPORT void *make_stack_vm(size_t memory_size)
  {
    return new StackVMExported(memory_size);
  }
  STACK_VM_EXPORT void destroy_stack_vm(void *vm)
  {
    delete static_cast<StackVMExported *>(vm);
  }
  STACK_VM_EXPORT uint64_t vm_get_sp(void *vm) { return static_cast<StackVMExported *>(vm)->pub_sp(); }
  STACK_VM_EXPORT void vm_set_sp(void *vm, uint64_t v) { static_cast<StackVMExported *>(vm)->pub_set_sp(v); }
  STACK_VM_EXPORT uint64_t vm_get_bp(void *vm) { return static_cast<StackVMExported *>(vm)->pub_bp(); }
  STACK_VM_EXPORT void vm_set_bp(void *vm, uint64_t v) { static_cast<StackVMExported *>(vm)->pub_set_bp(v); }
  STACK_VM_EXPORT uint64_t vm_get_ip(void *vm) { return static_cast<StackVMExported *>(vm)->pub_ip(); }
  STACK_VM_EXPORT void vm_set_ip(void *vm, uint64_t v) { static_cast<StackVMExported *>(vm)->pub_set_ip(v); }
  STACK_VM_EXPORT uint64_t vm_get_ax(void *vm) { return static_cast<StackVMExported *>(vm)->pub_ax(); }
  STACK_VM_EXPORT uint8_t vm_get_running(void *vm) { return static_cast<StackVMExported *>(vm)->pub_running(); }
  STACK_VM_EXPORT void vm_set_running(void *vm, uint8_t v) { static_cast<StackVMExported *>(vm)->pub_set_running(v); }
  STACK_VM_EXPORT uint8_t *vm_get_memory(void *vm) { return static_cast<StackVMExported *>(vm)->pub_memory(); }
  STACK_VM_EXPORT size_t vm_get_memsize(void *vm) { return static_cast<StackVMExported *>(vm)->pub_memsize(); }
  STACK_VM_EXPORT uint64_t vm_get_sysreg(void *vm, uint8_t n) { return static_cast<StackVMExported *>(vm)->pub_sysreg(n); }
  STACK_VM_EXPORT void vm_set_sysreg(void *vm, uint8_t n, uint64_t v) { static_cast<StackVMExported *>(vm)->pub_set_sysreg(n, v); }
  STACK_VM_EXPORT void vm_set_flags(void *vm, uint64_t flags) { static_cast<StackVMExported *>(vm)->pub_set_flags(flags); }
  STACK_VM_EXPORT void vm_set_virt_syscall(void *vm, void (*fn)(uint64_t, StackVM_TrapException::SimpleStruct *))
  {
    static_cast<StackVMExported *>(vm)->pub_set_virt_syscall(fn);
  }
  STACK_VM_EXPORT void vm_step(void *vm) { static_cast<StackVMExported *>(vm)->pub_step(); }
  STACK_VM_EXPORT void vm_execute(void *vm) { static_cast<StackVMExported *>(vm)->execute(); }
}
