#include <cstdint>
#include <limits>
#include <utility>
#include <cmath>
#include <type_traits>
#include <iostream>
#include <vector>
#ifdef __linux__
#define STACK_VM_EXPORT
#else
#define STACK_VM_EXPORT __declspec(dllexport)
#endif

#define STACK_VM_VER_2 2
// #define STACK_VM_VER_3

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
  BC_SYSRET = 14,
  // TODO: change BC_SYSRET
  BC_INT = 15,
  BC_LSHIFT1 = 16,
  BC_LSHIFT2 = 17,
  BC_LSHIFT4 = 18,
  BC_LSHIFT8 = 19,
  BC_RSHIFT1 = 20,
  BC_RSHIFT2 = 21,
  BC_RSHIFT4 = 22,
  BC_RSHIFT8 = 23,
  BC_LROT1 = 24,
  BC_LROT2 = 25,
  BC_LROT4 = 26,
  BC_LROT8 = 27,
  BC_RROT1 = 28,
  BC_RROT2 = 29,
  BC_RROT4 = 30,
  BC_RROT8 = 31,
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
  BCR_SZ_1 = 0x0 << 5,
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
  BCCE_N_REL = 1 << 6,
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
  SVSRB_PTE = 0x08,
  SVSR_KERNEL_PTE = 0x08,
  SVSR_USER_PTE = 0x09
};

enum StackVM_INT
{
  INT_INVAL_OPCODE = 6,
  INT_HARDWARE_IO = 7,
  INT_PROTECT_FAULT = 13,
  INT_PAGE_FAULT = 14
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
      idx -= size_first * (T *)(next + idx) = data;
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
      idx -= size_first return *(T *)(next + idx);
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
    // <- MSB [write user] [write kernel] [read user] [read kernel]
    0b1111, // FLAGS
    0b0101, // ISR
    0b0001, // SDP
    0b0101, // KERNEL_SYS_FN
    0b0101, // KERNEL_SP
    0b1111, // USER_SP
    0b0101, // KERNEL_PTE
    0b0101, // USER_PTE
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
  uint64_t sys_regs[8];
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
      throw std::exception("Unsupported virtual memory mode");
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
          phys_addr = walk_page(virt_addr, sys_regs[SVSR_USER_PTE], mrq_perms);
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
          phys_addr = walk_page(virt_addr, sys_regs[SVSR_USER_PTE], mrq_perms);
        }
        else
        {
          phys_addr = walk_page(virt_addr, sys_regs[SVSR_KERNEL_PTE], mrq_perms);
        }
      }
    }
    else
    {
      uint64_t page_size_m1 = 0xFFFF'FFFF'FFFF'FFFF;
      if (priv_lvl == PRIV_USER)
      {
        phys_addr = walk_page(virt_addr, sys_regs[SVSR_USER_PTE], mrq_perms);
      }
      else // priv_lvl == PRIV_KERNEL
      {
        phys_addr = walk_page(virt_addr, sys_regs[SVSR_KERNEL_PTE], mrq_perms);
        if (virt_error_data[0])
        {
          phys_addr = walk_page(virt_addr, sys_regs[SVSR_USER_PTE], mrq_perms);
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
  // half push(half val)
  float push(float val)
  {
    set(sp -= 4, val);
  }
  double push(double val)
  {
    set(sp -= 8, val);
  }
  // quadruple push(quadruple val)
  void pop_into(uint8_t *buf, size_t size)
  {
    get_into(sp, buf, size);
    sp += size;
  }
  void push_from(uint8_t *buf, size_t size)
  {
    set_from(sp -= size, buf, size);
  }
  void trap(uint8_t int_n, uint64_t prev_ip, uint64_t prev_bp, uint64_t prev_sp, uint64_t prev_flags, uint64_t arg0 = 0, uint64_t arg1 = 0, uint64_t arg2 = 0, uint64_t arg3 = 0)
  {
    uint64_t isr_table_ptr = sys_regs[SVSR_ISR];
    if (isr_table_ptr == 0)
    {
      running = false;
      printf("NO ISR TABLE provided. dumping error report\n  int_n = ");
      if (int_n == INT_INVAL_OPCODE)
      {
        printf("INT_INVAL_OPCODE");
      }
      else if (int_n == INT_PAGE_FAULT)
      {
        printf("INT_PAGE_FAULT");
      }
      else if (int_n == INT_PROTECT_FAULT)
      {
        printf("INT_PROTECT_FAULT");
      }
      else if (int_n == INT_HARDWARE_IO)
      {
        printf("INT_HARDWARE_IO");
      }
      else
      {
        printf("INT_UNKNOWN (0x%02X)", int_n);
      }
      printf("\n  prev_ip = 0x%016X\n  prev_bp = 0x%016X\n  prev_sp = 0x%016X\n  prev_flags = 0x%016X", prev_ip, prev_bp, prev_sp, prev_flags);
      printf("\n  arg0 = 0x%016X\n  arg1 = 0x%016X\n  arg2 = 0x%016X\n  arg3 = 0x%016X\n", arg0, arg1, arg2, arg3);
      return;
    }

    uint64_t flags_addr[2];
    {
      priv_lvl = PRIV_KERNEL; // switch so that we are getting memory under kernel privileges
      calc_flags();
      MemoryView page = get_memory_view(isr_table_ptr, 4096, MRQ_READ);
      page.readatinto(int_n * 16, (uint8_t *)flags_addr, 16);
      sys_regs[SVSR_FLAGS] = flags_addr[0] & ~SVSR_FLAGS_PRIV_MASK;
      calc_from_flags();
    }

    // TODO: finish implementation of switch to interrupt

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
  // writes back the SVSR stack pointer registers to synchronize the
  //   userspace SP with SVSR_USER_SP
  // modifies SVSR_FLAGS and its broken out components
  // loads SVSR_KERNEL_SP into sp
  // bp is unmodified and still points to userspace
  // fails if priv_lvl is already 0
  inline void switch_to_priv_simple(int priv_lvl)
  {
    // TODO
    if (priv_lvl == 0)
      ;
    sys_regs[SVSRB_SP + priv_lvl] = sp;
  }
  inline void set_flags_switch_to_priv(uint64_t new_flags) {
    uint64_t old_flags = sys_regs[SVSR_FLAGS];
    if (old_flags & SVSR_FLAGS_PRIV_MASK != new_flags & SVSR_FLAGS_PRIV_MASK) {
      int new_priv_lvl = (new_flags & SVSR_FLAGS_PRIV_MASK) >> SVSR_FLAGS_PRIV_SHFT;
      // TODO
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
      if (size >= 16)
      {
        throw StackVM_TrapException(INT_INVAL_OPCODE, code | (extra << 8));
      }
      uint8_t buf[8];
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
        if (which >= 8 || ((SVSR_REGISTER_PERMS[which] & (1 << priv_lvl)) == 0))
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
      default:
        throw StackVM_TrapException(INT_INVAL_OPCODE, code | (extra << 8));
      }
    }
    break;
    case BC_STOR:
    {
      const size_t size = 1 << (extra >> 5);
      if (size >= 16)
      {
        throw StackVM_TrapException(INT_INVAL_OPCODE, true);
      }
      uint8_t buf[8];
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
        if (which >= 8 || ((SVSR_REGISTER_PERMS[which] & (4 << priv_lvl)) == 0))
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
      default:
        throw StackVM_TrapException(INT_INVAL_OPCODE, true);
      }
    }
    break;
    case BC_CALL_E:
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
          StackVM_TrapException::SimpleStruct err;
          virt_syscall(sys_n, &err);
        }
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
        }
        catch (...)
        {
          sys_regs[SVSR_USER_SP] = prev_user_sp;
          sys_regs[SVSR_KERNEL_SP] = prev_kernel_sp;
          throw;
        }
      }
      else
      {
        // TODO
      }
    }
    break;
    case BC_RET_E:
    {
      if ((extra & BCRE_SYS) > 0)
      {
        // TODO sysret
      }
      else
      {
        // TODO
      }
    }
    break;
    case BC_INT:
    {
      const uint64_t arg0 = pop_uint64();
      const uint64_t arg1 = pop_uint64();
      const uint64_t arg2 = pop_uint64();
      const uint64_t arg3 = pop_uint64();
      trap(extra, arg0, arg1, arg2, arg3);
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
    case BC_LROT1:
    {
      uint8_t b = pop_uint8();
      uint8_t a = pop_uint8();
      b %= 8;
      push((uint8_t)((a << b) | (a >> (8 - b))));
    }
    break;
    case BC_LROT2:
    {
      uint8_t b = pop_uint8();
      uint16_t a = pop_uint16();
      b %= 16;
      push((uint16_t)((a << b) | (a >> (16 - b))));
    }
    break;
    case BC_LROT4:
    {
      uint8_t b = pop_uint8();
      uint32_t a = pop_uint32();
      b %= 32;
      push((uint32_t)((a << b) | (a >> (32 - b))));
    }
    break;
    case BC_LROT8:
    {
      uint8_t b = pop_uint8();
      uint64_t a = pop_uint64();
      b %= 64;
      push((uint64_t)((a << b) | (a >> (64 - b))));
    }
    break;
    case BC_RROT1:
    {
      uint8_t b = pop_uint8();
      uint8_t a = pop_uint8();
      b %= 8;
      push((uint8_t)((a >> b) | (a << (8 - b))));
    }
    break;
    case BC_RROT2:
    {
      uint8_t b = pop_uint8();
      uint16_t a = pop_uint16();
      b %= 16;
      push((uint16_t)((a >> b) | (a << (16 - b))));
    }
    break;
    case BC_RROT4:
    {
      uint8_t b = pop_uint8();
      uint32_t a = pop_uint32();
      b %= 32;
      push((uint32_t)((a >> b) | (a << (32 - b))));
    }
    break;
    case BC_RROT8:
    {
      uint8_t b = pop_uint8();
      uint64_t a = pop_uint64();
      b %= 64;
      push((uint64_t)((a >> b) | (a << (64 - b))));
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
      // TODO
      break;
    case BC_RCALL:
      // TODO
      break;
    case BC_RET:
      // TODO:
      break;
    case BC_RET_N2:
      // TODO:
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
        trap(exc.int_n, prev_ip, prev_bp, prev_sp, prev_flags, exc.arg0, exc.arg1, exc.arg2, exc.arg3);
      }
    }
  }
};
