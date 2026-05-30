# StackVM syscall number table.
#
# Convention:
#   When syscall(sys_n, arg0, arg1, arg2, arg3) is executed:
#     vm.sp + 0   = num_bytes_of_args (u64, always 32 for the 4-arg ABI)
#     vm.sp + 8   = arg0 (u64)
#     vm.sp + 16  = arg1 (u64)
#     vm.sp + 24  = arg2 (u64)
#     vm.sp + 32  = arg3 (u64) — also the return value slot
#
#   Handlers read args via ctx.arg(0..3) and write a result via ctx.set_result(v).

# ---------------------------------------------------------------------------
# Pygame syscall set  (0x00–0x0F)
# These numbers are fixed by the existing pygame_test.cpp demo.
# ---------------------------------------------------------------------------
SYS_PYG_INIT = 0x02  # () -> pygame_handle
SYS_PYG_DISPLAY_INIT = 0x03  # (pygame_handle)
SYS_PYG_FONT_INIT = 0x04  # (pygame_handle)
SYS_PYG_DISPLAY_SET_MODE = 0x05  # (pygame_handle, wh_packed) -> surf_handle
#   w = wh_packed & 0xFFFFFFFF, h = wh_packed >> 32
SYS_PYG_SURF_FILL = 0x06  # (surf_handle, rgba_flags, xy_packed, wh_packed)
#   color = rgba_flags & 0xFFFFFF (0x00RRGGBB)
#   flags = rgba_flags >> 32
#   x = xy_packed & 0xFFFFFFFF, y = xy_packed >> 32
#   w = wh_packed & 0xFFFFFFFF, h = wh_packed >> 32
SYS_PYG_DISPLAY_UPDATE = 0x07  # (pygame_handle, rect_arr_ptr, rect_count)
#   rect_count=0 means update all
SYS_PYG_QUIT = 0x08  # (pygame_handle)
SYS_PYG_WAIT_EVENT = 0x09  # (pygame_handle) -> event_handle
SYS_PYG_DELETE_OBJ = 0x0A  # (obj_handle)
SYS_PYG_LOAD_EVENT = 0x0B  # (pygame_handle, event_handle, buf_ptr)
#   writes event fields into buf_ptr
SYS_PYG_GET_EVENT_TYPE = 0x0C  # (pygame_handle, attr_str_ptr) -> type_id
#   returns getattr(pygame, attr) as int, or 0xFFFF...FF

# ---------------------------------------------------------------------------
# OS / basic syscall set  (0x10–0x1F)
# ---------------------------------------------------------------------------
SYS_EXIT = 0x10  # (exit_code, _, _, _)         — terminate program
SYS_WRITE = 0x11  # (fd, buf_ptr, len, _)         -> bytes_written
SYS_READ = 0x12  # (fd, buf_ptr, len, _)         -> bytes_read
SYS_OPEN = 0x13  # (path_ptr, flags, _, _)       -> fd  (flags: 0=r,1=w,2=rw,3=w+create)
SYS_CLOSE = 0x14  # (fd, _, _, _)
SYS_SEEK = 0x15  # (fd, offset, whence, _)       -> position
#   whence: 0=SEEK_SET, 1=SEEK_CUR, 2=SEEK_END
SYS_MMAP = 0x16  # (size, _, _, _)               -> ptr  (grow heap; 0 on failure)
SYS_MUNMAP = 0x17  # (ptr, size, _, _)             (no-op stub)
SYS_CLOCK_NS = 0x18  # (_, _, _, _)                  -> nanoseconds since epoch
SYS_SLEEP_NS = 0x19  # (ns, _, _, _)

# Standard file descriptors
FD_STDIN = 0
FD_STDOUT = 1
FD_STDERR = 2

# Seek whence values
SEEK_SET = 0
SEEK_CUR = 1
SEEK_END = 2

# Open flags
OPEN_READ = 0
OPEN_WRITE = 1
OPEN_READWRITE = 2
OPEN_WRITE_NEW = 3  # write + create/truncate
