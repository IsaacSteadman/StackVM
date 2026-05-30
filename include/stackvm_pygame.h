/*
 * stackvm_pygame.h — Pygame graphics surface for StackVM programs.
 *
 * Provides typed handle aliases and inline wrappers for every pygame syscall
 * (numbers 0x02–0x0C), preserving full binary compatibility with
 * pygame_test.cpp / PyStackVM.virt_syscall.
 *
 * Handle types
 * ------------
 * All handles are opaque size_t values assigned by the host.  Use the
 * typedef aliases to make code self-documenting.
 *
 *   h_pygame_t  — result of pyg_init(); must be passed to most other calls.
 *   h_surf_t    — a pygame Surface, returned by pyg_display_set_mode().
 *   h_event_t   — a pygame Event, returned by pyg_wait_event().
 *
 * Event buffer layout (for pyg_load_event)
 * -----------------------------------------
 * The buf pointer passed to pyg_load_event should point to at least 24 bytes:
 *
 *   [0]   uint32  evt.type
 *   [4]   uint32  key / button / btn_mask
 *   [8]   uint32  mod / pos.x / rel.x (event-specific)
 *   [12]  uint32  unicode / pos.y / rel.y
 *   [16]  uint32  rel.x  (MOUSEMOTION only)
 *   [20]  uint32  rel.y  (MOUSEMOTION only)
 *
 * Syscall numbers (host-side: StackVM/syscalls/pygame_sys.py):
 *
 *   SYS_PYG_INIT              0x02
 *   SYS_PYG_DISPLAY_INIT      0x03
 *   SYS_PYG_FONT_INIT         0x04
 *   SYS_PYG_DISPLAY_SET_MODE  0x05
 *   SYS_PYG_SURF_FILL         0x06
 *   SYS_PYG_DISPLAY_UPDATE    0x07
 *   SYS_PYG_QUIT              0x08
 *   SYS_PYG_WAIT_EVENT        0x09
 *   SYS_PYG_DELETE_OBJ        0x0A
 *   SYS_PYG_LOAD_EVENT        0x0B
 *   SYS_PYG_GET_EVENT_TYPE    0x0C
 */

#ifndef STACKVM_PYGAME_H
#define STACKVM_PYGAME_H

#include "stackvm.h"

/* ---- Handle types ------------------------------------------------------- */
typedef size_t h_pygame_t;
typedef size_t h_surf_t;
typedef size_t h_event_t;

/* ---- Syscall numbers ---------------------------------------------------- */
#define SYS_PYG_INIT 0x02
#define SYS_PYG_DISPLAY_INIT 0x03
#define SYS_PYG_FONT_INIT 0x04
#define SYS_PYG_DISPLAY_SET_MODE 0x05
#define SYS_PYG_SURF_FILL 0x06
#define SYS_PYG_DISPLAY_UPDATE 0x07
#define SYS_PYG_QUIT 0x08
#define SYS_PYG_WAIT_EVENT 0x09
#define SYS_PYG_DELETE_OBJ 0x0A
#define SYS_PYG_LOAD_EVENT 0x0B
#define SYS_PYG_GET_EVENT_TYPE 0x0C

/* ========================================================================= */
/* Inline wrappers                                                            */
/* ========================================================================= */

/*
 * Initialise pygame and return an opaque pygame handle.
 * Must be called before any other pyg_* function.
 */
static inline h_pygame_t pyg_init(void)
{
    return (h_pygame_t)syscall(SYS_PYG_INIT, 0, 0, 0, 0);
}

/* Initialise the display subsystem. */
static inline void pyg_display_init(h_pygame_t pyg)
{
    syscall(SYS_PYG_DISPLAY_INIT, pyg, 0, 0, 0);
}

/* Initialise the font subsystem. */
static inline void pyg_font_init(h_pygame_t pyg)
{
    syscall(SYS_PYG_FONT_INIT, pyg, 0, 0, 0);
}

/*
 * Set the display mode to *width* x *height* pixels.
 * Returns a Surface handle for the display.
 */
static inline h_surf_t pyg_display_set_mode(h_pygame_t pyg,
                                            uint32_t width,
                                            uint32_t height)
{
    size_t wh = (size_t)width | ((size_t)height << 32);
    return (h_surf_t)syscall(SYS_PYG_DISPLAY_SET_MODE, pyg, wh, 0, 0);
}

/*
 * Fill a rectangular region of *surf* with *r*/
*g * /*b* colour.
      * Pass x=0, y=0, w=0, h=0 for the full surface (rect is ignored when all zero
      * — identical to Pygame's no-rect behaviour).
      */
    static inline void
    pyg_surf_fill(h_surf_t surf,
                  uint8_t r, uint8_t g, uint8_t b,
                  uint32_t x, uint32_t y,
                  uint32_t w, uint32_t h)
{
    size_t color_flags = (size_t)((uint32_t)r << 16 | (uint32_t)g << 8 | b);
    size_t xy = (size_t)x | ((size_t)y << 32);
    size_t wh = (size_t)w | ((size_t)h << 32);
    syscall(SYS_PYG_SURF_FILL, surf, color_flags, xy, wh);
}

/*
 * Update the display.  Pass rect_arr=NULL, rect_count=0 to refresh everything.
 *
 * If rect_count > 0, *rect_arr* must point to an array of rect_count packed
 * 16-byte records: [left:i32][top:i32][width:i32][height:i32].
 */
static inline void pyg_display_update(h_pygame_t pyg,
                                      const void *rect_arr,
                                      size_t rect_count)
{
    syscall(SYS_PYG_DISPLAY_UPDATE, pyg, (size_t)rect_arr, rect_count, 0);
}

/* Quit pygame and release resources associated with *pyg*. */
static inline void pyg_quit(h_pygame_t pyg)
{
    syscall(SYS_PYG_QUIT, pyg, 0, 0, 0);
}

/*
 * Block until the next pygame event and return an event handle.
 * Release the handle with pyg_delete_obj() when done.
 */
static inline h_event_t pyg_wait_event(h_pygame_t pyg)
{
    return (h_event_t)syscall(SYS_PYG_WAIT_EVENT, pyg, 0, 0, 0);
}

/*
 * Release any object handle (Surface, Event, etc.) obtained from a pyg_*
 * function.
 */
static inline void pyg_delete_obj(size_t obj)
{
    syscall(SYS_PYG_DELETE_OBJ, obj, 0, 0, 0);
}

/*
 * Fill *buf* with fields from event handle *evt*.
 * See the event buffer layout in the file-level comment.
 */
static inline void pyg_load_event(h_pygame_t pyg,
                                  h_event_t evt,
                                  void *buf)
{
    syscall(SYS_PYG_LOAD_EVENT, pyg, evt, (size_t)buf, 0);
}

/*
 * Translate a pygame constant name (e.g. "QUIT", "KEYDOWN") to its integer
 * value.  Returns 0xFFFFFFFFFFFFFFFF if the attribute is not found.
 */
static inline size_t pyg_get_event_type(h_pygame_t pyg, const char *attr_name)
{
    return syscall(SYS_PYG_GET_EVENT_TYPE, pyg, (size_t)attr_name, 0, 0);
}

#endif /* STACKVM_PYGAME_H */
