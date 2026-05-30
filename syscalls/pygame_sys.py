"""
Pygame syscall set  (syscall numbers 0x02–0x0C).

These numbers are fixed by the existing pygame_test.cpp / PyStackVM.virt_syscall
implementation.  Do NOT change them without updating both the C-level test files
and the PyStackVM fallback.
"""

from __future__ import annotations

import sys

from .base import BaseSyscallSet, SyscallContext
from .numbers import (
    SYS_PYG_INIT,
    SYS_PYG_DISPLAY_INIT,
    SYS_PYG_FONT_INIT,
    SYS_PYG_DISPLAY_SET_MODE,
    SYS_PYG_SURF_FILL,
    SYS_PYG_DISPLAY_UPDATE,
    SYS_PYG_QUIT,
    SYS_PYG_WAIT_EVENT,
    SYS_PYG_DELETE_OBJ,
    SYS_PYG_LOAD_EVENT,
    SYS_PYG_GET_EVENT_TYPE,
)


class PygameSyscallSet(BaseSyscallSet):
    """Wraps the full pygame syscall surface (0x02–0x0C) in a SyscallSet."""

    name = "pygame"

    def __init__(self) -> None:
        super().__init__()
        self.handlers = {
            SYS_PYG_INIT: self._pyg_init,
            SYS_PYG_DISPLAY_INIT: self._pyg_display_init,
            SYS_PYG_FONT_INIT: self._pyg_font_init,
            SYS_PYG_DISPLAY_SET_MODE: self._pyg_display_set_mode,
            SYS_PYG_SURF_FILL: self._pyg_surf_fill,
            SYS_PYG_DISPLAY_UPDATE: self._pyg_display_update,
            SYS_PYG_QUIT: self._pyg_quit,
            SYS_PYG_WAIT_EVENT: self._pyg_wait_event,
            SYS_PYG_DELETE_OBJ: self._pyg_delete_obj,
            SYS_PYG_LOAD_EVENT: self._pyg_load_event,
            SYS_PYG_GET_EVENT_TYPE: self._pyg_get_event_type,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _objects(ctx: SyscallContext):
        """Return the VM's ObjectIdAllocator (must exist on PyStackVM instances)."""
        return ctx.vm.objects

    @staticmethod
    def _pyg_mod(ctx: SyscallContext):
        """Look up the cached pygame module handle."""
        return ctx.vm.objects[ctx.vm.pyg_index]

    # ------------------------------------------------------------------
    # Handlers
    # ------------------------------------------------------------------

    def _pyg_init(self, ctx: SyscallContext) -> None:
        import pygame  # noqa: PLC0415

        idx = self._objects(ctx).put(pygame)
        ctx.vm.pyg_index = idx
        ctx.set_result(idx)

    def _pyg_display_init(self, ctx: SyscallContext) -> None:
        pygame = self._objects(ctx)[ctx.arg(0)]
        pygame.display.init()

    def _pyg_font_init(self, ctx: SyscallContext) -> None:
        pygame = self._objects(ctx)[ctx.arg(0)]
        pygame.font.init()

    def _pyg_display_set_mode(self, ctx: SyscallContext) -> None:
        pygame = self._objects(ctx)[ctx.arg(0)]
        wh = ctx.arg(1)
        surf = pygame.display.set_mode((wh & 0xFFFFFFFF, wh >> 32))
        ctx.set_result(self._objects(ctx).put(surf))

    def _pyg_surf_fill(self, ctx: SyscallContext) -> None:
        objects = self._objects(ctx)
        pygame = self._pyg_mod(ctx)
        surf = objects[ctx.arg(0)]
        b = ctx.arg(1)  # LO: 0x00RRGGBB  HI: flags
        c = ctx.arg(2)  # LO: left        HI: top
        d = ctx.arg(3)  # LO: width       HI: height
        color = ((b & 0xFF0000) >> 16, (b & 0xFF00) >> 8, b & 0xFF)
        surf.fill(
            color,
            pygame.Rect(c & 0xFFFFFFFF, c >> 32, d & 0xFFFFFFFF, d >> 32),
        )

    def _pyg_display_update(self, ctx: SyscallContext) -> None:
        pygame = self._objects(ctx)[ctx.arg(0)]
        rect_ptr = ctx.arg(1)
        rect_count = ctx.arg(2)
        vm = ctx.vm
        if rect_count:
            lst_rects = [
                pygame.Rect(
                    vm.get(4, off),
                    vm.get(4, off + 4),
                    vm.get(4, off + 8),
                    vm.get(4, off + 12),
                )
                for off in range(rect_ptr, rect_ptr + rect_count * 16, 16)
            ]
            pygame.display.update(lst_rects)
        else:
            pygame.display.update()

    def _pyg_quit(self, ctx: SyscallContext) -> None:
        pygame = self._objects(ctx)[ctx.arg(0)]
        pygame.quit()

    def _pyg_wait_event(self, ctx: SyscallContext) -> None:
        pygame = self._objects(ctx)[ctx.arg(0)]
        ctx.set_result(self._objects(ctx).put(pygame.event.wait()))

    def _pyg_delete_obj(self, ctx: SyscallContext) -> None:
        del self._objects(ctx)[ctx.arg(0)]

    def _pyg_load_event(self, ctx: SyscallContext) -> None:
        objects = self._objects(ctx)
        pygame = objects[ctx.arg(0)]
        evt = objects[ctx.arg(1)]
        buf = ctx.arg(2)
        vm = ctx.vm
        vm.set(4, buf, evt.type)
        if evt.type == pygame.KEYDOWN:
            vm.set(4, buf + 4, evt.key)
            vm.set(4, buf + 8, evt.mod)
            vm.set(4, buf + 12, ord(evt.unicode) if len(evt.unicode) else 0)
        elif evt.type == pygame.KEYUP:
            vm.set(4, buf + 4, evt.key)
            vm.set(4, buf + 8, evt.mod)
        elif evt.type == pygame.MOUSEMOTION:
            btns = 0
            for i, btn in enumerate(evt.buttons):
                btns |= btn << i
            vm.set(4, buf + 4, btns)
            vm.set(4, buf + 8, evt.pos[0])
            vm.set(4, buf + 12, evt.pos[1])
            vm.set(4, buf + 16, evt.rel[0])
            vm.set(4, buf + 20, evt.rel[1])
        elif evt.type in (pygame.MOUSEBUTTONDOWN, pygame.MOUSEBUTTONUP):
            vm.set(4, buf + 4, evt.button)
            vm.set(4, buf + 8, evt.pos[0])
            vm.set(4, buf + 12, evt.pos[1])

    def _pyg_get_event_type(self, ctx: SyscallContext) -> None:
        pygame = self._objects(ctx)[ctx.arg(0)]
        attr = ctx.read_zstr(ctx.arg(1))
        res = 0xFFFFFFFFFFFFFFFF
        try:
            val = getattr(pygame, attr)
            if isinstance(val, int):
                res = val
        except AttributeError:
            pass
        ctx.set_result(res)
