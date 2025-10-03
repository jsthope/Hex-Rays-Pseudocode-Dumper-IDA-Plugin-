# -*- coding: utf-8 -*-
import os
import sys
import subprocess

import idaapi
import idautils
import ida_auto
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_loader

try:
    import ida_nalt
except Exception:
    ida_nalt = None

SKIP_LIBRARY_FUNCS_DEFAULT = True
SKIP_THUNK_FUNCS_DEFAULT   = True
ADD_HEADERS_DEFAULT        = True

SAVE_TO_FILE_ENABLED_DEFAULT = False
FILENAME_SUFFIX              = "_decomp_all.c"
HOTKEY_DEFAULT               = "Alt-Shift-D"

SAVE_TO_FILE_ENABLED = SAVE_TO_FILE_ENABLED_DEFAULT

def is_library_func(ea):
    """Return True if function comes from a library/import."""
    try:
        if hasattr(idaapi, "is_libfunc") and idaapi.is_libfunc(ea):
            return True
    except Exception:
        pass
    f = ida_funcs.get_func(ea)
    if f and (f.flags & ida_funcs.FUNC_LIB) != 0:
        return True
    try:
        if ida_nalt and ida_nalt.is_imported_name(ea):
            return True
    except Exception:
        pass
    return False

def is_thunk_func(ea):
    f = ida_funcs.get_func(ea)
    return bool(f and (f.flags & ida_funcs.FUNC_THUNK))

def decompile_text(ea):
    """Return Hex-Rays pseudocode as plain text (color tags removed)."""
    try:
        cfunc = ida_hexrays.decompile(ea)
        if not cfunc:
            return None
        return "\n".join(ida_lines.tag_remove(l.line) for l in cfunc.get_pseudocode())
    except ida_hexrays.DecompilationFailure:
        return None
    except Exception:
        return None

def copy_to_clipboard(txt):
    """Copy text to IDA clipboard with OS fallbacks."""
    try:
        ida_kernwin.set_clipboard(txt)
        return True
    except Exception:
        pass
    try:
        if sys.platform.startswith("win"):
            p = subprocess.Popen(["clip"], stdin=subprocess.PIPE, close_fds=True)
            p.communicate(input=txt.encode("utf-16le"))
            return p.returncode == 0
        elif sys.platform == "darwin":
            p = subprocess.Popen(["pbcopy"], stdin=subprocess.PIPE, close_fds=True)
            p.communicate(input=txt.encode("utf-8"))
            return p.returncode == 0
        else:
            for cmd in (["wl-copy"], ["xclip", "-selection", "clipboard"]):
                try:
                    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, close_fds=True)
                    p.communicate(input=txt.encode("utf-8"))
                    if p.returncode == 0:
                        return True
                except Exception:
                    continue
    except Exception:
        pass
    return False

def default_output_path():
    idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    base = os.path.splitext(os.path.basename(idb_path))[0] if idb_path else "output"
    dirn = os.path.dirname(idb_path) if idb_path else os.getcwd()
    return os.path.join(dirn, base + FILENAME_SUFFIX)

def build_output_path(ask_user=False):
    if not ask_user:
        return default_output_path()
    chosen = ida_kernwin.ask_file(True, default_output_path(), "Save Hex-Rays dump as...")
    return chosen or default_output_path()

def do_dump(skip_libs=True, skip_thunks=True, add_headers=True, save_mode="auto"):
    """
    save_mode:
      - "never": clipboard only (no file)
      - "auto" : save if SAVE_TO_FILE_ENABLED is True
      - "idb"  : force save next to IDB
      - "ask"  : prompt for a file path
    """
    ida_auto.auto_wait()

    if not ida_hexrays.init_hexrays_plugin():
        ida_kernwin.warning("Hex-Rays is not available (license/arch).")
        return

    out_lines = []
    total = dumped = skipped_lib = skipped_thunk = failed = 0

    for ea in idautils.Functions():
        total += 1
        if skip_libs and is_library_func(ea):
            skipped_lib += 1
            continue
        if skip_thunks and is_thunk_func(ea):
            skipped_thunk += 1
            continue

        text = decompile_text(ea)
        if not text:
            failed += 1
            continue

        dumped += 1
        if add_headers:
            name = ida_funcs.get_func_name(ea)
            out_lines.append("/" + "*" * 78 + "/")
            out_lines.append("/*** {0} @ 0x{1:08X} ***/".format(name, ea))
        out_lines.append(text)
        out_lines.append("")

    final_text = ("\n".join(out_lines)).strip() + "\n"

    clip_ok = copy_to_clipboard(final_text)

    save_path = None
    if save_mode == "idb":
        save_path = build_output_path(False)
    elif save_mode == "ask":
        save_path = build_output_path(True)
    elif save_mode == "auto":
        if SAVE_TO_FILE_ENABLED:
            save_path = build_output_path(False)
    elif save_mode == "never":
        save_path = None

    saved_ok = False
    if save_path:
        try:
            with open(save_path, "w", encoding="utf-8") as f:
                f.write(final_text)
            saved_ok = True
        except Exception as e:
            ida_kernwin.msg("[!] Failed to write file: {}\n".format(e))

    msg = (
        "[Hex-Rays dump] Done.\n"
        "  Total functions    : {t}\n"
        "  Dumped             : {d}\n"
        "  Skipped (lib)      : {sl}\n"
        "  Skipped (thunk)    : {st}\n"
        "  Decomp failures    : {f}\n"
        "  Clipboard          : {cp}\n"
        "  Save-to-.c (auto)  : {auto}\n"
    ).format(
        t=total, d=dumped, sl=skipped_lib, st=skipped_thunk, f=failed,
        cp="OK ✔" if clip_ok else "failed ✖",
        auto="ON" if SAVE_TO_FILE_ENABLED else "OFF",
    )
    if saved_ok:
        msg += "  File saved         : {}\n".format(save_path)
    ida_kernwin.info(msg)

ACTION_DUMP_AUTO   = "hx_dump:auto"     # respects SAVE_TO_FILE_ENABLED (OFF by default)
ACTION_DUMP_IDB    = "hx_dump:idb"      # force save next to IDB
ACTION_DUMP_ASK    = "hx_dump:ask"      # prompt for path
ACTION_TOGGLE_SAVE = "hx_dump:toggle"   # toggle SAVE_TO_FILE_ENABLED

class DumpAutoHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        do_dump(
            skip_libs=SKIP_LIBRARY_FUNCS_DEFAULT,
            skip_thunks=SKIP_THUNK_FUNCS_DEFAULT,
            add_headers=ADD_HEADERS_DEFAULT,
            save_mode="auto",
        )
        return 1
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class DumpIDBHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        do_dump(
            skip_libs=SKIP_LIBRARY_FUNCS_DEFAULT,
            skip_thunks=SKIP_THUNK_FUNCS_DEFAULT,
            add_headers=ADD_HEADERS_DEFAULT,
            save_mode="idb",
        )
        return 1
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class DumpAskHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        do_dump(
            skip_libs=SKIP_LIBRARY_FUNCS_DEFAULT,
            skip_thunks=SKIP_THUNK_FUNCS_DEFAULT,
            add_headers=ADD_HEADERS_DEFAULT,
            save_mode="ask",
        )
        return 1
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ToggleSaveHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        global SAVE_TO_FILE_ENABLED
        SAVE_TO_FILE_ENABLED = not SAVE_TO_FILE_ENABLED
        ida_kernwin.info('Save-to-.c (auto) is now: {}\n'
                         .format("ON" if SAVE_TO_FILE_ENABLED else "OFF"))
        return 1
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

def safe_unregister(aid):
    try:
        ida_kernwin.unregister_action(aid)
    except Exception:
        pass

def register_actions():
    for aid in (ACTION_DUMP_AUTO, ACTION_DUMP_IDB, ACTION_DUMP_ASK, ACTION_TOGGLE_SAVE):
        safe_unregister(aid)

    ida_kernwin.register_action(ida_kernwin.action_desc_t(
        ACTION_DUMP_AUTO,
        'Dump Hex-Rays pseudocode (auto save setting)',
        DumpAutoHandler(),
        HOTKEY_DEFAULT,
        'Concatenate pseudocode; always copies to clipboard; save depends on toggle (OFF by default).',
        0,
    ))
    ida_kernwin.register_action(ida_kernwin.action_desc_t(
        ACTION_DUMP_IDB,
        'Dump Hex-Rays pseudocode (save next to IDB)',
        DumpIDBHandler(),
        None,
        'Force saving a .c next to the IDB (also copies to clipboard).',
        0,
    ))
    ida_kernwin.register_action(ida_kernwin.action_desc_t(
        ACTION_DUMP_ASK,
        'Dump Hex-Rays pseudocode… (choose file)',
        DumpAskHandler(),
        None,
        'Prompt for an output file (also copies to clipboard).',
        0,
    ))
    ida_kernwin.register_action(ida_kernwin.action_desc_t(
        ACTION_TOGGLE_SAVE,
        'Toggle "Save to .c" (next to IDB)',
        ToggleSaveHandler(),
        None,
        'Turn automatic save ON/OFF for this session.',
        0,
    ))

    # Menus
    try:
        ida_kernwin.attach_action_to_menu("Edit/Dump Hex-Rays pseudocode (auto save setting)", ACTION_DUMP_AUTO, ida_kernwin.SETMENU_APP)
        ida_kernwin.attach_action_to_menu("Edit/Dump Hex-Rays pseudocode (save next to IDB)", ACTION_DUMP_IDB, ida_kernwin.SETMENU_APP)
        ida_kernwin.attach_action_to_menu("Edit/Dump Hex-Rays pseudocode… (choose file)", ACTION_DUMP_ASK, ida_kernwin.SETMENU_APP)
        ida_kernwin.attach_action_to_menu('Edit/Toggle "Save to .c" (next to IDB)', ACTION_TOGGLE_SAVE, ida_kernwin.SETMENU_APP)
    except Exception:
        # Fallback: Edit/Plugins
        ida_kernwin.attach_action_to_menu("Edit/Plugins/Dump Hex-Rays pseudocode (auto save setting)", ACTION_DUMP_AUTO, ida_kernwin.SETMENU_APP)
        ida_kernwin.attach_action_to_menu("Edit/Plugins/Dump Hex-Rays pseudocode (save next to IDB)", ACTION_DUMP_IDB, ida_kernwin.SETMENU_APP)
        ida_kernwin.attach_action_to_menu("Edit/Plugins/Dump Hex-Rays pseudocode… (choose file)", ACTION_DUMP_ASK, ida_kernwin.SETMENU_APP)
        ida_kernwin.attach_action_to_menu('Edit/Plugins/Toggle "Save to .c" (next to IDB)', ACTION_TOGGLE_SAVE, ida_kernwin.SETMENU_APP)

def unregister_actions():
    for title in (
        "Edit/Dump Hex-Rays pseudocode (auto save setting)",
        "Edit/Dump Hex-Rays pseudocode (save next to IDB)",
        "Edit/Dump Hex-Rays pseudocode… (choose file)",
        'Edit/Toggle "Save to .c" (next to IDB)',
        "Edit/Plugins/Dump Hex-Rays pseudocode (auto save setting)",
        "Edit/Plugins/Dump Hex-Rays pseudocode (save next to IDB)",
        "Edit/Plugins/Dump Hex-Rays pseudocode… (choose file)",
        'Edit/Plugins/Toggle "Save to .c" (next to IDB)',
    ):
        try:
            ida_kernwin.detach_action_from_menu(title, ACTION_DUMP_AUTO)
            ida_kernwin.detach_action_from_menu(title, ACTION_DUMP_IDB)
            ida_kernwin.detach_action_from_menu(title, ACTION_DUMP_ASK)
            ida_kernwin.detach_action_from_menu(title, ACTION_TOGGLE_SAVE)
        except Exception:
            pass
    for aid in (ACTION_DUMP_AUTO, ACTION_DUMP_IDB, ACTION_DUMP_ASK, ACTION_TOGGLE_SAVE):
        safe_unregister(aid)

class hx_dump_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Dump Hex-Rays pseudocode (non-library functions)"
    help = "Concatenate Hex-Rays pseudocode, copy to clipboard, and optionally save to .c."
    wanted_name = "Dump Hex-Rays pseudocode"
    wanted_hotkey = HOTKEY_DEFAULT

    def init(self):
        register_actions()
        return idaapi.PLUGIN_OK

    def run(self, arg):
        ida_kernwin.process_ui_action(ACTION_DUMP_AUTO)

    def term(self):
        unregister_actions()

def PLUGIN_ENTRY():
    return hx_dump_plugin_t()
