# Hex-Rays Pseudocode Dumper (IDA Plugin)

Concatenate Hex-Rays pseudocode for **non-library** (and non-thunk) functions into a single text.
The result is **always copied to the clipboard** and can be **optionally saved as a `.c` file**  
(the “Save to .c” toggle is **OFF by default**).

> ✅ Compatible with **IDA 7.x / 8.x / 9.x** + **Hex-Rays** (any supported architecture)

---

## Features

- Skips **library** functions and **thunks** by default
- Collects Hex-Rays pseudocode (color tags removed), concatenated in call-order
- **Clipboard first**: always copies the final text to the clipboard
- Optional **“.c” output** next to your IDB, or to a chosen path
- One-key workflow: **Alt+Shift+D** (uses the current toggle)
- Small, pure-Python plugin — easy to tweak

---

## Actions & Hotkeys

- **Dump Hex-Rays pseudocode (auto save setting)** — `Alt+Shift+D`  
  Copies to clipboard; saves a `.c` file only if the *Save to .c* toggle is ON.

- **Dump Hex-Rays pseudocode (save next to IDB)**  
  Forces saving `<idb_basename>_decomp_all.c` next to your IDB (also copies to clipboard).

- **Dump Hex-Rays pseudocode… (choose file)**  
  Prompts for an output path (also copies to clipboard).

- **Toggle "Save to .c" (next to IDB)**  
  Switches the auto-save behavior **ON/OFF** (default **OFF**, not persisted across sessions).

---

## Installation

1. Save the plugin file as: dump_hexrays_pseudocode.py
2. Drop it into your IDA **plugins** folder, e.g.:
- **Windows**:  
  `C:\Program Files\IDA\plugins\` or `%APPDATA%\Hex-Rays\IDA Pro\plugins\`
- **Linux/macOS**:  
  `~/.idapro/plugins/` or your IDA install’s `plugins/` directory
3. Restart IDA.

You’ll find the actions under **Edit** (or **Edit → Plugins** depending on IDA version).

---

## Requirements

- IDA 7/8/9
- Hex-Rays decompiler for the target architecture
- For OS clipboard fallbacks (optional):
- Windows: built-in `clip`
- macOS: `pbcopy`
- Linux: `wl-copy` (Wayland) or `xclip` (X11)

The plugin uses IDA’s internal clipboard API first; OS tools are only a fallback.

---

## Usage

- Press **Alt+Shift+D** to dump to **clipboard** (no file by default).
- Toggle **Save to .c** when you want automatic saving next to the IDB.
- Or call the explicit actions to force saving either next to the IDB or to a chosen file.

Output headers look like:
```c
/*******************************************************************************/
/*** function_name @ 0x401234 ***/
