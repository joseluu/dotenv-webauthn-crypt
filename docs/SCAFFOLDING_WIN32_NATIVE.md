# Scaffolding a Native Win32 C++ Application

This document summarizes the toolchain, build setup, and key techniques used to
build **light_mp3** — a native Windows GUI application written in C++ with no
frameworks, no CMake, and no runtime dependencies beyond Windows itself.

## Toolchain

| Component | Version / Path |
|---|---|
| Compiler | MSVC `cl.exe` 14.43.34808 (C++ 17) |
| Linker | MSVC `link.exe` (same version) |
| Resource Compiler | Windows SDK `rc.exe` |
| Toolchain install | VS 2022 **Build Tools** — `C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/14.43.34808` |
| Windows SDK | 10.0.22621.0 — `C:/Program Files (x86)/Windows Kits/10` |
| Shell | Git Bash (MINGW64) — all build commands run here |

### Why Build Tools, not Visual Studio IDE?

VS 2022 Community was installed but had **no C++ compiler** (only clang-format).
The **Build Tools** edition provides the full MSVC toolchain (`cl.exe`,
`link.exe`, headers, libs) without the IDE overhead. You can install it from
https://visualstudio.microsoft.com/visual-cpp-build-tools/ — select the
"Desktop development with C++" workload.

## Build System: `build.sh` (no make/cmake)

The entire build is a single Bash script with three steps:

```
bash build.sh          # → build/light_mp3.exe
```

### Step 1 — Resource Compilation

```bash
MSYS_NO_PATHCONV=1 "$RC" /nologo /I"..." /fo build/app.res res/app.rc
```

- `rc.exe` compiles the `.rc` resource script that embeds the application
  manifest (ComCtl32 v6, DPI awareness) and the application icon.
- **`MSYS_NO_PATHCONV=1`** is critical: Git Bash converts `/fo` to a Unix path
  without it.

### Step 2 — C++ Compilation

```bash
"$CL" "@build/compile.rsp"
```

A **response file** (`compile.rsp`) lists all flags and source files, one per
line. This avoids shell quoting problems with paths that contain spaces
(e.g. `Program Files (x86)`).

Key flags:
- `/c` — compile only, no link (link is a separate step)
- `/std:c++17 /EHsc /O2 /W3`
- `/DUNICODE /D_UNICODE` — wide-char Win32 API
- `/I"..."` — include paths for MSVC headers, UCRT, Windows SDK um/shared

**Important**: the `/link` separator does **not** work inside response files.
Compile and link must be separate invocations.

### Step 3 — Linking

```bash
"$LINK" "@build/link.rsp"
```

The link response file specifies:
- `/SUBSYSTEM:WINDOWS` — GUI application (no console window)
- `/LIBPATH:` for MSVC libs, UCRT libs, and Windows SDK um libs
- Object files and `.res` file
- Required Win32 libraries (see below)

### Win32 Libraries Used

| Library | Purpose |
|---|---|
| `user32.lib` | Window creation, message loop, controls |
| `gdi32.lib` | Device contexts, basic drawing |
| `gdiplus.lib` | Image decoding (JPEG/PNG cover art) |
| `winmm.lib` | `waveOut*` PCM audio playback |
| `comctl32.lib` | ListView, Trackbar (common controls) |
| `comdlg32.lib` | `GetOpenFileNameW` file picker dialog |
| `ole32.lib` | `CreateStreamOnHGlobal` (IStream for GDI+) |
| `shell32.lib` | `DragQueryFileW` (drag-and-drop), `CommandLineToArgvW` |

## Key Win32 Patterns

### Application Manifest (`res/app.manifest`)

Embedded as `RT_MANIFEST` resource via `app.rc`. Enables:
- **ComCtl32 v6** — modern-looking controls (buttons, ListView, Trackbar)
- **DPI awareness** — crisp rendering on high-DPI displays

```rc
1 RT_MANIFEST "app.manifest"
100 ICON "app.ico"
```

### Window Procedure Architecture

Single `MainWndProc` handles all messages. Child windows for specialized
rendering (e.g. `CoverArtClass` with its own `WndProc` for flicker-free
cover art painting via `WM_ERASEBKGND` returning 1).

### Custom Messages

- `WM_PLAYER_DONE` (`WM_APP + 1`) — posted by the audio callback when
  playback reaches the end of the PCM buffer.

### Audio: waveOut with Buffer Rotation

4 buffers of 4096 samples each. `CALLBACK_FUNCTION` mode — the audio thread
calls `WaveOutProc` on `WOM_DONE`, which refills and resubmits the buffer.

Critical race-condition pattern: always set `m_playing = false` **before**
calling `waveOutReset()`, because the reset fires `WOM_DONE` callbacks
synchronously on the calling thread.

### Cover Art: GDI+ via IStream

Raw JPEG/PNG bytes from ID3v2 APIC frames are loaded into an `HGLOBAL`,
wrapped with `CreateStreamOnHGlobal`, and passed to `Gdiplus::Bitmap`.
GDI+ handles format detection and decoding internally.

### Text Rendering and Controls

All Win32 API calls use the `W` (wide-char) variants. `UNICODE` and
`_UNICODE` are defined at compile time so `TCHAR` maps to `wchar_t`.

## Third-Party Dependencies

| Library | License | Integration |
|---|---|---|
| [minimp3](https://github.com/lieff/minimp3) | Public domain (CC0) | Header-only (`minimp3.h` + `minimp3_ex.h`) copied into `src/` |

This is the **only** external dependency. Everything else is Windows SDK.

## Gotchas and Lessons Learned

1. **Git Bash path conversion** — MSYS automatically converts `/flag` to
   `C:/msys64/flag`. Use `MSYS_NO_PATHCONV=1` for commands with `/` flags.

2. **Response files** — essential when calling MSVC tools from Git Bash with
   paths containing spaces. One argument per line, no quoting needed inside.

3. **`/link` in response files** — does not work. `cl.exe` ignores everything
   after `/link` in a `.rsp` file. Split compile and link into separate steps.

4. **MCI and DirectShow** — both require optional Windows components for MP3
   playback. Embedding a decoder (minimp3) eliminates codec dependencies.

5. **waveOut callback races** — `waveOutReset()` fires `WOM_DONE` callbacks
   synchronously. Guard with a flag (`m_playing = false`) before calling it.

6. **Stop must close the device** — calling `waveOutReset()` alone leaves
   buffers prepared and the device open. Always unprepare headers and call
   `waveOutClose()` in `Stop()`.

## Reproducing This Setup

1. Install [VS Build Tools 2022](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
   with the "Desktop development with C++" workload.
2. Install [Git for Windows](https://gitforwindows.org/) (provides Git Bash).
3. Clone the repo and run `bash build.sh`.
4. Output: `build/light_mp3.exe` — a single self-contained executable.
