# lsass-dump-toolkit

A toolkit for diagnosing and repairing `lsass.exe` dumps captured from a **full
physical RAM image** or by other means that do not page in evicted pages. Such
dumps often cannot be processed by `pypykatz` / `mimikatz` — the tool fails with
`LSA signature not found! / All detection methods failed`.

### Contents

| Script | Purpose |
|--------|---------|
| **`fix_lsass_minidump.py`** | Diagnose (`--check`) and repair a **ready-made minidump** (MDMP), carved out e.g. via [MemProcFS](https://github.com/ufrisk/MemProcFS). Restores zeroed file-backed module pages from the original DLLs. |
| **`binmap_to_minidump.py`** | Assemble a real minidump from a **raw `bin`+`map` dump** (memory regions + a text map of `va length file_offset`). Performs the same code backfill along the way. |

Both scripts address the same root cause (see below), just on different input
formats; the code-backfill logic is shared.

---

## TL;DR

```bash
# 1. Diagnose: what is damaged and which DLLs you need to pull from the target.
#    Writes nothing, does not touch the original. No DLL file required.
python3 fix_lsass_minidump.py dump.dmp --check

# 2. Repair: overlays the bytes of the original DLLs onto the zeroed pages.
#    Writes to a NEW file, the source is left unchanged.
python3 fix_lsass_minidump.py dump.dmp fixed.dmp \
    --module lsasrv.dll:/path/to/lsasrv.dll

# 3. Profit:
pypykatz lsa minidump fixed.dmp
```

And if the input is a raw `bin`+`map` dump (not a minidump) — assemble and repair
in one go:

```bash
python3 binmap_to_minidump.py dump.bin out.dmp \
    --build 26200 --module lsasrv.dll:/path/to/lsasrv.dll
pypykatz lsa minidump out.dmp
```

---

## The problem

### Symptom

An `lsass` dump captured the normal way (Task Manager → *Create dump file*,
`comsvcs.dll MiniDump`, procdump, etc.) is parsed by `pypykatz` without issues.
But a minidump of **the same machine**, obtained from a physical RAM image via
MemProcFS, is not:

```
Exception: LSA signature not found!
Exception: All detection methods failed.
```

### Cause

Every Windows process sees a **virtual** address space, but at any given moment
only its "working set" resides in physical RAM. When memory runs low, pages are
evicted — and the page type decides where they go:

* **Private/"dirty" pages** (heap, stack, modified data) — the only copy of their
  contents is in memory, so on eviction the OS **writes them to `pagefile.sys`**.
* **"Clean" file-backed pages** (`.text` code and read-only `.rdata` of loaded
  DLLs) — these are just an image mapped from disk. On eviction the OS simply
  **discards them**, writing nothing: an exact copy already lives in the DLL file
  on disk (`C:\Windows\System32\<dll>`). When needed, they are re-read from there.

> Key point: a discarded DLL code page **ends up in neither RAM nor the
> pagefile** — it remains only in the DLL file on disk.

**Why the Task Manager dump is complete.** `MiniDumpWriteDump` runs inside the
live OS and reads the process's virtual memory. Every read of an evicted page
triggers a page fault, and the OS transparently pages it back in (private from
the pagefile, code from disk). The dump comes out coherent and complete.

**Why the RAM-image dump is not.** winpmem/FTK/DumpIt take a passive snapshot of
physical memory: it contains only what **physically resided in RAM** at the
moment of capture. MemProcFS reconstructs `lsass`'s virtual space from that
snapshot; pages that had been evicted (clean DLL code, or whatever went to the
pagefile/compressed Store) cannot be sourced from anywhere — and MemProcFS
returns them as **zeros**.

The LSA signature that `pypykatz` uses to locate the crypto keys lives in the
code of `lsasrv.dll` (`.text`). If its page was evicted → zeroed → the signature
is not found → parsing fails.

### Why Windows 11 specifically

This is **not** a categorical Win10/Win11 difference — the mechanism is the same.
It is a probabilistic question: was the page holding the signature resident in
RAM at the moment of capture. Win11 (especially 24H2/25H2, builds 26100/26200),
through more aggressive memory compression and working-set trimming, evicts the
"cold" code of an idle `lsass` more often, so in Win11 RAM images the needed
pages are missing noticeably more frequently. The outcome is also affected by the
**capture conditions** (taken right after logon under load vs. on a "settled"
machine) and the **capture tool** itself.

---

## The solution

The lost `.text`/`.rdata` pages are immutable, file-backed code. It can be
**restored byte-for-byte** from the same DLL version taken from the target
machine: on x64 the code is RIP-relative, relocations do not touch `.text`, so
the code in memory is identical to the code on disk (verified: all 323 `.text`
pages of lsasrv.dll matched the reference Task-Manager dump, 0 differences).

The script overlays the disk DLL bytes onto **only the fully zeroed** pages of
the corresponding module in the minidump. Real data (`.data` with the keys, heap)
is left untouched.

After the repair, `pypykatz` finds the signature and extracts the secrets:

```
== MSV ==
    Username: user
    NT: 57d583aa46d571502aad4bb7aea09c70   # matches the reference dump
== DPAPI ==
    masterkey ...
```

---

## Usage

### Diagnostics (`--check`)

Only counts the zeroed pages, **writes nothing**, **needs no DLL file** (the
section table is read from the PE header right inside the dump).

```bash
# Auto-scan of all known credential modules:
python3 fix_lsass_minidump.py dump.dmp --check

# Specific modules:
python3 fix_lsass_minidump.py dump.dmp --check \
    --module lsasrv.dll --module kerberos.dll
```

Exit code: `1` — zeroed pages were found, `0` — modules are intact (handy for
scripts and batch checks).

Example output:

```
DIAGNOSE: dump.dmp
  [lsasrv.dll] base=0x... size=0x1b7000 : zero=156 nonzero=283  -> PROBLEM
        .text      zero= 115 nonzero= 208  <-- holes in code
        .rdata     zero=  28 nonzero=  52  <-- holes in code
        .data      zero=   0 nonzero=  10
  [kerberos.dll] base=0x... : zero=335 nonzero=24 -> PROBLEM  [PE header zeroed, sections not parseable]
  ...
PULL FROM THE MACHINE (file-backed code damaged, original DLL needed):
   - lsasrv.dll
   - kerberos.dll
   ...
Then repair:  python3 fix_lsass_minidump.py <in> <out> --module lsasrv.dll:/path/lsasrv.dll ...
```

The script prints a ready-to-paste repair command with the required modules.

### Repair

```bash
python3 fix_lsass_minidump.py <in.dmp> <out.dmp> \
    --module lsasrv.dll:/path/to/lsasrv.dll \
    [--module kerberos.dll:/path/to/kerberos.dll] \
    [--module msv1_0.dll:/path/to/msv1_0.dll] ...
```

* `<in.dmp>` — the source minidump (opened **read-only**).
* `<out.dmp>` — the output file (created as a copy of the source; the copy is
  patched).
* `--module NAME:PATH` — a module and the path to the original DLL of **the same
  version** from the target machine. Repeatable.

### Where to get the original DLLs

The files live on the target machine in `C:\Windows\System32\`. **The version
must match exactly** the dump. If the version is wrong the script will still run,
but it will overlay foreign code and the parse will be incorrect. You can verify
the match indirectly: after the repair, `--check` of the target module should
return `OK`, and `pypykatz` — a meaningful result.

---

## Known modules (auto-scan)

`--check` without `--module` scans the modules where `pypykatz`/`mimikatz` look
for signatures and read secrets:

| DLL | What it carries |
|-----|-----------------|
| `lsasrv.dll`  | MSV/NTLM, LSA keys, DPAPI, credman |
| `wdigest.dll` | WDigest (plaintext, if enabled) |
| `kerberos.dll`| Kerberos (tickets, keys) |
| `msv1_0.dll`  | MSV / SSP |
| `tspkg.dll`   | TsPkg (RDP) |
| `livessp.dll` | LiveSSP |
| `cloudap.dll` | CloudAP (Azure AD / PRT) |
| `dpapisrv.dll`| DPAPI |

---

## Raw `bin`+`map` dumps: `binmap_to_minidump.py`

Some dumpers write the process not as a minidump but in a raw way:

* `<name>.bin` — a bare concatenation of memory-region bytes (no headers);
* `<name>.bin.map` — a text map of lines `va length file_offset`.

`pypykatz`/`mimikatz` do not understand this format. `binmap_to_minidump.py`
assembles a real minidump (MDMP) from this pair, synthesizing the minimal
required streams:

* **SystemInfoStream** — architecture and `BuildNumber` (needed to pick the
  structure template; set via the `--build` flag);
* **ModuleListStream** — the module list (needed to find `lsasrv.dll` and others).
  The name is taken from the export table, and if that is zeroed/truncated — by an
  exact `SizeOfImage` match against the DLLs passed via `--module`;
* **Memory64ListStream** — the memory map (`va` → data), built from the `.map`.

Why the `.map` is needed: the `.bin` has neither headers nor addresses — it is
just a glued-together set of memory chunks. The map is a translation table
"virtual address ↔ file offset", a direct analogue of the `Memory64List` stream
inside a minidump. Without it the `.bin` bytes are meaningless for address-based
parsing.

While assembling, the script performs **the same code backfill** as
`fix_lsass_minidump.py`: the zeroed file-backed pages of the specified modules
are filled with the bytes of the original DLLs.

### Usage

```bash
python3 binmap_to_minidump.py dump.bin out.dmp \
    --build 26200 \
    --module lsasrv.dll:/path/to/lsasrv.dll \
    [--module kerberos.dll:/path/to/kerberos.dll] ...

pypykatz lsa minidump out.dmp
```

* `dump.bin` — the raw dump; the map is looked up as `dump.bin.map` or `dump.map`.
* `--build` — the `BuildNumber` of the target OS (e.g. `26200` for Win11 25H2).
* `--module NAME:PATH` — a DLL for the code backfill and for reliably naming the
  module by `SizeOfImage`. Repeatable. To extract NTLM `lsasrv.dll` is enough;
  add `kerberos.dll`/`wdigest.dll`/`dpapisrv.dll` etc. for the other providers.

The `.bin` file is copied in full into the output minidump as a memory block —
the source `bin`/`map` are not modified.

---

## Limitations

* **Heap is not restored.** The script only repairs file-backed DLL code. If
  **private heap pages** of `lsass` (where the MSV/Kerberos structures themselves
  and the key material live) were evicted from RAM, their only copy was in
  RAM/pagefile — they are absent in a clean RAM image and cannot be restored from
  a DLL. In practice this looks like: the signature and some secrets (e.g. DPAPI)
  are extracted, but the walk over the logon-session list fails on a "broken"
  pointer from a zeroed heap page. Conclusion: the DLL backfill is a
  **necessary** but not always **sufficient** condition.
* **An exact DLL version is required.** See above.
* **Patching by the "page is fully zero" rule.** The script does not distinguish
  a genuinely missing page from a legitimately zero one. For code (`.text`/
  `.rdata`) this is safe (there are no zero pages there during normal operation,
  and the disk bytes match). The theoretical edge case is a zero page in `.data`
  (zero-initialized data): the script will overwrite it with the disk image. In
  practice the `.data` with the keys is always resident and is not affected.
* **The converter does not add missing data.** `binmap_to_minidump.py` works only
  with what is present in `bin`+`map`. If the dumper saved an incomplete set of
  regions — e.g. it truncated module images and the `.data` section of lsasrv.dll
  (where the keys live) or the heap did not make it into the dump — conversion and
  the code backfill will not help: `.data`/heap are not file-backed, there is
  nowhere to restore them from. It is worth checking completeness before
  conversion: the `.text` **and** `.data` sections of lsasrv.dll must be present
  in the map.

### Practical recommendation

For guaranteed extraction of all credential types (especially Kerberos) it is
better to capture the RAM image while `lsass` is "hot" — right after/during
authentication, when its working set is resident. Different capture tools yield
different completeness even on the same machine.

---

## Dependencies

```bash
pip install minidump        # the same package pypykatz uses
```

Python 3.8+. Requires no external binaries.

---

## How it works (briefly)

**`fix_lsass_minidump.py`** (ready-made minidump):

1. Parses the minidump with the `minidump` package, takes the module list (base,
   size) and the memory-segment table (virtual address ↔ offset in the dump file).
2. For the target module it walks its pages; if a page in the dump is **fully
   zero** — it computes the corresponding RVA → file offset in the disk DLL (via
   the PE section table) and writes the disk bytes into the dump copy.
3. In `--check` mode it writes nothing, only classifies the pages by section and
   builds the list of modules that need to be pulled from the machine.

**`binmap_to_minidump.py`** (raw `bin`+`map`):

1. Reads the map (`va length file_offset`) and scans the regions for PE headers,
   determining the modules (base, `SizeOfImage`, name from the export/by
   `--module`).
2. Backfills the zeroed file-backed module pages from the disk DLLs — right in the
   memory block of the future minidump (by the same logic as
   `fix_lsass_minidump.py`).
3. Writes the minidump: the MDMP header, the `SystemInfo`/`ModuleList`/
   `Memory64List` streams and the memory block itself (the contents of `.bin` in
   map order).

---

## Context

The tool was built as part of research into offensive work with `lsass.exe` dumps
across different OSes. A detailed breakdown of the cause (with byte-for-byte
evidence) is in the research history; here is the working result and the utility.
