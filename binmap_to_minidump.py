#!/usr/bin/env python3
"""
binmap_to_minidump.py — собрать настоящий minidump (MDMP) из сырого дампа
вида <name>.bin + <name>.bin.map (регионы памяти + текстовая карта
"va length file_offset"), попутно восстановив занулённые file-backed
страницы модулей из оригинальных DLL (как fix_lsass_minidump.py).

Зачем: pypykatz/mimikatz понимают только формат minidump. Сырой bin+map
ему не скормить. Скрипт синтезирует минимально необходимые потоки:
  * SystemInfoStream  — архитектура + BuildNumber (нужен для выбора шаблона);
  * ModuleListStream  — список модулей (нужен, чтобы найти lsasrv.dll и др.);
  * Memory64ListStream — карта памяти (va -> данные).

Имя модуля берётся из таблицы экспорта, а если она занулена/обрезана —
по точному совпадению SizeOfImage с известными credential-DLL.

Использование:
    python3 binmap_to_minidump.py dump.bin out.dmp \
        --build 26200 \
        [--module lsasrv.dll:/path/to/lsasrv.dll] ...   # бэкфилл кода (опц.)

Карта ищется как <bin>.map либо <bin без .bin>.map.
"""
import argparse
import os
import struct
import sys

# Известные credential-DLL по SizeOfImage (для именования при битом экспорте).
KNOWN_BY_SIZEOFIMAGE = {}  # заполняется из --module и эвристики ниже

ARCH_AMD64 = 9


def load_map(map_path):
    regions = []
    for ln in open(map_path):
        ln = ln.strip()
        if not ln or ln.startswith('#'):
            continue
        va, length, off = ln.split()
        regions.append((int(va, 16), int(length), int(off)))
    return regions


def pe_disk_sections(buf):
    e = struct.unpack_from('<I', buf, 0x3c)[0]
    numsec = struct.unpack_from('<H', buf, e + 6)[0]
    szopt = struct.unpack_from('<H', buf, e + 20)[0]
    so = e + 24 + szopt
    secs = []
    for i in range(numsec):
        o = so + i * 40
        vsz = struct.unpack_from('<I', buf, o + 8)[0]
        va = struct.unpack_from('<I', buf, o + 12)[0]
        rawsz = struct.unpack_from('<I', buf, o + 16)[0]
        rawptr = struct.unpack_from('<I', buf, o + 20)[0]
        secs.append((va, vsz, rawsz, rawptr))
    return secs


def rva_to_off(secs, rva):
    for va, vsz, rawsz, rawptr in secs:
        if va <= rva < va + max(vsz, rawsz):
            d = rva - va
            return rawptr + d if d < rawsz else None
    return None


def export_name(blob, regoff, reglen, regions, base):
    """Имя модуля из таблицы экспорта (с VA-резолвом через карту)."""
    h = blob[regoff:regoff + 0x1000]
    if h[:2] != b'MZ':
        return None
    try:
        e = struct.unpack_from('<I', h, 0x3c)[0]
        if h[e:e + 4] != b'PE\x00\x00':
            return None
        magic = struct.unpack_from('<H', h, e + 24)[0]
        ddoff = e + 24 + (112 if magic == 0x20b else 96)
        exp_rva = struct.unpack_from('<I', h, ddoff)[0]
        if not exp_rva:
            return None
        name_rva = struct.unpack_from('<I', read_va(blob, regions, base + exp_rva + 12, 4), 0)[0]
        nm = read_va(blob, regions, base + name_rva, 64).split(b'\x00')[0]
        return nm.decode('latin1', 'replace') if nm else None
    except Exception:
        return None


def read_va(blob, regions, va, n):
    res = bytearray(); cur = va; rem = n
    while rem > 0:
        hit = next(((rva, l, off) for rva, l, off in regions if rva <= cur < rva + l), None)
        if not hit:
            break
        rva, l, off = hit
        can = min(rem, (rva + l) - cur)
        res += blob[off + (cur - rva): off + (cur - rva) + can]
        cur += can; rem -= can
    return bytes(res)


def find_modules(blob, regions, name_overrides):
    """Вернуть список (base, size_of_image, name) для всех MZ-регионов."""
    mods = []
    for va, l, off in regions:
        if blob[off:off + 2] != b'MZ':
            continue
        h = blob[off:off + 0x1000]
        e = struct.unpack_from('<I', h, 0x3c)[0]
        if h[e:e + 4] != b'PE\x00\x00':
            continue
        si = struct.unpack_from('<I', h, e + 24 + 56)[0]
        # Явно заданное имя (--module по SizeOfImage) авторитетнее экспорта.
        nm = name_overrides.get(si)
        if not nm:
            nm = export_name(blob, off, l, regions, va)
        # отбраковка мусора: имя модуля должно оканчиваться на .dll/.exe
        if not nm or not nm.lower().endswith(('.dll', '.exe')):
            nm = name_overrides.get(si) or ('mod_%x.dll' % va)
        mods.append((va, si, nm))
    return mods


def backfill(blob, regions, base, size, dll_path):
    """Залить занулённые file-backed страницы модуля байтами с диска. Возвращает счётчик."""
    dll = open(dll_path, 'rb').read()
    secs = pe_disk_sections(dll)
    patched = 0
    # карта va -> позиция в blob
    for rva in range(0, size, 0x1000):
        va = base + rva
        hit = next(((r, l, off) for r, l, off in regions if r <= va < r + l), None)
        if not hit:
            continue
        r, l, off = hit
        pos = off + (va - r)
        page = blob[pos:pos + 0x1000]
        if page and any(b != 0 for b in page):
            continue
        fo = rva_to_off(secs, rva)
        if fo is None:
            continue
        disk = dll[fo:fo + 0x1000]
        if not disk or all(b == 0 for b in disk):
            continue
        if len(disk) < 0x1000:
            disk = disk + bytes(0x1000 - len(disk))
        blob[pos:pos + 0x1000] = disk
        patched += 1
    return patched


def mdmp_string(s):
    u = s.encode('utf-16-le')
    return struct.pack('<I', len(u)) + u + b'\x00\x00'


def build(bin_path, out_path, build_number, modules_to_fix):
    map_path = bin_path + '.map'
    if not os.path.exists(map_path):
        map_path = os.path.splitext(bin_path)[0] + '.map'
    regions = load_map(map_path)
    blob = bytearray(open(bin_path, 'rb').read())

    # 1) Бэкфилл кода модулей (если заданы --module).
    name_overrides = {}
    for nm, path in modules_to_fix:
        si = struct.unpack_from('<I', open(path, 'rb').read(0x100)[0x3c:0x40], 0)[0]
        # точный SizeOfImage берём из PE на диске
        d = open(path, 'rb').read()
        e = struct.unpack_from('<I', d, 0x3c)[0]
        si = struct.unpack_from('<I', d, e + 24 + 56)[0]
        name_overrides[si] = nm

    mods = find_modules(blob, regions, name_overrides)

    for nm, path in modules_to_fix:
        d = open(path, 'rb').read()
        e = struct.unpack_from('<I', d, 0x3c)[0]
        si = struct.unpack_from('<I', d, e + 24 + 56)[0]
        target = [m for m in mods if m[1] == si]
        if not target:
            print('  [!] модуль %s (SizeOfImage=0x%x) не найден в дампе' % (nm, si))
            continue
        base = target[0][0]
        n = backfill(blob, regions, base, si, path)
        print('  [backfill] %s @0x%x : восстановлено %d страниц' % (nm, base, n))

    # 2) Сборка minidump.
    STREAM_SYSINFO, STREAM_MODULELIST, STREAM_MEM64 = 7, 4, 9
    out = bytearray()

    # резерв под header(32) + directory(3*12)
    HEADER = 32
    NDIR = 3
    dir_off = HEADER
    body_off = HEADER + NDIR * 12
    out += b'\x00' * body_off

    def append(data):
        rva = len(out)
        out.extend(data)
        return rva

    # CSDVersion (пустая строка) для SystemInfo
    csd_rva = append(mdmp_string(''))

    # SystemInfo
    sysinfo = struct.pack('<HHHBB', ARCH_AMD64, 0, 0, 1, 1)  # arch, level, rev, #cpu, producttype
    sysinfo += struct.pack('<III', 10, 0, build_number)       # major, minor, build
    sysinfo += struct.pack('<I', 2)                            # PlatformId = VER_PLATFORM_WIN32_NT
    sysinfo += struct.pack('<I', csd_rva)                      # CSDVersionRva
    sysinfo += struct.pack('<HH', 0, 0)                        # SuiteMask, Reserved2
    sysinfo += struct.pack('<III', 0, 0, 0)                    # CPU info union (VendorId)
    sysinfo += struct.pack('<I', 0)                            # VersionInformation
    sysinfo += struct.pack('<I', 0)                            # FeatureInformation
    sysinfo += struct.pack('<I', 0)                            # AMDExtendedCpuFeatures
    sysinfo_rva = append(sysinfo)
    sysinfo_size = len(out) - sysinfo_rva

    # Имена модулей
    name_rvas = []
    for base, si, nm in mods:
        name_rvas.append(append(mdmp_string(nm)))

    # ModuleList
    modlist = struct.pack('<I', len(mods))
    for (base, si, nm), nrva in zip(mods, name_rvas):
        modlist += struct.pack('<Q', base)        # BaseOfImage
        modlist += struct.pack('<I', si)          # SizeOfImage
        modlist += struct.pack('<I', 0)           # CheckSum
        modlist += struct.pack('<I', 0)           # TimeDateStamp
        modlist += struct.pack('<I', nrva)        # ModuleNameRva
        modlist += b'\x00' * 52                   # VS_FIXEDFILEINFO
        modlist += struct.pack('<II', 0, 0)       # CvRecord
        modlist += struct.pack('<II', 0, 0)       # MiscRecord
        modlist += struct.pack('<QQ', 0, 0)       # Reserved0/1
    modlist_rva = append(modlist)
    modlist_size = len(out) - modlist_rva

    # Memory64List: header + descriptors, затем сам blob.
    ndesc = len(regions)
    mem64_hdr_rva = len(out)
    # NumberOfMemoryRanges (u64), BaseRva (u64), descriptors (16 each)
    desc_blob = b''.join(struct.pack('<QQ', va, length) for va, length, off in regions)
    base_rva = mem64_hdr_rva + 16 + len(desc_blob)
    mem64 = struct.pack('<QQ', ndesc, base_rva) + desc_blob
    append(mem64)
    # сам blob памяти — ровно содержимое .bin (порядок дескрипторов = порядок карты)
    append(bytes(blob))
    mem64_size = 16 + len(desc_blob)  # DataSize потока = только header+descriptors

    # Header
    struct.pack_into('<4sIIIIIQ', out, 0,
                     b'MDMP', 0xa793, NDIR, dir_off, 0, 0, 0)
    # Directory
    entries = [
        (STREAM_SYSINFO, sysinfo_size, sysinfo_rva),
        (STREAM_MODULELIST, modlist_size, modlist_rva),
        (STREAM_MEM64, mem64_size, mem64_hdr_rva),
    ]
    for i, (t, sz, rva) in enumerate(entries):
        struct.pack_into('<III', out, dir_off + i * 12, t, sz, rva)

    open(out_path, 'wb').write(out)
    print('  собран minidump: %s  (%d модулей, %d регионов, %d байт)'
          % (out_path, len(mods), ndesc, len(out)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('bin')
    ap.add_argument('out')
    ap.add_argument('--build', type=int, required=True, help='Windows BuildNumber (напр. 26200)')
    ap.add_argument('--module', action='append', default=[], metavar='NAME:PATH',
                    help='бэкфилл кода модуля из оригинальной DLL (повторяемо)')
    args = ap.parse_args()
    mods = []
    for spec in args.module:
        nm, path = spec.split(':', 1)
        mods.append((nm, path))
    build(args.bin, args.out, args.build, mods)


if __name__ == '__main__':
    main()
