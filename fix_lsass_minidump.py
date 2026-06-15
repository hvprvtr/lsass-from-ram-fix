#!/usr/bin/env python3
"""
fix_lsass_minidump.py — backfill zero-filled module pages in an lsass minidump.

Назначение
----------
Минидампы lsass, вырезанные из ПОЛНОГО образа RAM (winpmem / FTK Imager /
DumpIt) через MemProcFS, содержат зануленные страницы в секциях кода (.text)
и .rdata модулей: «чистые» file-backed страницы DLL, вытесненные из рабочего
набора, отсутствуют в физической RAM и не пишутся в pagefile (их можно
перечитать с диска). MemProcFS отдаёт такие страницы нулями.

pypykatz из-за этого не находит байтовую сигнатуру LSA в .text lsasrv.dll и
падает с "LSA signature not found! / All detection methods failed."

Скрипт берёт ОРИГИНАЛЬНЫЙ файл DLL с той же машины и накладывает его байты на
зануленные страницы соответствующего модуля в минидампе. .text/.rdata
file-backed и в памяти идентичны диску (x64 RIP-relative код, релокации .text
не затрагивают), поэтому наложение корректно. Реальные данные (включая .data
с crypto-ключами и heap) НЕ трогаются — патчатся только страницы, которые в
дампе целиком нулевые.

Ограничение: heap-страницы lsass (где лежат сами структуры MSV/Kerberos и
ключевой материал) НЕ file-backed. Если они были выгружены из RAM на момент
снятия образа — восстановить их этим способом нельзя, данные отсутствуют в
самой выгрузке. Делайте образ RAM так, чтобы рабочий набор lsass был резидентен.

Использование
-------------
    python3 fix_lsass_minidump.py <minidump_in> <minidump_out> \
        --module lsasrv.dll:<path_to_disk_lsasrv.dll> \
        [--module kerberos.dll:<path>] [--module msv1_0.dll:<path>] ...

Модуль сопоставляется по имени (без учёта регистра) со списком модулей дампа,
база и размер берутся оттуда.
"""
import argparse
import os
import shutil
import struct
import sys

from minidump.minidumpfile import MinidumpFile


def pe_sections(buf):
    """Вернуть список секций (va, vsize, rawsize, rawptr) из PE-образа на диске."""
    e_lfanew = struct.unpack_from('<I', buf, 0x3c)[0]
    if buf[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
        raise ValueError('not a PE file')
    numsec = struct.unpack_from('<H', buf, e_lfanew + 6)[0]
    sizeopt = struct.unpack_from('<H', buf, e_lfanew + 20)[0]
    sectab = e_lfanew + 24 + sizeopt
    secs = []
    for i in range(numsec):
        o = sectab + i * 40
        vsz = struct.unpack_from('<I', buf, o + 8)[0]
        va = struct.unpack_from('<I', buf, o + 12)[0]
        rawsz = struct.unpack_from('<I', buf, o + 16)[0]
        rawptr = struct.unpack_from('<I', buf, o + 20)[0]
        secs.append((va, vsz, rawsz, rawptr))
    return secs


def rva_to_off(secs, rva):
    """RVA -> файловое смещение в дисковом образе, либо None (нет raw-данных)."""
    for va, vsz, rawsz, rawptr in secs:
        if va <= rva < va + max(vsz, rawsz):
            delta = rva - va
            return rawptr + delta if delta < rawsz else None
    return None


# Модули, в которых pypykatz/mimikatz ищет сигнатуры и читает секреты.
# Если у такого модуля занулены кодовые страницы — его, возможно, придётся
# достать с целевой машины для реконструкции дампа.
CRED_DLLS = [
    'lsasrv.dll',    # MSV/NTLM, LSA-ключи, DPAPI, credman
    'wdigest.dll',   # WDigest
    'kerberos.dll',  # Kerberos
    'msv1_0.dll',    # MSV/SSP
    'tspkg.dll',     # TsPkg (RDP)
    'livessp.dll',   # LiveSSP
    'cloudap.dll',   # CloudAP (Azure AD / PRT)
    'dpapisrv.dll',  # DPAPI
]


def sections_from_dump(reader, base):
    """Прочитать таблицу секций PE прямо из памяти модуля в дампе (без файла на диске)."""
    mz = reader.read(base, 0x1000)
    if not mz or mz[:2] != b'MZ':
        return None
    e_lfanew = struct.unpack_from('<I', mz, 0x3c)[0]
    pe = reader.read(base + e_lfanew, 0x400)
    if not pe or pe[:4] != b'PE\x00\x00':
        return None
    numsec = struct.unpack_from('<H', pe, 6)[0]
    sizeopt = struct.unpack_from('<H', pe, 20)[0]
    sectab = 24 + sizeopt
    secs = []
    for i in range(numsec):
        o = sectab + i * 40
        name = pe[o:o + 8].rstrip(b'\x00').decode('latin1')
        vsz = struct.unpack_from('<I', pe, o + 8)[0]
        va = struct.unpack_from('<I', pe, o + 12)[0]
        secs.append((name, va, vsz))
    return secs


def diagnose(src, module_names):
    """Только проверка: сколько страниц модуля занулено/отсутствует. Файл не пишется."""
    mf = MinidumpFile.parse(src)
    reader = mf.get_reader()
    print('DIAGNOSE: %s' % src)
    problem = False
    need_fetch = []   # модули с дырами в коде -> их стоит достать с машины
    for name in module_names:
        base, size = find_module(mf, name)
        if base is None:
            print('  [-] %s : в дампе не загружен, пропуск' % name)
            continue
        secs = sections_from_dump(reader, base) or []
        header_ok = bool(secs)   # удалось ли прочитать PE-заголовок из дампа
        bounds = []
        for i, (sname, va, vsz) in enumerate(secs):
            end = secs[i + 1][1] if i + 1 < len(secs) else size
            bounds.append((sname, va & ~0xfff, end))
        def sect_of(rva):
            for sname, s, e in bounds:
                if s <= rva < e:
                    return sname
            return '?'
        per = {}
        z_total = nz_total = 0
        for off in range(0, size, 0x1000):
            b = reader.read(base + off, 0x1000)
            iszero = (not b) or all(x == 0 for x in b)
            sec = sect_of(off)
            d = per.setdefault(sec, [0, 0])
            if iszero:
                d[0] += 1; z_total += 1
            else:
                d[1] += 1; nz_total += 1
        # «дыры в коде» = зануленные страницы в исполняемых/read-only секциях,
        # которые file-backed и восстанавливаются с диска (.text/.rdata/fothk).
        code_holes = sum(z for sname, (z, nz) in per.items()
                         if sname in ('.text', '.rdata', 'fothk'))
        verdict = 'ПРОБЛЕМА' if z_total else 'OK'
        if z_total:
            problem = True
        # Достать DLL нужно, если повреждён file-backed код. Если PE-заголовок
        # сам занулен, секции не классифицировать — но раз страницы пропали,
        # модуль точно повреждён (часто это самый тяжёлый случай).
        if code_holes or (not header_ok and z_total):
            need_fetch.append(name)
        note = '' if header_ok else '  [PE-заголовок занулен, секции не разобрать]'
        print('  [%s] base=0x%x size=0x%x : zero=%d nonzero=%d  -> %s%s'
              % (name, base, size, z_total, nz_total, verdict, note))
        if header_ok:
            for sname, (z, nz) in per.items():
                mark = '  <-- дыры в коде' if (z and sname in ('.text', '.rdata', 'fothk')) else ''
                print('        %-10s zero=%4d nonzero=%4d%s' % (sname, z, nz, mark))
    print('RESULT: %s' % ('зануленные страницы есть — pypykatz, вероятно, не сработает'
                          if problem else 'модули целы'))
    if need_fetch:
        print('ДОСТАТЬ С МАШИНЫ (file-backed код повреждён, нужен оригинал DLL):')
        for n in need_fetch:
            print('   - %s' % n)
        print('Затем чинить:  python3 %s <in> <out> %s'
              % (os.path.basename(sys.argv[0]),
                 ' '.join('--module %s:/путь/%s' % (n, n) for n in need_fetch)))
    return problem


def find_module(mf, name):
    name = name.lower()
    for m in (mf.modules.modules if mf.modules else []):
        if os.path.basename(m.name.replace('\\', '/')).lower() == name:
            return m.baseaddress, m.size
    return None, None


def backfill(src, dst, modules):
    shutil.copyfile(src, dst)
    mf = MinidumpFile.parse(src)
    segs = mf.memory_segments_64.memory_segments if mf.memory_segments_64 else []
    total_patched = 0

    with open(dst, 'r+b') as f:
        for mod_name, dll_path in modules:
            base, size = find_module(mf, mod_name)
            if base is None:
                print('  [!] module %s not found in dump, skipped' % mod_name)
                continue
            dll = open(dll_path, 'rb').read()
            secs = pe_sections(dll)
            patched = skipped = 0
            for s in segs:
                sa, ss, fa = s.start_virtual_address, s.size, s.start_file_address
                if sa + ss <= base or sa >= base + size:
                    continue
                for off in range(0, ss, 0x1000):
                    va = sa + off
                    if va < base or va >= base + size:
                        continue
                    f.seek(fa + off)
                    page = f.read(0x1000)
                    if page and any(b != 0 for b in page):
                        continue  # реальные данные — не трогаем
                    fo = rva_to_off(secs, va - base)
                    if fo is None:
                        skipped += 1
                        continue
                    disk = dll[fo:fo + 0x1000]
                    if not disk or all(b == 0 for b in disk):
                        skipped += 1
                        continue
                    if len(disk) < 0x1000:
                        disk = disk + bytes(0x1000 - len(disk))
                    f.seek(fa + off)
                    f.write(disk)
                    patched += 1
            print('  [%s] base=0x%x size=0x%x : patched %d zero-pages, skipped %d'
                  % (mod_name, base, size, patched, skipped))
            total_patched += patched
    print('  total patched pages: %d -> %s' % (total_patched, dst))


def main():
    ap = argparse.ArgumentParser(description='Backfill zeroed module pages in an lsass minidump.')
    ap.add_argument('src')
    ap.add_argument('dst', nargs='?',
                    help='выходной файл (не нужен при --check)')
    ap.add_argument('--check', action='store_true',
                    help='только диагностика: посчитать зануленные страницы, ничего не писать')
    ap.add_argument('--module', action='append',
                    metavar='NAME[:PATH]',
                    help='lsasrv.dll:/path/to/lsasrv.dll (PATH не нужен при --check; '
                         'при --check без --module сканируются все credential-DLL)')
    args = ap.parse_args()

    if args.check:
        if args.module:
            names = [spec.split(':', 1)[0] for spec in args.module]
        else:
            names = CRED_DLLS  # авто-скан всех известных credential-модулей
        sys.exit(1 if diagnose(args.src, names) else 0)

    if not args.module:
        ap.error('для починки нужен хотя бы один --module NAME:PATH')

    if not args.dst:
        ap.error('нужен выходной файл (dst), либо используйте --check для диагностики')
    mods = []
    for spec in args.module:
        if ':' not in spec:
            ap.error('--module должен быть NAME:PATH (PATH обязателен без --check)')
        name, path = spec.split(':', 1)
        mods.append((name, path))
    backfill(args.src, args.dst, mods)


if __name__ == '__main__':
    main()
