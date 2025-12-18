#!/usr/bin/env python3
"""Scan a Windows DLL for imported dependencies and check whether they're present on the system.
Usage: python scripts/scan_dll_deps.py <path/to/Matryoshka.dll>
Requires: pip install pefile
"""
import os
import sys

try:
    import pefile
except Exception:
    print("pefile is required. Install with: python -m pip install pefile")
    sys.exit(2)

if len(sys.argv) < 2:
    print("Usage: python scripts/scan_dll_deps.py <path/to/Matryoshka.dll>")
    sys.exit(2)

dll = sys.argv[1]
if not os.path.exists(dll):
    print("DLL not found:", dll)
    sys.exit(2)

search_paths = []
# DLL directory first
dll_dir = os.path.dirname(os.path.abspath(dll))
search_paths.append(dll_dir)
# System directories
systemroot = os.environ.get('SYSTEMROOT', r'C:\Windows')
search_paths.append(os.path.join(systemroot, 'System32'))
search_paths.append(os.path.join(systemroot, 'SysWOW64'))
# PATH entries
for p in os.environ.get('PATH', '').split(os.pathsep):
    if p and p not in search_paths:
        search_paths.append(p)

print('Scanning imports for:', dll)
print('Searching in (sample):', search_paths[:6])

pe = pefile.PE(dll)
imports = []
if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        name = entry.dll.decode('utf-8', errors='replace')
        imports.append(name)

if not imports:
    print('No import table entries found (DLL may be static or stripped).')
    sys.exit(0)

missing = []
for name in imports:
    found = False
    for d in search_paths:
        candidate = os.path.join(d, name)
        if os.path.exists(candidate):
            found = True
            break
    print(f"{name}: {'FOUND' if found else 'MISSING'}")
    if not found:
        missing.append(name)

if missing:
    print('\nMissing dependencies detected:')
    for m in missing:
        print(' -', m)
    print('\nNext steps:')
    print(' - Install the Visual C++ Redistributable (2015-2022 x64) if you see MSVCP*.DLL or VCRUNTIME*.DLL missing.')
    print(' - If other runtime DLLs are missing (OpenSSL, libcrypto, etc.), install them or place the DLLs next to the target DLL.')
    print(" - You can use the 'Dependencies' GUI (https://github.com/lucasg/Dependencies) for a graphical view.")
else:
    print('\nAll imported DLLs appear present on disk in PATH or system folders.\nIf load still fails, the issue may be:')
    print(' - Architecture mismatch (32-bit vs 64-bit).')
    print(' - A missing implicit dependency of one of the imported DLLs (run Dependencies to see nested missing entries).')
    print(' - PATH or permission issues for the process that will load the DLL.')

print('\nDone')
