#!/usr/bin/env python3
"""Small helper that attempts to load a DLL and prints diagnostics.
Usage: python scripts/test_dll_load.py <path/to/Matryoshka.dll>
"""
import sys
import os
import ctypes
import platform
import getpass

if len(sys.argv) > 1:
    dll_path = sys.argv[1]
else:
    print("Usage: python scripts/test_dll_load.py <path/to/Matryoshka.dll>")
    sys.exit(2)

print("Python:", sys.version.splitlines()[0])
print("Platform:", platform.platform(), platform.architecture())
print("PID:", os.getpid(), "CWD:", os.getcwd(), "User:", getpass.getuser())
print("DLL path:", dll_path)
print("Exists:", os.path.exists(dll_path))
print("DLL dir in PATH:", os.path.dirname(dll_path) in os.environ.get('PATH',''))
try:
    print("Attempting ctypes.CDLL...")
    lib = ctypes.CDLL(dll_path)
    print("ctypes.CDLL loaded, handle=", getattr(lib, '_handle', None))
except Exception as e:
    print("ctypes.CDLL failed:", repr(e))

try:
    print("Attempting ctypes.WinDLL...")
    lib2 = ctypes.WinDLL(dll_path)
    print("ctypes.WinDLL loaded, handle=", getattr(lib2, '_handle', None))
except Exception as e:
    print("ctypes.WinDLL failed:", repr(e))

try:
    # Try kernel32 LoadLibraryExW to get a Win32 error code
    kernel32 = ctypes.WinDLL('kernel32')
    kernel32.LoadLibraryExW.argtypes = [ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_uint32]
    kernel32.LoadLibraryExW.restype = ctypes.c_void_p
    h = kernel32.LoadLibraryExW(dll_path, None, 0x00000008)
    if not h:
        err = kernel32.GetLastError()
        print('LoadLibraryExW returned NULL, GetLastError=', err)
    else:
        print('LoadLibraryExW succeeded, handle=', h)
except Exception as e:
    print('LoadLibraryExW attempt failed:', repr(e))

# Try auto add_dll_directory then load
try:
    if hasattr(os, 'add_dll_directory'):
        print('Attempting os.add_dll_directory and retry')
        ad = os.add_dll_directory(os.path.dirname(dll_path))
        try:
            lib3 = ctypes.CDLL(dll_path)
            print('ctypes.CDLL loaded after add_dll_directory, handle=', getattr(lib3,'_handle',None))
        except Exception as e:
            print('Still failed after add_dll_directory:', repr(e))
        try:
            ad.close()
        except Exception:
            pass
except Exception as e:
    print('add_dll_directory attempt failed:', repr(e))

print('Done')
