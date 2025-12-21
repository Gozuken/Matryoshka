# 🐛 Critical Bug Report: Access Violation in circuit_builder.py

**Date:** December 21, 2024  
**Reported By:** Security Review  
**Severity:** CRITICAL - Causes crashes  
**File:** `cli/core/circuit_builder.py`

---

## The Problem

When you run the client and try to send a message, it crashes with:
```
[Core Warning] REAL send failed (exception: access violation reading 0x0000000000000008)
```

This happens because of a **classic Python ctypes mistake**: temporary byte strings are being freed while C++ is still using them.

---

## Root Cause

### Location: `circuit_builder.py`, lines 171-177

```python
def _build_circuit_cpp(num_relays: int, message: str, destination: str, directory_base_url: str) -> Circuit:
    # ... code ...
    
    msg_bytes = message.encode("utf-8")
    msg_buf = (ctypes.c_uint8 * len(msg_bytes)).from_buffer_copy(msg_bytes)

    rc = lib.matryoshka_build_circuit_json_c(
        int(num_relays),
        msg_buf,
        int(len(msg_bytes)),
        destination.encode("utf-8"),           # ❌ BUG: Temporary bytes object!
        directory_base_url.encode("utf-8"),    # ❌ BUG: Temporary bytes object!
        ctypes.byref(out_ptr),
    )
```

### What's Wrong?

When you call `.encode("utf-8")` inline like this, Python creates a temporary bytes object. The C++ function receives a pointer to this object, but **Python immediately frees it** after the function call starts. The C++ code then tries to read from freed memory → crash!

Think of it like this:
1. Python: "Here's a pointer to '194.146.36.166:5000'"
2. Python GC: "Nobody's using this, let me free it"
3. C++: "Let me read from that pointer..." → **CRASH** (reading freed memory)

---

## The Fix

### File: `circuit_builder.py`

**Replace lines 171-177 with:**

```python
def _build_circuit_cpp(num_relays: int, message: str, destination: str, directory_base_url: str) -> Circuit:
    lib = _load_matryoshka_lib()
    if not lib:
        raise FileNotFoundError("matryoshka.dll not found")

    out_ptr = ctypes.c_char_p()

    msg_bytes = message.encode("utf-8")
    msg_buf = (ctypes.c_uint8 * len(msg_bytes)).from_buffer_copy(msg_bytes)
    
    # FIX: Keep byte strings alive by storing them in variables
    dest_bytes = destination.encode("utf-8")
    dir_bytes = directory_base_url.encode("utf-8")

    rc = lib.matryoshka_build_circuit_json_c(
        int(num_relays),
        msg_buf,
        int(len(msg_bytes)),
        dest_bytes,      # ✅ Now this won't be freed
        dir_bytes,       # ✅ Now this won't be freed
        ctypes.byref(out_ptr),
    )

    if rc != 0:
        raise RuntimeError(f"matryoshka_build_circuit_json_c failed (rc={rc})")

    # ... rest of code stays the same ...
```

### Why This Works

By storing the encoded bytes in variables (`dest_bytes` and `dir_bytes`), Python keeps them alive for the entire function. The C++ code can safely read from these pointers without them being freed.

---

## Bonus Fix: Directory URL

While we're at it, there's another bug on **line 288**:

### Current Code:
```python
directory_base_url = os.environ.get("MATRYOSHKA_DIRECTORY_URL", "http://localhost:5000")
```

### Problem:
If the environment variable is set to `"194.146.36.166:5000"` (without `http://`), the requests library fails with:
```
No connection adapters were found for '194.146.36.166:5000/relays'
```

### Fix:
**Add after line 288:**

```python
directory_base_url = os.environ.get("MATRYOSHKA_DIRECTORY_URL", "http://localhost:5000")

# FIX: Ensure URL has http:// prefix
if not directory_base_url.startswith('http://') and not directory_base_url.startswith('https://'):
    directory_base_url = 'http://' + directory_base_url
```

---

## Complete Fixed Code

Here's the complete fixed `_build_circuit_cpp` function:

```python
def _build_circuit_cpp(num_relays: int, message: str, destination: str, directory_base_url: str) -> Circuit:
    lib = _load_matryoshka_lib()
    if not lib:
        raise FileNotFoundError("matryoshka.dll not found")

    out_ptr = ctypes.c_char_p()

    msg_bytes = message.encode("utf-8")
    msg_buf = (ctypes.c_uint8 * len(msg_bytes)).from_buffer_copy(msg_bytes)
    
    # FIXED: Keep references alive to prevent premature garbage collection
    dest_bytes = destination.encode("utf-8")
    dir_bytes = directory_base_url.encode("utf-8")

    rc = lib.matryoshka_build_circuit_json_c(
        int(num_relays),
        msg_buf,
        int(len(msg_bytes)),
        dest_bytes,
        dir_bytes,
        ctypes.byref(out_ptr),
    )

    if rc != 0:
        raise RuntimeError(f"matryoshka_build_circuit_json_c failed (rc={rc})")

    try:
        json_str = out_ptr.value.decode("utf-8")
        data = json.loads(json_str)
    finally:
        lib.matryoshka_free_buffer(out_ptr)

    encrypted_payload = base64.b64decode(data["encrypted_payload_b64"])
    entry_ip = data["first_relay_ip"]
    entry_port = int(data["first_relay_port"])
    hop_count = int(data.get("hop_count", num_relays))
    
    response_keys = generate_response_keys(hop_count)

    circuit = Circuit(
        relays=[],
        entry_ip=entry_ip,
        entry_port=entry_port,
        encrypted_payload=encrypted_payload,
        hop_count=hop_count,
    )
    circuit.response_keys = response_keys
    
    return circuit
```

And the directory URL fix in `send_through_circuit`:

```python
def send_through_circuit(circuit: Circuit, message: str, destination: str) -> Optional[str]:
    if not circuit:
        raise ValueError("Invalid circuit")

    directory_base_url = os.environ.get("MATRYOSHKA_DIRECTORY_URL", "http://localhost:5000")
    
    # FIXED: Ensure URL has protocol prefix
    if not directory_base_url.startswith('http://') and not directory_base_url.startswith('https://'):
        directory_base_url = 'http://' + directory_base_url

    try:
        if _find_default_dll():
            real_circuit = _build_circuit_cpp(len(circuit), message, destination, directory_base_url)
            # ... rest of code stays the same ...
```

---

## Testing

After applying the fix:

```bash
# Test 1: Basic send
python client.py -s 194.146.36.166:5000 -m "test message" -d "194.146.36.166:9000"

# Expected: Should NOT crash with access violation
# Expected: Should connect to directory server (with http:// auto-added)

# Test 2: Multiple sends
python client.py -s 194.146.36.166:5000

# Enter message: "first message"
# Enter destination: "194.146.36.166:9000"
# (send)
# Enter message: "second message"  
# Enter destination: "194.146.36.166:9000"
# (send)

# Expected: Second send should NOT crash
```

---

## Why This Bug Happened

This is a **very common mistake** when using Python ctypes with C/C++ libraries. Python's automatic memory management doesn't know that C++ is holding a pointer, so it frees the memory too early.

**Rule of thumb:** When passing strings to C/C++:
- ✅ Store `.encode()` result in a variable
- ❌ Don't use `.encode()` inline in function calls

---

## Summary

**Changes needed:** 2 lines in `circuit_builder.py`

1. **Line ~173:** Add `dest_bytes = destination.encode("utf-8")`
2. **Line ~174:** Add `dir_bytes = directory_base_url.encode("utf-8")`
3. **Line ~176:** Change inline `destination.encode("utf-8")` to `dest_bytes`
4. **Line ~177:** Change inline `directory_base_url.encode("utf-8")` to `dir_bytes`
5. **Line ~290:** Add URL protocol validation

**Time to fix:** 5 minutes  
**Difficulty:** Easy  
**Impact:** Fixes critical crash bug

---

**After this fix, you can proceed with implementing the response encryption from the main bug report!**
