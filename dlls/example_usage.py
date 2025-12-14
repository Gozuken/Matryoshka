import ctypes
import json
import base64
import requests
import os
import time

# ==========================================
# 1. CONFIGURATION
# ==========================================
DIRECTORY_URL = "http://localhost:5600"  # Person 1's Server
DLL_NAME = "./matryoshka.dll" if os.name == 'nt' else "./libmatryoshka.so"

# ==========================================
# 2. LOAD YOUR C++ LIBRARY
# ==========================================
try:
    lib = ctypes.CDLL(os.path.abspath(DLL_NAME))
except OSError:
    print(f"❌ Could not find {DLL_NAME}. Did you compile it?")
    exit(1)

# Define C function signatures
lib.matryoshka_generate_keypair_c.argtypes = [ctypes.POINTER(ctypes.c_char_p), ctypes.POINTER(ctypes.c_char_p)]
lib.matryoshka_build_circuit_json_c.argtypes = [
    ctypes.c_int, ctypes.c_char_p, ctypes.c_int, 
    ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p)
]
lib.matryoshka_decrypt_layer_json_c.argtypes = [
    ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p)
]
lib.matryoshka_free_buffer.argtypes = [ctypes.c_void_p]

# ==========================================
# 3. HELPER WRAPPERS
# ==========================================
def generate_keypair_cpp():
    priv_ptr = ctypes.c_char_p()
    pub_ptr = ctypes.c_char_p()
    res = lib.matryoshka_generate_keypair_c(ctypes.byref(priv_ptr), ctypes.byref(pub_ptr))
    if res != 0: raise Exception("Key generation failed in C++")
    priv = priv_ptr.value.decode('utf-8')
    pub = pub_ptr.value.decode('utf-8')
    lib.matryoshka_free_buffer(priv_ptr)
    lib.matryoshka_free_buffer(pub_ptr)
    return priv, pub

def build_circuit_cpp(hops, msg, dest):
    out_ptr = ctypes.c_char_p()
    # Note: We pass DIRECTORY_URL to your C++ code so it queries the real server!
    res = lib.matryoshka_build_circuit_json_c(
        hops, msg.encode('utf-8'), len(msg), 
        dest.encode('utf-8'), DIRECTORY_URL.encode('utf-8'), 
        ctypes.byref(out_ptr)
    )
    if res != 0: raise Exception(f"Circuit build failed (Error {res})")
    json_str = out_ptr.value.decode('utf-8')
    lib.matryoshka_free_buffer(out_ptr)
    return json.loads(json_str)

def decrypt_layer_cpp(packet_str, priv_key):
    out_ptr = ctypes.c_char_p()
    res = lib.matryoshka_decrypt_layer_json_c(
        packet_str.encode('utf-8'), priv_key.encode('utf-8'), 
        ctypes.byref(out_ptr)
    )
    if res != 0: raise Exception(f"Decryption failed (Error {res})")
    json_str = out_ptr.value.decode('utf-8')
    lib.matryoshka_free_buffer(out_ptr)
    return json.loads(json_str)

# ==========================================
# 4. MAIN TEST FLOW
# ==========================================
def run_test():
    print(f"--- 🚀 Starting Integration Test with {DIRECTORY_URL} ---")

    # STEP 1: GENERATE KEYS (Simulating Person 2 Relay Startup)
    print("\n[Relay] Generating RSA Keys using C++...")
    try:
        my_priv_key, my_pub_key = generate_keypair_cpp()
        print("   ✅ Keys Generated successfully.")
    except Exception as e:
        print(f"   ❌ Failed: {e}")
        print("      (Did you add 'matryoshka_generate_keypair_c' to the export block?)")
        return

    # STEP 2: REGISTER RELAY (Talking to Person 1)
    relay_id = "test_relay_9"
    relay_port = 8001
    print(f"\n[Relay] Registering '{relay_id}' with Directory Server...")
    
    try:
        reg_data = {
            "id": relay_id,
            "ip": "127.0.0.1",
            "port": relay_port,
            "public_key": my_pub_key
        }
        resp = requests.post(f"{DIRECTORY_URL}/register", json=reg_data)
        if resp.status_code == 200 or resp.status_code == 201:
            print("   ✅ Registration successful!")
        else:
            print(f"   ❌ Registration failed: {resp.text}")
            return
    except requests.exceptions.ConnectionError:
        print(f"   ❌ Could not connect to {DIRECTORY_URL}. Is Person 1's server running?")
        return

    # STEP 3: BUILD CIRCUIT (Person 3 Logic)
    # We use 1 hop because we only registered 1 relay (ourselves)
    print("\n[Client] Building 1-hop circuit using C++...")
    dest = "10.0.0.99:5600"
    message = "Secret Payload"
    
    try:
        # This calls your C++ code, which performs HTTP GET /relays
        circuit = build_circuit_cpp(1, message, dest)
        print("   ✅ Circuit built!")
        print(f"   📦 Encrypted Packet Size: {len(circuit['encrypted_payload_b64'])} bytes")
        print(f"   wf Next Hop: {circuit['first_relay_ip']}:{circuit['first_relay_port']}")
    except Exception as e:
        print(f"   ❌ Build failed: {e}")
        print("      (Make sure C++ can reach the directory URL)")
        return

    # STEP 4: DECRYPT PACKET (Person 2 Logic)
    print("\n[Relay] Attempting to decrypt the packet...")
    try:
        # Construct the JSON packet format Person 2 receives
        # Your C++ build_circuit returns the raw payload, but decrypt expects JSON wrapper?
        # WAIT: Your C++ build_circuit returns the inner payload ready for sending.
        # But your decrypt_layer expects a JSON string with "cipher" key? 
        # Let's check the protocol.
        
        # Based on Matryoshka.cpp logic:
        # build_circuit returns a 'Circuit' struct with 'encrypted_payload'
        # The internal logic created a JSON string "{ 'cipher': ... }" and put it in that payload.
        # So we just treat the payload string as the input packet.
        
        packet_to_decrypt = base64.b64decode(circuit['encrypted_payload_b64']).decode('utf-8')
        print(f"DEBUG: The packet being sent to C++ is:\n{packet_to_decrypt}")
        result = decrypt_layer_cpp(packet_to_decrypt, my_priv_key)
        
        print("   ✅ Decryption successful!")
        print(f"   jw Next Hop: {result['next_hop']}")
        print(f"   jw Expected: {dest}")
        
        if result['next_hop'] == dest:
            print("\n🎉 SUCCESS: The message traveled through the full C++ logic!")
        else:
            print("\n⚠️ WARNING: Decrypted next_hop didn't match destination.")
            
    except Exception as e:
        print(f"   ❌ Decryption failed: {e}")

if __name__ == "__main__":
    run_test()