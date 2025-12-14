"""
Example Usage - Matryoshka C++ kütüphanesi entegrasyon testi
Bu dosya core/cpp_wrapper.py modülünü kullanarak C++ kütüphanesini test eder.
"""

import json
import base64
import requests
import os
import time

# Core modülünden C++ wrapper'ı import et
try:
    from core.cpp_wrapper import get_wrapper, is_available
except ImportError:
    print("❌ core.cpp_wrapper modülü bulunamadı!")
    exit(1)


# ==========================================
# 1. CONFIGURATION
# ==========================================
DIRECTORY_URL = os.environ.get("MATRYOSHKA_DIRECTORY_URL", "http://localhost:5000")  # Person 1's Server


# ==========================================
# 2. HELPER WRAPPERS (core modülünü kullanarak)
# ==========================================
def generate_keypair_cpp():
    """C++ kütüphanesi kullanarak anahtar çifti oluşturur"""
    wrapper = get_wrapper()
    return wrapper.generate_keypair()


def build_circuit_cpp(hops, msg, dest):
    """C++ kütüphanesi kullanarak devre oluşturur"""
    wrapper = get_wrapper()
    return wrapper.build_circuit(hops, msg, dest, DIRECTORY_URL)


def decrypt_layer_cpp(packet_str, priv_key):
    """C++ kütüphanesi kullanarak paket katmanını çözer"""
    wrapper = get_wrapper()
    return wrapper.decrypt_layer(packet_str, priv_key)



# ==========================================
# 3. MAIN TEST FLOW
# ==========================================

def run_test():
    """Ana test fonksiyonu - C++ kütüphanesi entegrasyonunu test eder"""
    print(f"--- 🚀 Starting Integration Test with {DIRECTORY_URL} ---")
    
    # C++ kütüphanesinin mevcut olup olmadığını kontrol et
    if not is_available():
        print("❌ C++ kütüphanesi bulunamadı!")
        print("   Lütfen matryoshka.dll (Windows) veya libmatryoshka.so (Linux) dosyasını")
        print("   proje dizinine ekleyin.")
        return
    
    print("✅ C++ kütüphanesi yüklendi")
    
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
        print(f"   Next Hop: {circuit['first_relay_ip']}:{circuit['first_relay_port']}")
    except Exception as e:
        print(f"   ❌ Build failed: {e}")
        print("      (Make sure C++ can reach the directory URL)")
        return

    # STEP 4: DECRYPT PACKET (Person 2 Logic)
    print("\n[Relay] Attempting to decrypt the packet...")
    try:
        # Based on Matryoshka.cpp logic:
        # build_circuit returns a 'Circuit' struct with 'encrypted_payload'
        # The internal logic created a JSON string "{ 'cipher': ... }" and put it in that payload.
        # So we just treat the payload string as the input packet.
        packet_to_decrypt = base64.b64decode(circuit['encrypted_payload_b64']).decode('utf-8')
        print(f"DEBUG: The packet being sent to C++ is:\n{packet_to_decrypt}")
        result = decrypt_layer_cpp(packet_to_decrypt, my_priv_key)
        
        print("   ✅ Decryption successful!")
        print(f"   Next Hop: {result['next_hop']}")
        print(f"   Expected: {dest}")
        
        if result['next_hop'] == dest:
            print("\n🎉 SUCCESS: The message traveled through the full C++ logic!")
        else:
            print("\n⚠️ WARNING: Decrypted next_hop didn't match destination.")
            
    except Exception as e:
        print(f"   ❌ Decryption failed: {e}")


if __name__ == "__main__":
    run_test()

