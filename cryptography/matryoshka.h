#ifndef MATRYOSHKA_H
#define MATRYOSHKA_H

#include <string>
#include <vector>
#include <cstdint>
#include <openssl/evp.h>

// DLL Export/Import macro
#ifdef MATRYOSHKA_EXPORTS
    #define MATRYOSHKA_API __declspec(dllexport)
#else
    #define MATRYOSHKA_API __declspec(dllimport)
#endif

// Forward declarations for external users
namespace Matryoshka {

    // ============================================================
    // FOR PERSON 2 (RELAY NODE)
    // ============================================================

    /**
     * Result structure after decrypting one layer of the onion
     * Used by relay nodes to determine next hop and remaining payload
     */
    struct MATRYOSHKA_API DecryptedLayer {
        std::string next_hop;                      // "ip:port" of next hop
        std::vector<unsigned char> remaining_payload;  // Encrypted payload for next hop

        // Response encryption material extracted from the layer (for upstream responses)
        unsigned char response_key[32];  // AES-256 key for response encryption
        unsigned char response_iv[16];   // AES-128 IV for response encryption
    };

    /**
     * Decrypt one layer of the onion routing packet
     * 
     * @param encrypted_packet - JSON string received from previous hop
     * @param rsa_private_key - Relay's RSA private key (EVP_PKEY*)
     * @return DecryptedLayer with next_hop and remaining_payload
     * 
     * Usage in Relay:
     *   DecryptedLayer result = decrypt_layer(packet_json, my_private_key);
     *   if (!result.next_hop.empty()) {
     *       forward_to(result.next_hop, result.remaining_payload);
     *   }
     */
    MATRYOSHKA_API DecryptedLayer decrypt_layer(
        const std::string& encrypted_packet,
        EVP_PKEY* rsa_private_key
    );

    // ============================================================
    // FOR PERSON 3 (CLIENT)
    // ============================================================

    /**
     * Circuit structure containing encrypted onion and entry relay info
     * Created by build_circuit() and used by send_through_circuit()
     */
    // Simple POD to hold response AES key/iv for each hop
    struct MATRYOSHKA_API ResponseKey {
        unsigned char key[32];
        unsigned char iv[16];
    };

    struct MATRYOSHKA_API Circuit {
        std::vector<unsigned char> encrypted_payload;  // The complete onion
        std::string first_relay_ip;                   // Entry relay IP
        int first_relay_port;                         // Entry relay port
        int hop_count;                                // Number of hops

        // Response keys in order from entry->exit (client will decrypt in reverse)
        std::vector<ResponseKey> response_keys;
    };

    /**
     * Build an encrypted circuit through the Matryoshka network
     * 
     * @param hop_count - Number of relays to use (typically 3)
     * @param payload - Your message as bytes
     * @param final_destination - "ip:port" of final destination
     * @param directory_url - URL of directory server (default: http://localhost:5600)
     * @return Circuit object ready to send
     * 
     * Usage in Client:
     *   std::vector<unsigned char> msg = {'H','e','l','l','o'};
     *   Circuit circuit = build_circuit(3, msg, "192.168.1.100:9000");
     *   if (!circuit.first_relay_ip.empty()) {
     *       std::string response = send_through_circuit(circuit);
     *   }
     */
    MATRYOSHKA_API Circuit build_circuit(
        int hop_count,
        const std::vector<unsigned char>& payload,
        const std::string& final_destination,
        const std::string& directory_url = "http://localhost:5600"
    );

    /**
     * Send encrypted message through the built circuit
     * 
     * @param circuit - Circuit object from build_circuit()
     * @return Response from destination (or empty string if none)
     * 
     * Usage in Client:
     *   std::string response = send_through_circuit(circuit);
     */
    MATRYOSHKA_API std::string send_through_circuit(
        const Circuit& circuit
    );

    // ============================================================
    // UTILITY FUNCTIONS (Optional - for advanced users)
    // ============================================================

    /**
     * Generate RSA-2048 keypair for relay nodes
     * @return EVP_PKEY* (caller must free with EVP_PKEY_free)
     */
    MATRYOSHKA_API EVP_PKEY* generateRSAKey();

    /**
     * Get public key as PEM string (for directory registration)
     * @param pkey - EVP_PKEY* containing public/private key
     * @return PEM-formatted public key string
     */
    MATRYOSHKA_API std::string getPublicKeyPEM(EVP_PKEY* pkey);

} // namespace Matryoshka

// ============================================================
// C ABI (extern "C") for interoperability with other languages
// ============================================================
//
// These wrappers expose a stable C interface so that Python
// (ctypes/cffi), Node.js (ffi-napi), Rust (bindgen), etc. can
// call into the DLL without dealing with C++ name mangling or
// STL container layouts.
// All buffers returned by these functions are heap-allocated via
// `malloc`; callers **must** free them with `matryoshka_free_buffer`.
//
extern "C" {

    struct MATRYOSHKA_API MatryoshkaC_DecryptedLayer {
        char* next_hop;                 // null-terminated "ip:port"
        std::uint8_t* remaining_payload;
        int remaining_len;

        // Response key/iv (malloc'd buffers, len given)
        std::uint8_t* response_key;
        int response_key_len;
        std::uint8_t* response_iv;
        int response_iv_len;
    };

    struct MATRYOSHKA_API MatryoshkaC_Circuit {
        std::uint8_t* encrypted_payload;
        int payload_len;
        char* first_relay_ip;           // null-terminated
        int first_relay_port;
        int hop_count;
    };

    /**
     * C wrapper for decrypt_layer.
     * @return 0 on success, non-zero on error.
     */
    MATRYOSHKA_API int matryoshka_decrypt_layer_c(
        const char* encrypted_packet,
        EVP_PKEY* rsa_private_key,
        MatryoshkaC_DecryptedLayer* out_layer
    );

    /**
     * C wrapper for build_circuit.
     * @param directory_url - optional, defaults to http://localhost:5600 when nullptr.
     * @return 0 on success, non-zero on error.
     */
    MATRYOSHKA_API int matryoshka_build_circuit_c(
        int hop_count,
        const std::uint8_t* payload,
        int payload_len,
        const char* final_destination,
        const char* directory_url,
        MatryoshkaC_Circuit* out_circuit
    );

    /**
     * C wrapper for send_through_circuit.
     * @return 0 on success, non-zero on error.
     */
    MATRYOSHKA_API int matryoshka_send_through_circuit_c(
        const MatryoshkaC_Circuit* circuit,
        char** response_out
    );

    /**
     * JSON wrapper for decrypt_layer.
     * Returns a JSON string: {"next_hop":"...","remaining_payload_b64":"..."}
     */
    MATRYOSHKA_API int matryoshka_decrypt_layer_json_c(
        const char* encrypted_packet,
        const char* rsa_private_key_pem,
        char** json_out
    );

    /**
     * JSON wrapper for build_circuit.
     * Returns a JSON string with base64 payload and relay info.
     */
    MATRYOSHKA_API int matryoshka_build_circuit_json_c(
        int hop_count,
        const std::uint8_t* payload,
        int payload_len,
        const char* final_destination,
        const char* directory_url,
        char** json_out
    );

    /**
     * JSON wrapper for send_through_circuit.
     * Returns response (string, may be empty) as JSON: {"response":"..."}
     */
    MATRYOSHKA_API int matryoshka_send_through_circuit_json_c(
        const MatryoshkaC_Circuit* circuit,
        char** json_out
    );

    /**
     * Free any buffer allocated by the C wrappers.
     */
    MATRYOSHKA_API void matryoshka_free_buffer(void* buffer);
}

#endif // MATRYOSHKA_H
