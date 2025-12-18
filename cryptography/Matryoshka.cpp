#include <iostream>
#include <iomanip>
#include <set>
#include <boost/asio.hpp>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <nlohmann/json.hpp>
#include <cpr/cpr.h>
#include <random>
#include <format>
#include <cstdlib>
#include <cstring>
#include <cstdint>

// Define the export macro BEFORE including the header
#define MATRYOSHKA_EXPORTS
#include "matryoshka.h"

using json = nlohmann::json;

struct AESPair
{
    unsigned char key[32]; // 256-bit AES key
    unsigned char iv[16];  // 128-bit IV
};
struct RSAEncryptedAESPair
{
    std::vector<unsigned char> encrypted_key;
    std::vector<unsigned char> encrypted_iv;
};
struct RelayInfo
{
    std::string ip;
    int port;
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key;

    RelayInfo(std::string i, int p, EVP_PKEY* k)
        : ip(std::move(i)), port(p), key(k, EVP_PKEY_free) {
    }
};

// ============================================================
// Internal helper functions (not exported)
// ============================================================

EVP_PKEY* generateRSAKeyInternal() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        std::cerr << "Error: Failed to create EVP_PKEY_CTX\n";
        return nullptr;
    }
    
    EVP_PKEY* pkey = nullptr;

    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0)
    {
        std::cerr << "Error: RSA key generation failed\n";
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }
    
    std::cout << "RSA-2048 key successfully generated!" << std::endl;

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}
AESPair generateAESPair()
{
    AESPair result;
    unsigned char aes_key[32];  // 256-bit AES key
    unsigned char aes_iv[16];   // 128-bit IV
    RAND_bytes(result.key, sizeof(result.key));
    RAND_bytes(result.iv, sizeof(result.iv));
	return result;
}

RSAEncryptedAESPair encrypt_RSA(EVP_PKEY* rsa_public_key, const AESPair& aes_key)
{
    RSAEncryptedAESPair result;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(rsa_public_key, nullptr);
    if (!ctx) {
        std::cerr << "Error: Failed to create encryption context\n";
        return result;
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        std::cerr << "Error: Failed to initialize encryption\n";
        EVP_PKEY_CTX_free(ctx);
        return result;
    }
    
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        std::cerr << "Error: Failed to set RSA padding\n";
        EVP_PKEY_CTX_free(ctx);
        return result;
    }

    // --- Encrypt AES KEY (32 bytes) ---
    size_t key_outlen = 0;
    EVP_PKEY_encrypt(ctx, nullptr, &key_outlen,
        aes_key.key, sizeof(aes_key.key));

    result.encrypted_key.resize(key_outlen);

    EVP_PKEY_encrypt(ctx,
        result.encrypted_key.data(), &key_outlen,
        aes_key.key, sizeof(aes_key.key));

    result.encrypted_key.resize(key_outlen);

    // --- Encrypt AES IV (16 bytes) ---
    size_t iv_outlen = 0;
    EVP_PKEY_encrypt(ctx, nullptr, &iv_outlen,
        aes_key.iv, sizeof(aes_key.iv));

    result.encrypted_iv.resize(iv_outlen);

    EVP_PKEY_encrypt(ctx,
        result.encrypted_iv.data(), &iv_outlen,
        aes_key.iv, sizeof(aes_key.iv));

    result.encrypted_iv.resize(iv_outlen);

    EVP_PKEY_CTX_free(ctx);
    return result;
}
AESPair decrypt_RSA(EVP_PKEY* rsa_private_key, RSAEncryptedAESPair rsa_aes)
{
    AESPair aes_key_out{};

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(rsa_private_key, nullptr);
    if (!ctx) return aes_key_out;

    EVP_PKEY_decrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

    // ---- DECRYPT AES KEY ----
    size_t key_len = 0;
    EVP_PKEY_decrypt(ctx, nullptr, &key_len,
        rsa_aes.encrypted_key.data(), rsa_aes.encrypted_key.size());

    EVP_PKEY_decrypt(ctx,
        aes_key_out.key, &key_len,
        rsa_aes.encrypted_key.data(), rsa_aes.encrypted_key.size());

    // ---- DECRYPT AES IV ----
    size_t iv_len = 0;
    EVP_PKEY_decrypt(ctx, nullptr, &iv_len,
        rsa_aes.encrypted_iv.data(), rsa_aes.encrypted_iv.size());

    EVP_PKEY_decrypt(ctx,
        aes_key_out.iv, &iv_len,
        rsa_aes.encrypted_iv.data(), rsa_aes.encrypted_iv.size());

    EVP_PKEY_CTX_free(ctx);
    return aes_key_out;
}
std::vector<unsigned char> encrypt_AES(const std::vector<unsigned char>& payload, AESPair aes_pair)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error: Failed to create AES encryption context\n";
        return {};
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_pair.key, aes_pair.iv) != 1) {
        std::cerr << "Error: Failed to initialize AES encryption\n";
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    std::vector<unsigned char> ciphertext(payload.size() + 16);

    int outlen1 = 0;
    EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen1, payload.data(), payload.size());

    int outlen2 = 0;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen1, &outlen2);

    ciphertext.resize(outlen1 + outlen2);
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}
std::vector<unsigned char> decrypt_AES(const std::vector<unsigned char>& ciphertext, AESPair aes_pair)
{
    std::vector<unsigned char> plaintext(ciphertext.size()); // plaintext <= ciphertext size (AES guarantee)
    int outlen1 = 0, outlen2 = 0;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error: Failed to create AES decryption context\n";
        return {};
    }
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aes_pair.key, aes_pair.iv) != 1) {
        std::cerr << "Error: Failed to initialize AES decryption\n";
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    EVP_DecryptUpdate(ctx, plaintext.data(), &outlen1, ciphertext.data(), ciphertext.size());
    EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen1, &outlen2);

    plaintext.resize(outlen1 + outlen2); // resize to actual decrypted size
    EVP_CIPHER_CTX_free(ctx);

    return plaintext; // move semantics used here (learn this later)
}

nlohmann::json getRelaysInternal(const std::string& directory_url = "http://localhost:5600")
{
    auto r = cpr::Get(cpr::Url{ directory_url + "/relays" });

    if (r.status_code == 200)
    {
        nlohmann::json j = nlohmann::json::parse(r.text);
        return j;
    }
    else
    {
        std::cout << "Error fetching relays: " << r.error.message << "\n";
        return "";
    }
}

std::string to_base64(const std::vector<unsigned char>& data)
{
    int encoded_len = 4 * ((data.size() + 2) / 3);  // base64 length
    std::string out(encoded_len, '\0');

    int written = EVP_EncodeBlock(
        reinterpret_cast<unsigned char*>(&out[0]),
        data.data(),
        data.size()
    );

    out.resize(written);
    return out;
}
std::vector<unsigned char> decode_base64(const std::string& in)
{
    std::vector<unsigned char> out(in.size()); // max size
    int len = EVP_DecodeBlock(out.data(),
        reinterpret_cast<const unsigned char*>(in.data()),
        in.size());

    // OpenSSL includes padding in output; trim '=' padding
    while (!out.empty() && out.back() == '\0')
        out.pop_back();

    return out;
}
std::string toJson(RSAEncryptedAESPair rsa_aes, std::vector<unsigned char> payload)
{
	std::string aesPayloadBase64 = to_base64(payload);
	std::string encrypted_key = to_base64(rsa_aes.encrypted_key);
    std::string encrypted_iv = to_base64(rsa_aes.encrypted_iv);

    json j;
    j["cipher"] = 
    {
        {"enc_key",     encrypted_key},
        {"enc_iv",      encrypted_iv},
        {"enc_payload", aesPayloadBase64}
    };
    
    std::string json_payload = j.dump();
    return json_payload;
}

std::string lockMatryoshka(std::vector<unsigned char> payload, EVP_PKEY* rsaKey)
{
	AESPair aes_pair = generateAESPair();
    std::vector<unsigned char> aes_encrypted_payload = encrypt_AES(payload, aes_pair);
	RSAEncryptedAESPair rsa_encrypted_aes = encrypt_RSA(rsaKey, aes_pair);
	std::string json_payload = toJson(rsa_encrypted_aes, aes_encrypted_payload);

    return json_payload;
}

// ============================================================
// EXPORTED FUNCTIONS - Namespace Matryoshka
// ============================================================

namespace Matryoshka {

// Structs are defined in matryoshka.h

// For relay, decrypts a single layer
DecryptedLayer decrypt_layer(const std::string& encrypted_packet, EVP_PKEY* rsa_private_key)
{
    DecryptedLayer result;
    
    try {
        json j = json::parse(encrypted_packet);
        std::vector<unsigned char> rsa_enc_key = decode_base64(j["cipher"]["enc_key"]);
        std::vector<unsigned char> rsa_enc_iv = decode_base64(j["cipher"]["enc_iv"]);
        std::vector<unsigned char> enc_payload = decode_base64(j["cipher"]["enc_payload"]);

        RSAEncryptedAESPair rsa_aes{ rsa_enc_key, rsa_enc_iv };
        AESPair aes_pair = decrypt_RSA(rsa_private_key, rsa_aes);
        std::vector<unsigned char> decrypted_payload = decrypt_AES(enc_payload, aes_pair);
        
        // Save response key/iv into the result so relays can encrypt upstream responses
        std::memcpy(result.response_key, aes_pair.key, sizeof(aes_pair.key));
        std::memcpy(result.response_iv, aes_pair.iv, sizeof(aes_pair.iv));
        
        // Parse decrypted payload to extract next_hop
        std::string decrypted_str(decrypted_payload.begin(), decrypted_payload.end());
        json inner_j = json::parse(decrypted_str);
        
        result.next_hop = inner_j["next_hop"];
        
        // Check if there's more payload (another layer) or final message
        if (inner_j.contains("payload")) {
            if (inner_j["payload"].is_string()) {
                std::string payload_str = inner_j["payload"];
                result.remaining_payload = std::vector<unsigned char>(payload_str.begin(), payload_str.end());
            }
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error decrypting layer: " << e.what() << "\n";
    }
    
    return result;
}

// FOR PERSON 3 (CLIENT): Build a circuit through the network
Circuit build_circuit(int hop_count,
    const std::vector<unsigned char>& payload,
    const std::string& final_destination,
    const std::string& directory_url)
{
nlohmann::json relays;
    try {
        relays = getRelaysInternal(directory_url);
    } catch (const std::exception& e) {
        std::cerr << "Error fetching relays from directory: " << e.what() << "\n";
        return Circuit{};
    }

    if (hop_count < 1)
    {
        std::cerr << "Error: hop_count must be at least 1." << std::endl;
        return Circuit{};
    }

    // Be defensive: ensure relays JSON contains a valid count field
    int available_relays = 0;
    if (relays.is_object() && relays.contains("count")) {
        try {
            available_relays = relays["count"].get<int>();
        } catch (const std::exception& e) {
            std::cerr << "Error parsing 'count' from directory response: " << e.what() << "\n";
            return Circuit{};
        }
    } else {
        std::cerr << "Error: Directory response invalid or missing 'count' field: " << relays.dump() << "\n";
        return Circuit{};
    }

    if (hop_count > available_relays)
    {
        std::cerr << "Error: Not enough relays available to build the circuit. Available: " << available_relays << "\n";
        return Circuit{};
    }

    std::cout << relays.dump(4) << "\n";

    if (!relays.contains("relays") || !relays["relays"].is_array()) {
        std::cerr << "Error: Directory response missing 'relays' array: " << relays.dump() << "\n";
        return Circuit{};
    }

    // Put all relays from json to a vector
    std::vector<RelayInfo> relay_infos;
    try {
        relay_infos.reserve(relays["relays"].size());

    for (const auto& relay : relays["relays"])
    {
        std::string ip = relay["ip"];
        int port = relay["port"];
        std::string pubkey_pem = relay["public_key"];

        // Load public key
        BIO* bio = BIO_new_mem_buf(pubkey_pem.data(), static_cast<int>(pubkey_pem.size()));
        if (!bio)
        {
            std::cerr << "Failed to create BIO for relay " << ip << ":" << port << "\n";
            continue;
        }

        EVP_PKEY* pubkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (!pubkey)
        {
            std::cerr << "Failed to load public key for relay " << ip << ":" << port << "\n";
            continue;
        }

        relay_infos.push_back(RelayInfo{ ip, port, pubkey });
    }

    if (relay_infos.size() < static_cast<size_t>(hop_count))
    {
        std::cerr << "Error: Not enough valid relays after parsing.\n";
        return Circuit{};
    }
    } catch (const std::exception& e) {
        std::cerr << "Exception while parsing relays: " << e.what() << "\n";
        return Circuit{};
    }
    // Choose random relays without repeats
    std::random_device rd;
    std::mt19937 gen(rd());
    std::vector<RelayInfo*> chosen_relays;
    std::set<int> used_indices;

    for (int i = 0; i < hop_count; ++i)
    {
        int idx;
        do
        {
            std::uniform_int_distribution<int> dist(0, relay_infos.size() - 1);
            idx = dist(gen);
        } while (used_indices.count(idx) > 0);

        used_indices.insert(idx);
        RelayInfo& relay = relay_infos[idx];
        chosen_relays.push_back(&relay);
        std::cout << relay.ip << ":" << relay.port << " ";
    }
    std::cout << "\n";

    // Build the matryoshka payload by encrypting from innermost to outermost layer
    std::vector<unsigned char> current_payload = payload;

    // Track response keys for client so it can decrypt responses (entry -> exit order)
    std::vector<ResponseKey> response_keys;

    // Iterate backwards (exit relay first, entry relay last)
    for (int i = hop_count - 1; i >= 0; --i)
    {
        RelayInfo* relay = chosen_relays[i];

        // Determine the next hop IP:port
        std::string next_hop;
        if (i == hop_count - 1) {
            next_hop = final_destination;  // Final destination
        }
        else
        {
            RelayInfo* next_relay = chosen_relays[i + 1];
            next_hop = next_relay->ip + ":" + std::to_string(next_relay->port);
        }

        // Create inner JSON with next_hop and payload
        json inner_layer;
        inner_layer["next_hop"] = next_hop;
        std::string payload_str(current_payload.begin(), current_payload.end());
        inner_layer["payload"] = payload_str;
        std::string inner_json_str = inner_layer.dump();
        std::vector<unsigned char> inner_payload(inner_json_str.begin(), inner_json_str.end());

        // Generate AES key for this layer
        AESPair aes_pair = generateAESPair();

        // Save the response key material in the per-circuit list (entry->exit order)
        ResponseKey resp_key;
        std::memcpy(resp_key.key, aes_pair.key, sizeof(aes_pair.key));
        std::memcpy(resp_key.iv, aes_pair.iv, sizeof(aes_pair.iv));
        response_keys.push_back(resp_key);

        // Encrypt the inner payload (which contains next_hop) with AES
        std::vector<unsigned char> aes_encrypted = encrypt_AES(inner_payload, aes_pair);

        // Encrypt the AES key/iv with the relay's RSA public key
        if (!relay->key || relay->key.get() == nullptr) {
            std::cerr << "matryoshka::build_circuit: null public key for relay "
                      << relay->ip << ":" << relay->port << " — aborting circuit build\n";
            throw std::runtime_error("relay public key is null");
        }
        RSAEncryptedAESPair rsa_encrypted_aes = encrypt_RSA(relay->key.get(), aes_pair);

        // Build outer JSON structure (only cipher, no plaintext next_hop)
        std::string json_str = toJson(rsa_encrypted_aes, aes_encrypted);

        // Convert JSON string to vector<unsigned char> for next iteration
        current_payload = std::vector<unsigned char>(json_str.begin(), json_str.end());

        std::cout << "Layer " << (hop_count - i) << " encrypted for relay "
            << relay->ip << ":" << relay->port
            << " (next hop: " << next_hop << ")\n";
    }

    std::cout << "\nFinal encrypted payload size: " << current_payload.size() << " bytes\n";
    std::cout << "\nCircuit ready. First relay: "
        << chosen_relays[0]->ip << ":" << chosen_relays[0]->port << "\n";
    
    // Build Circuit structure
    Circuit circuit;
    circuit.encrypted_payload = current_payload;
    circuit.first_relay_ip = chosen_relays[0]->ip;
    circuit.first_relay_port = chosen_relays[0]->port;
    circuit.hop_count = hop_count;

    // Attach response keys collected during build
    circuit.response_keys = response_keys;
    
    return circuit;
}

// FOR CLIENT Send encrypted message through the circuit
std::string send_through_circuit(const Circuit& circuit)
{
    try {
        boost::asio::io_context io_context;
        boost::asio::ip::tcp::socket socket(io_context);
        boost::asio::ip::tcp::resolver resolver(io_context);
        
        std::cout << "\nConnecting to first relay: " 
                  << circuit.first_relay_ip << ":" << circuit.first_relay_port << "\n";
        
        // Resolve and connect to first relay
        auto endpoints = resolver.resolve(
            circuit.first_relay_ip,
            std::to_string(circuit.first_relay_port)
        );
        boost::asio::connect(socket, endpoints);
        
        std::cout << "Connected! Sending encrypted payload (" 
                  << circuit.encrypted_payload.size() << " bytes)...\n";
        
        // Send the encrypted payload
        boost::asio::write(socket, boost::asio::buffer(circuit.encrypted_payload));
        
        std::cout << "Payload sent successfully through circuit!\n";
        
        // Wait for response (optional - depends on protocol)
        boost::asio::streambuf response_buffer;
        boost::system::error_code ec;
        size_t bytes_read = boost::asio::read_until(socket, response_buffer, "\n", ec);
        
        std::string response;
        if (bytes_read > 0) {
            std::istream response_stream(&response_buffer);
            std::getline(response_stream, response);
            std::cout << "Response received: " << response << "\n";
        }
        
        socket.close();
        return response;
    }
    catch (const std::exception& e) {
        std::cerr << "Error sending through circuit: " << e.what() << "\n";
        return "";
    }
}

// Generate RSA key (exported)
EVP_PKEY* generateRSAKey() {
    return generateRSAKeyInternal();
}

//Get public key as PEM string (exported)
std::string getPublicKeyPEM(EVP_PKEY* pkey) {
    if (!pkey) return "";
    
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "";
    
    PEM_write_bio_PUBKEY(bio, pkey);
    
    char* pubkey_data;
    long pubkey_len = BIO_get_mem_data(bio, &pubkey_data);
    std::string public_key_pem(pubkey_data, pubkey_len);
    
    BIO_free(bio);
    return public_key_pem;
}

} // namespace Matryoshka

// ============================================================
// C ABI WRAPPERS FOR INTEROP (Python/Node/Rust/etc.)
// ============================================================

namespace {
    // Duplicate a std::string into a malloc-owned C buffer.
    char* dup_cstr(const std::string& s) {
        char* out = static_cast<char*>(std::malloc(s.size() + 1));
        if (!out) return nullptr;
        std::memcpy(out, s.data(), s.size());
        out[s.size()] = '\0';
        return out;
    }

    // Copy binary blob into a malloc-owned buffer.
    std::uint8_t* dup_bytes(const std::vector<unsigned char>& bytes) {
        if (bytes.empty()) return nullptr;
        auto* out = static_cast<std::uint8_t*>(std::malloc(bytes.size()));
        if (!out) return nullptr;
        std::memcpy(out, bytes.data(), bytes.size());
        return out;
    }
}

extern "C" {

MATRYOSHKA_API int matryoshka_decrypt_layer_c(
    const char* encrypted_packet,
    EVP_PKEY* rsa_private_key,
    MatryoshkaC_DecryptedLayer* out_layer)
{
    if (!encrypted_packet || !rsa_private_key || !out_layer) {
        return -1;
    }

    Matryoshka::DecryptedLayer cpp_layer =
        Matryoshka::decrypt_layer(std::string(encrypted_packet), rsa_private_key);

    if (cpp_layer.next_hop.empty()) {
        return -2; // decryption failed
    }

    out_layer->next_hop = dup_cstr(cpp_layer.next_hop);
    out_layer->remaining_len = static_cast<int>(cpp_layer.remaining_payload.size());
    out_layer->remaining_payload = dup_bytes(cpp_layer.remaining_payload);

    // Copy response key/iv into malloc'd buffers if available
    out_layer->response_key_len = sizeof(cpp_layer.response_key);
    out_layer->response_key = nullptr;
    if (out_layer->response_key_len > 0) {
        out_layer->response_key = static_cast<std::uint8_t*>(std::malloc(out_layer->response_key_len));
        if (out_layer->response_key) std::memcpy(out_layer->response_key, cpp_layer.response_key, out_layer->response_key_len);
    }
    out_layer->response_iv_len = sizeof(cpp_layer.response_iv);
    out_layer->response_iv = nullptr;
    if (out_layer->response_iv_len > 0) {
        out_layer->response_iv = static_cast<std::uint8_t*>(std::malloc(out_layer->response_iv_len));
        if (out_layer->response_iv) std::memcpy(out_layer->response_iv, cpp_layer.response_iv, out_layer->response_iv_len);
    }

    if (!out_layer->next_hop && out_layer->remaining_len > 0 && !out_layer->remaining_payload) {
        return -3; // allocation failure
    }

    return 0;
}

MATRYOSHKA_API int matryoshka_build_circuit_c(
    int hop_count,
    const std::uint8_t* payload,
    int payload_len,
    const char* final_destination,
    const char* directory_url,
    MatryoshkaC_Circuit* out_circuit)
{
    if (!payload || payload_len <= 0 || !final_destination || !out_circuit) {
        return -1;
    }

    std::string dir_url = directory_url ? std::string(directory_url) : "http://localhost:5600";
    std::vector<unsigned char> payload_vec(payload, payload + payload_len);

    Matryoshka::Circuit cpp_circuit = Matryoshka::build_circuit(
        hop_count,
        payload_vec,
        std::string(final_destination),
        dir_url);

    if (cpp_circuit.first_relay_ip.empty()) {
        return -2; // build failed
    }

    out_circuit->encrypted_payload = dup_bytes(cpp_circuit.encrypted_payload);
    out_circuit->payload_len = static_cast<int>(cpp_circuit.encrypted_payload.size());
    out_circuit->first_relay_ip = dup_cstr(cpp_circuit.first_relay_ip);
    out_circuit->first_relay_port = cpp_circuit.first_relay_port;
    out_circuit->hop_count = cpp_circuit.hop_count;

    if ((!out_circuit->encrypted_payload && out_circuit->payload_len > 0) || !out_circuit->first_relay_ip) {
        return -3; // allocation failure
    }

    return 0;
}

MATRYOSHKA_API int matryoshka_send_through_circuit_c(
    const MatryoshkaC_Circuit* circuit,
    char** response_out)
{
    if (!circuit || !response_out) {
        return -1;
    }

    Matryoshka::Circuit cpp_circuit;
    if (circuit->encrypted_payload && circuit->payload_len > 0) {
        cpp_circuit.encrypted_payload.assign(
            circuit->encrypted_payload,
            circuit->encrypted_payload + circuit->payload_len);
    }
    cpp_circuit.first_relay_ip = circuit->first_relay_ip ? circuit->first_relay_ip : "";
    cpp_circuit.first_relay_port = circuit->first_relay_port;
    cpp_circuit.hop_count = circuit->hop_count;

    std::string resp = Matryoshka::send_through_circuit(cpp_circuit);

    // Always return a valid C string (empty string when no response)
    *response_out = dup_cstr(resp);
    if (!*response_out) {
        return -2; // allocation failure
    }

    return resp.empty() ? 1 : 0; // 1 indicates no response payload but call succeeded
}

MATRYOSHKA_API int matryoshka_decrypt_layer_json_c(
    const char* encrypted_packet,
    const char* rsa_private_key_pem,
    char** json_out)
{
    if (!encrypted_packet || !rsa_private_key_pem || !json_out) {
        return -1;
    }

    // Load EVP_PKEY from PEM string provided by higher-level language
    BIO* bio = BIO_new_mem_buf(rsa_private_key_pem, -1);
    if (!bio) {
        return -2;
    }

    EVP_PKEY* rsa_private_key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!rsa_private_key) {
        return -3;
    }

    Matryoshka::DecryptedLayer cpp_layer =
        Matryoshka::decrypt_layer(std::string(encrypted_packet), rsa_private_key);

    EVP_PKEY_free(rsa_private_key);

    if (cpp_layer.next_hop.empty()) {
        return -4;
    }

    std::string remaining_b64 = to_base64(cpp_layer.remaining_payload);
    json j;
    j["next_hop"] = cpp_layer.next_hop;
    j["remaining_payload_b64"] = remaining_b64;

    // Add response key/iv (base64) so caller can store and reuse for upstream encryption
    std::vector<unsigned char> resp_key_vec(cpp_layer.response_key, cpp_layer.response_key + sizeof(cpp_layer.response_key));
    std::vector<unsigned char> resp_iv_vec(cpp_layer.response_iv, cpp_layer.response_iv + sizeof(cpp_layer.response_iv));
    j["response_key_b64"] = to_base64(resp_key_vec);
    j["response_iv_b64"] = to_base64(resp_iv_vec);

    std::string out = j.dump();
    *json_out = dup_cstr(out);
    if (!*json_out) {
        return -5;
    }

    return 0;
}

MATRYOSHKA_API int matryoshka_build_circuit_json_c(
    int hop_count,
    const std::uint8_t* payload,
    int payload_len,
    const char* final_destination,
    const char* directory_url,
    char** json_out)
{
    if (!payload || payload_len <= 0 || !final_destination || !json_out) {
        return -1;
    }

    std::string dir_url = directory_url ? std::string(directory_url) : "http://localhost:5600";
    std::vector<unsigned char> payload_vec;
    // Debug: print incoming parameters to help diagnose crashes (avoid printing payload contents)
    std::cerr << "matryoshka_build_circuit_json_c: hop_count=" << hop_count << " payload_len=" << payload_len
              << " dest=" << (final_destination ? final_destination : "(null)")
              << " dir=" << dir_url << "\n";
    try {
        payload_vec.assign(payload, payload + payload_len);

        // Build circuit with defensive exception handling
        Matryoshka::Circuit cpp_circuit = Matryoshka::build_circuit(
            hop_count,
            payload_vec,
            std::string(final_destination),
            dir_url);

        if (cpp_circuit.first_relay_ip.empty()) {
            return -2;
        }

        // Continue to JSON export below (move j-building into this scope)

        json j;
        j["encrypted_payload_b64"] = to_base64(cpp_circuit.encrypted_payload);
        j["first_relay_ip"] = cpp_circuit.first_relay_ip;
        j["first_relay_port"] = cpp_circuit.first_relay_port;
        j["hop_count"] = cpp_circuit.hop_count;

        // Export response keys (base64-encoded) so higher-level clients can decrypt responses
        json response_keys_json = json::array();
        for (const auto& rk : cpp_circuit.response_keys) {
            json k;
            std::vector<unsigned char> key_vec(rk.key, rk.key + sizeof(rk.key));
            std::vector<unsigned char> iv_vec(rk.iv, rk.iv + sizeof(rk.iv));
            k["key_b64"] = to_base64(key_vec);
            k["iv_b64"] = to_base64(iv_vec);
            response_keys_json.push_back(k);
        }
        j["response_keys"] = response_keys_json;

        std::string out = j.dump();
        *json_out = dup_cstr(out);
        if (!*json_out) {
            return -3;
        }

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Exception in matryoshka_build_circuit_json_c: " << e.what() << "\n";
        return -2;
    }

}

MATRYOSHKA_API int matryoshka_send_through_circuit_json_c(
    const MatryoshkaC_Circuit* circuit,
    char** json_out)
{
    if (!circuit || !json_out) {
        return -1;
    }

    char* resp_cstr = nullptr;
    int rc = matryoshka_send_through_circuit_c(circuit, &resp_cstr);
    if (rc < 0) {
        return rc;
    }

    std::string resp = resp_cstr ? std::string(resp_cstr) : "";
    json j;
    j["response"] = resp;

    std::string out = j.dump();
    *json_out = dup_cstr(out);
    if (!*json_out) {
        if (resp_cstr) std::free(resp_cstr);
        return -2;
    }

    if (resp_cstr) std::free(resp_cstr);
    return 0;
}

MATRYOSHKA_API int matryoshka_generate_keypair_c(char** private_key_out, char** public_key_out)
{
    if (!private_key_out || !public_key_out) return -1;

    // 1. Generate the key object using your existing internal function
    EVP_PKEY* pkey = Matryoshka::generateRSAKey();
    if (!pkey) return -2;

    // 2. Export PRIVATE Key to PEM string
    BIO* bio_priv = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio_priv, pkey, nullptr, nullptr, 0, nullptr, nullptr);

    char* priv_data;
    long priv_len = BIO_get_mem_data(bio_priv, &priv_data);
    *private_key_out = static_cast<char*>(std::malloc(priv_len + 1));
    std::memcpy(*private_key_out, priv_data, priv_len);
    (*private_key_out)[priv_len] = '\0'; // Null-terminate
    BIO_free(bio_priv);

    // 3. Export PUBLIC Key to PEM string (using your existing helper)
    std::string pub_str = Matryoshka::getPublicKeyPEM(pkey);
    *public_key_out = dup_cstr(pub_str);

    // 4. Cleanup
    EVP_PKEY_free(pkey);

    // Check for allocation failures
    if (!*private_key_out || !*public_key_out) return -3;

    return 0;
}

MATRYOSHKA_API void matryoshka_free_buffer(void* buffer)
{
    if (buffer) {
        std::free(buffer);
    }
}

} 
