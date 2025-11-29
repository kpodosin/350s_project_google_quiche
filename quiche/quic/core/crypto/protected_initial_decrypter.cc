// TODO Keely header? 

#include "quiche/quic/core/crypto/protected_initial_decrypter.h"

#include <string>
#include <vector>
#include <iostream>
#include <array>

#include "absl/strings/string_view.h"
#include "openssl/aes.h"
#include "openssl/crypto.h"
#include "openssl/evp.h"
#include "openssl/err.h"
#include "openssl/rsa.h"
#include "openssl/tls1.h"
#include "openssl/rand.h"
#include "openssl/kdf.h"
#include "openssl/ec.h"
#include "openssl/bio.h"
#include "openssl/pem.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/common/quiche_crypto_logging.h"

namespace quic {

    // TODO: Replace with actual RSA private key.
    // static const char* SERVER_PUBLIC_KEY_PEM = R"(-----BEGIN PUBLIC KEY-----
    // MCowBQYDK2VuAyEAxQz3sAKsoJCV3QUf7yVU8rEmphBCJ5N2vQEpou4koxQ=
    // -----END PUBLIC KEY-----
    // )";

  static const char* SERVER_PRIVATE_KEY_PEM = R"(-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VuBCIEIKjiUObrpM8EG692XZQpWEl1bbAcQolpgz00tfqQyyNz
-----END PRIVATE KEY-----
)";


    const size_t kKeySize = 32;  // AES-128 uses 16-byte keys NOTE TODO: ENCRYPTER IS 32 - SHOULD THIS BE 32 or 16????
    const size_t kNonceSize = 12;
    const size_t kTagSize = 16;
    const size_t kHeaderSize = kKeySize + kNonceSize + kTagSize;

ProtectedInitialDecrypter::ProtectedInitialDecrypter() 
    : AesBaseDecrypter(EVP_aead_aes_128_gcm(), 
                       kKeySize, 
                       kTagSize,
                       kNonceSize,
                       /* use_ietf_nonce_construction */ false) {
  static_assert(kKeySize <= kMaxKeySize, "key size too big");
  static_assert(kNonceSize <= kMaxNonceSize, "nonce size too big");
}

bool ProtectedInitialDecrypter::DecryptPacket(uint64_t packet_number,
                                               absl::string_view associated_data,
                                               absl::string_view ciphertext, 
                                               char* output,
                                               size_t* output_length,
                                               size_t max_output_length) {
  
  // The ciphertext format is: [eph pub key (32 bytes)][iv (12 bytes)][auth tag (16 bytes)][encrypted payload]
  const size_t header_len = kHeaderSize;

  if (ciphertext.size() < header_len) {
    QUIC_LOG(ERROR) << "Ciphertext too short";
    return false;
  }

  // Extract ephemeral public key, IV, tag, and encrypted payload from ciphertext.
  const uint8_t* cursor =
      reinterpret_cast<const uint8_t*>(ciphertext.data());
  std::array<uint8_t, kKeySize> eph_pub{};
  std::memcpy(eph_pub.data(), cursor, kKeySize);
  cursor += kKeySize;

  std::array<uint8_t, kNonceSize> iv{};
  std::memcpy(iv.data(), cursor, kNonceSize);
  cursor += kNonceSize;

  std::array<uint8_t, kTagSize> tag{};
  std::memcpy(tag.data(), cursor, kTagSize);
  cursor += kTagSize;

  size_t enc_len = ciphertext.size() - header_len;
  const uint8_t* enc_payload = cursor;

  // load server private key from PEM
  BIO* bio_priv = BIO_new_mem_buf(SERVER_PRIVATE_KEY_PEM, -1);
  EVP_PKEY* server_priv = PEM_read_bio_PrivateKey(bio_priv, nullptr, nullptr, nullptr);
  BIO_free(bio_priv);
  if (!server_priv) {
    QUIC_LOG(ERROR) << "Failed to load server private key";
    return false;
  }

  // Create ephemeral public key object
  EVP_PKEY* eph_pub_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr,
                                                      eph_pub.data(), eph_pub.size());
  if (!eph_pub_key) {
    QUIC_LOG(ERROR) << "Failed to create EVP_PKEY from ephemeral public key";
    EVP_PKEY_free(server_priv);
    return false;
  }

  // derive the shared secret
  std::array<uint8_t, kKeySize> shared_secret{};
  size_t secret_len = shared_secret.size();
  EVP_PKEY_CTX* derive_ctx = EVP_PKEY_CTX_new(server_priv, nullptr);
  if (!derive_ctx || EVP_PKEY_derive_init(derive_ctx) <= 0 ||
      EVP_PKEY_derive_set_peer(derive_ctx, eph_pub_key) <= 0 ||
      EVP_PKEY_derive(derive_ctx, shared_secret.data(), &secret_len) <= 0) {
    QUIC_LOG(ERROR) << "Failed to derive shared secret";
    EVP_PKEY_free(server_priv);
    EVP_PKEY_free(eph_pub_key);
    EVP_PKEY_CTX_free(derive_ctx);
    return false;
  }
  EVP_PKEY_CTX_free(derive_ctx);
  EVP_PKEY_free(eph_pub_key);
  EVP_PKEY_free(server_priv);

  // use HKDF to get same symmetric key
  std::array<uint8_t, kKeySize> aes_key{};
  EVP_PKEY_CTX* hkdf_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  if (!hkdf_ctx || EVP_PKEY_derive_init(hkdf_ctx) <= 0) return false;
  EVP_PKEY_CTX_set_hkdf_md(hkdf_ctx, EVP_sha256());
  EVP_PKEY_CTX_set1_hkdf_salt(hkdf_ctx, nullptr, 0);
  EVP_PKEY_CTX_set1_hkdf_key(hkdf_ctx, shared_secret.data(), shared_secret.size());
  EVP_PKEY_CTX_add1_hkdf_info(hkdf_ctx,
      reinterpret_cast<const uint8_t*>("protected-initial-ecdh"),
      strlen("protected-initial-ecdh"));
  size_t aes_key_len = aes_key.size();
  if (EVP_PKEY_derive(hkdf_ctx, aes_key.data(), &aes_key_len) <= 0) {
    EVP_PKEY_CTX_free(hkdf_ctx);
    QUIC_LOG(ERROR) << "HKDF derivation failed";
    return false;
  }
  EVP_PKEY_CTX_free(hkdf_ctx);

  // decrypt using AES-256-GCM
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return false;

  int out_len1 = 0;
  int out_len2 = 0;
  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
      EVP_DecryptInit_ex(ctx, nullptr, nullptr, aes_key.data(), iv.data()) != 1 ||
      EVP_DecryptUpdate(ctx, reinterpret_cast<uint8_t*>(output), &out_len1,
                        enc_payload, enc_len) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, kTagSize, tag.data()) != 1 ||
      EVP_DecryptFinal_ex(ctx, reinterpret_cast<uint8_t*>(output) + out_len1, &out_len2) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    QUIC_LOG(ERROR) << "AES-GCM decryption failed";
    return false;
  }

  *output_length = out_len1 + out_len2;
  EVP_CIPHER_CTX_free(ctx);
  return true;



// old code below 
/*
  // cast as a uint8_t pointer for easier byte access
  const uint8_t* data = reinterpret_cast<const uint8_t*>(ciphertext.data());

  // First two bytes are length (in big endian)
  size_t wrapped_key_len = (static_cast<size_t>(data[0]) << 8) | data[1]; // recalculates the length from the big endian format 

  // Error check - amount of data. 
  if (ciphertext.size() < 2 + wrapped_key_len) {
    QUIC_LOG(ERROR) << "Ciphertext too short for wrapped key. Expected at least " 
                    << (2 + wrapped_key_len) << " bytes, got " << ciphertext.size();
    return false;
  }

  // Extract ciphertext and wrapped key
  absl::string_view wrapped_key(reinterpret_cast<const char*>(data + 2), wrapped_key_len);
  absl::string_view actual_ciphertext(reinterpret_cast<const char*>(data + 2 + wrapped_key_len),
                                         ciphertext.size() - 2 - wrapped_key_len);

  
  // Try printing but don't think it'll work... maybe QUIC_LOG ??
  std::cout << "Wrapped key length: " << wrapped_key_len << "\n";
  std::cout << "Actual ciphertext length: " << actual_ciphertext.size() << "\n";

  // Now unwrap the temp key using our private key. 
  // TODO: PUT ACTUAL PRIVATE KEY HERE!!!
  EVP_PKEY *private_key = nullptr;
  
  // Can delete this once we get our private key in there. 
  if (!private_key) {
    QUIC_LOG(ERROR) << "Failed to load private key - you need to implement key loading";
    return false;
  }

  // create new encyrption context for decryption
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(private_key, NULL);
  if (!ctx) {
    QUIC_LOG(ERROR) << "Failed to create EVP_PKEY_CTX";
    EVP_PKEY_free(private_key);
    return false;
  }

  // initialize the decryption operation
  if (EVP_PKEY_decrypt_init(ctx) <= 0) {
    QUIC_LOG(ERROR) << "EVP_PKEY_decrypt_init failed";
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(private_key);
    return false;
  }

  // Do this cause we encrypt with this padding. 
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
    QUIC_LOG(ERROR) << "EVP_PKEY_CTX_set_rsa_padding failed";
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(private_key);
    return false;
  }

  // Determine output length
  size_t temp_key_len;
  if (EVP_PKEY_decrypt(ctx, NULL, &temp_key_len,
                       reinterpret_cast<const uint8_t*>(wrapped_key.data()),
                       wrapped_key.size()) <= 0) {
    QUIC_LOG(ERROR) << "EVP_PKEY_decrypt (length check) failed";
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(private_key);
    return false;
  }

  // Decrypt the wrapped key
  std::vector<uint8_t> temp_key(temp_key_len);
  if (EVP_PKEY_decrypt(ctx, temp_key.data(), &temp_key_len,
                       reinterpret_cast<const uint8_t*>(wrapped_key.data()),
                       wrapped_key.size()) <= 0) {
    QUIC_LOG(ERROR) << "EVP_PKEY_decrypt failed";
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(private_key);
    return false;
  }

  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(private_key);

  std::cout << "Unwrapped temp key length: " << temp_key_len << "\n";

  // Error check our temp key is the correct size (16 bytes for AES-128), probably 32 for AES-256 (TODO: DOUBLE CHECK WHICH WE USE)
  if (temp_key_len != 16) {
    QUIC_LOG(ERROR) << "Unwrapped key has wrong size: " << temp_key_len 
                    << " (expected 16)";
    return false;
  }

  // Now we unwrapped our temp key! Set the AEAD key to the unwrapped temp key
  if (!SetKey(absl::string_view(reinterpret_cast<const char*>(temp_key.data()), 
                                 temp_key_len))) {
    QUIC_LOG(ERROR) << "Failed to set AEAD key";
    return false;
  }

  // Construct the nonce (same as in the base decrypter)
  if (actual_ciphertext.length() < auth_tag_size_) {
    QUIC_LOG(ERROR) << "Ciphertext too short";
    return false;
  }

  if (have_preliminary_key_) {
    QUIC_BUG(quic_bug_10709_3)
        << "Unable to decrypt while key diversification is pending";
    return false;
  }

  uint8_t nonce[kMaxNonceSize];
  memcpy(nonce, iv_, nonce_size_);
  size_t prefix_len = nonce_size_ - sizeof(packet_number);
  
  if (use_ietf_nonce_construction_) {
    for (size_t i = 0; i < sizeof(packet_number); ++i) {
      nonce[prefix_len + i] ^=
          (packet_number >> ((sizeof(packet_number) - i - 1) * 8)) & 0xff;
    }
  } else {
    memcpy(nonce + prefix_len, &packet_number, sizeof(packet_number));
  }

  // YAY now time to decrypt the actual ciphertext
  if (!EVP_AEAD_CTX_open(
          ctx_.get(), 
          reinterpret_cast<uint8_t*>(output), 
          output_length,
          max_output_length, 
          reinterpret_cast<const uint8_t*>(nonce),
          nonce_size_, 
          reinterpret_cast<const uint8_t*>(actual_ciphertext.data()),
          actual_ciphertext.size(),
          reinterpret_cast<const uint8_t*>(associated_data.data()),
          associated_data.size())) {
    // Decryption errors are expected during trial decryption
    using ::quiche::ClearOpenSslErrors;
    ClearOpenSslErrors();
    return false;
  }

  std::cout << "Successfully decrypted packet\n";
  return true;*/
}

// this is required and just defines what cipher suite this decrypter uses. 
uint32_t ProtectedInitialDecrypter::cipher_id() const {
  return TLS1_CK_AES_128_GCM_SHA256;
}

}  // namespace quic
