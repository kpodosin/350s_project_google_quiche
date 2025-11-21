// TODO header comment? 
#include "quiche/quic/core/crypto/protected_initial_encrypter.h"
#include "quiche/quic/core/crypto/aes_base_encrypter.h"

#include <string>
#include <array>
#include <vector>

#include "absl/strings/string_view.h"
#include "openssl/aes.h"
#include "openssl/crypto.h"
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/core/crypto/protected_initial_encrypter.h"
#include "quiche/quic/core/crypto/aes_128_gcm_encrypter.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/common/quiche_crypto_logging.h"
#include <iostream>

namespace quic {

    // const unsigned char SERVER_PUBLIC_KEY[256] = "MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgGPFyw0TjK9XCn+pq/XAyOT4xaKMOrkp8K+vPdrmVHKd2dcpT9IH4fPckzzZ6T1OrJaH5529L5wZ4hh2HGMKinrJHZYZ+ps1ek+/r1i93JrSDJip7L3lE33wW39pFYo8y8WzuwdKGlsAfeG2bR3k1ByiV8n2wJQ5bwQKPVcumMx3AgMBAAE=";

    const char* SERVER_PUBLIC_KEY_PEM = R"(-----BEGIN PUBLIC KEY-----
    MCowBQYDK2VuAyEAxQz3sAKsoJCV3QUf7yVU8rEmphBCJ5N2vQEpou4koxQ=
    -----END PUBLIC KEY-----
    )";

    const char* SERVER_PRIVATE_KEY_PEM = R"(-----BEGIN PRIVATE KEY-----
    MC4CAQAwBQYDK2VuBCIEIKjiUObrpM8EG692XZQpWEl1bbAcQolpgz00tfqQyyNz
    -----END PRIVATE KEY-----
    )"; 
    const size_t kKeySize = 32;
    const size_t kNonceSize = 12;
    const size_t kAuthTagSize = 16;

ProtectedInitialEncrypter::ProtectedInitialEncrypter() : AesBaseEncrypter(EVP_aead_aes_128_gcm(), kKeySize, kAuthTagSize,
                       kNonceSize,
                       /* use_ietf_nonce_construction */ false) {
    static_assert(kKeySize <= kMaxKeySize, "key size too big");
    static_assert(kNonceSize <= kMaxNonceSize, "nonce size too big");
}



bool ProtectedInitialEncrypter::EncryptPacket(uint64_t packet_number,
                                      absl::string_view associated_data,
                                      absl::string_view plaintext, char* output,
                                      size_t* output_length,
                                      size_t max_output_length) {


    // Create ephemeral X25519 public and private key pair with new context
    EVP_PKEY_CTX* eph_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!eph_ctx || EVP_PKEY_keygen_init(eph_ctx) <= 0) {
        QUIC_LOG(ERROR) << "Failed to init ephemeral keygen";
        return false;
    }
    EVP_PKEY* eph_priv = nullptr;
    if (EVP_PKEY_keygen(eph_ctx, &eph_priv) <= 0) {
        QUIC_LOG(ERROR) << "Failed to generate ephemeral key";
        return false;
    }

    std::array<uint8_t, kX25519KeySize> eph_pub_bytes{};
    size_t pub_len = eph_pub_bytes.size();
    if (EVP_PKEY_get_raw_public_key(eph_priv, eph_pub_bytes.data(), &pub_len) <= 0) {
        QUIC_LOG(ERROR) << "Failed to extract ephemeral public key";
        EVP_PKEY_free(eph_priv);
        EVP_PKEY_CTX_free(eph_ctx);
        return false;
    }
    // now we should have matching pub and private keys!

    // now actually load in the server public key
    BIO* bio_pub = BIO_new_mem_buf(SERVER_PUBLIC_KEY_PEM, -1);
    EVP_PKEY* server_pub = PEM_read_bio_PUBKEY(bio_pub, nullptr, nullptr, nullptr);
    BIO_free(bio_pub);
    if (!server_pub) {
        QUIC_LOG(ERROR) << "Failed to load server public key from PEM";
        EVP_PKEY_free(eph_priv);
        EVP_PKEY_CTX_free(eph_ctx);
        return false;
    }

    // using server pubkey and eph privkey get the shared secret
    std::array<uint8_t, kX25519KeySize> shared_secret{};
    size_t secret_len = shared_secret.size();
    EVP_PKEY_CTX* derive_ctx = EVP_PKEY_CTX_new(eph_priv, nullptr);
    if (!derive_ctx || EVP_PKEY_derive_init(derive_ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(derive_ctx, server_pub) <= 0 ||
        EVP_PKEY_derive(derive_ctx, shared_secret.data(), &secret_len) <= 0) {
            QUIC_LOG(ERROR) << "Failed to derive shared secret";
            EVP_PKEY_free(eph_priv);
            EVP_PKEY_free(server_pub);
            EVP_PKEY_CTX_free(eph_ctx);
            EVP_PKEY_CTX_free(derive_ctx);
            return false;
    }

    // use the HKDF on the shared secret to get the symmetric key
    std::array<uint8_t, 32> aes_key{};
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
        QUIC_LOG(ERROR) << "HKDF failed";
        EVP_PKEY_free(eph_priv);
        EVP_PKEY_free(server_pub);
        EVP_PKEY_CTX_free(eph_ctx);
        EVP_PKEY_CTX_free(derive_ctx);
        EVP_PKEY_CTX_free(hkdf_ctx);
        return false;
    }

    // make nonce
    std::array<uint8_t, kIVSize> iv{};
    if (RAND_bytes(iv.data(), iv.size()) != 1) return false;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<uint8_t> ciphertext(plaintext.size());
    int out_len = 0;
    if (!ctx ||
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, aes_key.data(), iv.data()) != 1 ||
        EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len,
                            reinterpret_cast<const uint8_t*>(plaintext.data()),
                            plaintext.size()) != 1 ||
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len, &out_len) != 1) {
        QUIC_LOG(ERROR) << "AES-GCM encryption failed";
        EVP_PKEY_free(eph_priv);
        EVP_PKEY_free(server_pub);
        EVP_PKEY_CTX_free(eph_ctx);
        EVP_PKEY_CTX_free(derive_ctx);
        EVP_PKEY_CTX_free(hkdf_ctx);
        return false;
    }
    // make tag
    std::array<uint8_t, kTagSize> tag{};
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kTagSize, tag.data());
    EVP_CIPHER_CTX_free(ctx);

    // now create the output ciphertext buffer !
    size_t total_len = kX25519KeySize + kIVSize + kTagSize + plaintext.size();
    if (max_output_length < total_len) return false;

    uint8_t* outp = reinterpret_cast<uint8_t*>(output);
    memcpy(outp, eph_pub_bytes.data(), kX25519KeySize);
    memcpy(outp + kX25519KeySize, iv.data(), kIVSize);
    memcpy(outp + kX25519KeySize + kIVSize, tag.data(), kTagSize);
    memcpy(outp + kX25519KeySize + kIVSize + kTagSize, plaintext.data(), plaintext.size());

    *output_length = total_len;

    // cleanup time
    EVP_PKEY_free(eph_priv);
    EVP_PKEY_free(server_pub);
    EVP_PKEY_CTX_free(eph_ctx);
    EVP_PKEY_CTX_free(derive_ctx);
    EVP_PKEY_CTX_free(hkdf_ctx);

    return true;



  // old stuff below. 
  /*// First, create temp key (new)
  uint8_t temp_key[16];
  if (RAND_bytes(temp_key, sizeof(temp_key)) != 1) {
    QUIC_LOG(ERROR) << "RAND_bytes failed getting temp key";
    return false;
  }

  // Second, set the aead key to be this temp key (new)
  if (!SetKey(reinterpret_cast<const char*>(temp_key))) {
    QUIC_LOG(ERROR) << "Failed to set AEAD key.";
    return false;
  }

  // Third, the stuff from the other EncryptPacket code
  size_t ciphertext_size = GetCiphertextSize(plaintext.length());
  if (max_output_length < ciphertext_size) {
    return false;
  }
  // TODO(ianswett): Introduce a check to ensure that we don't encrypt with the
  // same packet number twice.
  alignas(4) char nonce_buffer[kMaxNonceSize];
  memcpy(nonce_buffer, iv_, nonce_size_);
  size_t prefix_len = nonce_size_ - sizeof(packet_number);
  if (use_ietf_nonce_construction_) {
    for (size_t i = 0; i < sizeof(packet_number); ++i) {
      nonce_buffer[prefix_len + i] ^=
          (packet_number >> ((sizeof(packet_number) - i - 1) * 8)) & 0xff;
    }
  } else {
    memcpy(nonce_buffer + prefix_len, &packet_number, sizeof(packet_number));
  }

  std::string ciphertext("a", ciphertext_size);
  if (!Encrypt(absl::string_view(nonce_buffer, nonce_size_), associated_data,
               plaintext, reinterpret_cast<unsigned char*>(&ciphertext[0]))) {
    return false;
  }
  *output_length = ciphertext_size;

  // Below is new - do stuff to organize the output.

  // Fourth, wrap the temp key with the stored public key
  EVP_PKEY *SERVER_PUBLIC_KEY_EVP = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, SERVER_PUBLIC_KEY, sizeof(SERVER_PUBLIC_KEY));
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(SERVER_PUBLIC_KEY_EVP, NULL);
  EVP_PKEY_encrypt_init(ctx);
  EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);

  size_t outlen;
  EVP_PKEY_encrypt(ctx, NULL, &outlen, temp_key, sizeof(temp_key));
  std::vector<uint8_t> wrapped_key(outlen); // encrypted temp key
  EVP_PKEY_encrypt(ctx, wrapped_key.data(), &outlen, temp_key, sizeof(temp_key));
  EVP_PKEY_CTX_free(ctx);

  // Fifth, put the [len][wrapped key][ciphertext] into the output
  if (2 + wrapped_key.size() + ciphertext_size > max_output_length) {
    QUIC_LOG(ERROR) << "Output buffer too small.";
    return false;
  }
  std::cout << "Wrapped key " << wrapped_key.data() << "\n";

  uint8_t* outp = reinterpret_cast<uint8_t*>(output);
  // write big-endian 2-byte length
  outp[0] = static_cast<uint8_t>((wrapped_key.size() >> 8) & 0xff);
  outp[1] = static_cast<uint8_t>(wrapped_key.size() & 0xff);
  memcpy(outp + 2, wrapped_key.data(), wrapped_key.size());
  memcpy(outp + 2 + wrapped_key.size(), ciphertext.data(), ciphertext_size);
  // memcpy(outp, 0, 16);
  *output_length = 2 + wrapped_key.size() + ciphertext_size;
  
  std::cout << "Ciphertext " << ciphertext.data() << "\n";

  std::cout << "Output " << *output;

  // And we're done!!

  return true;*/
}

}  // namespace quic





