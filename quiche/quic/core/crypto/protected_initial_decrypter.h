
#ifndef QUICHE_QUIC_CORE_CRYPTO_PROTECTED_INITIAL_DECRYPTER_H_
#define QUICHE_QUIC_CORE_CRYPTO_PROTECTED_INITIAL_DECRYPTER_H_

#include <cstddef>
#include <cstdint>

#include "absl/strings/string_view.h"
#include "openssl/aes.h"
#include "quiche/quic/core/crypto/aead_base_decrypter.h"
#include "quiche/quic/core/crypto/aes_base_decrypter.h"
#include "quiche/quic/platform/api/quic_export.h"

namespace quic {


class QUICHE_EXPORT ProtectedInitialDecrypter : public AesBaseDecrypter {
 public:
  ProtectedInitialDecrypter();
  ProtectedInitialDecrypter(const ProtectedInitialDecrypter&) = delete;
  ProtectedInitialDecrypter& operator=(const ProtectedInitialDecrypter&) = delete;
  ~ProtectedInitialDecrypter() override = default;

  // Override DecryptPacket to handle the custom [len][wrapped_key][ciphertext] format
  bool DecryptPacket(uint64_t packet_number,
                     absl::string_view associated_data,
                     absl::string_view ciphertext, 
                     char* output,
                     size_t* output_length,
                     size_t max_output_length) override;

  uint32_t cipher_id() const override;

 private:
  // The RSA private key corresponding to the public key used in the encrypter
  // This should be set during initialization
  //static const unsigned char SERVER_PRIVATE_KEY[256]; // TODO: Check that this is where we want to store the private key. 
};

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_CRYPTO_PROTECTED_INITIAL_DECRYPTER_H_