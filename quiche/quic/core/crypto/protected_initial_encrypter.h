// Header comment TODO Keely

#ifndef QUICHE_QUIC_CORE_CRYPTO_PROTECTED_INITIAL_ENCRYPTER_H_
#define QUICHE_QUIC_CORE_CRYPTO_PROTECTED_INITIAL_ENCRYPTER_H_

#include <cstddef>
#include <array>

#include "absl/strings/string_view.h"
#include "openssl/aes.h"
#include "openssl/evp.h"
#include "openssl/rand.h"
#include "quiche/quic/core/crypto/aead_base_encrypter.h"
#include "quiche/quic/platform/api/quic_export.h"
#include "quiche/quic/core/crypto/aes_base_encrypter.h"
#include "quiche/quic/core/crypto/aes_128_gcm_encrypter.h"

namespace quic {

class QUICHE_EXPORT ProtectedInitialEncrypter : public AesBaseEncrypter {
 public:

  ProtectedInitialEncrypter();

  ProtectedInitialEncrypter(const Aes128GcmEncrypter&) = delete;
  ProtectedInitialEncrypter& operator=(const Aes128GcmEncrypter&) = delete;
 ~ProtectedInitialEncrypter() = default;


  bool EncryptPacket (uint64_t packet_number, absl::string_view associated_data, 
    absl::string_view plaintext, char* output, size_t* output_length, 
    size_t max_output_length) override;

  size_t GetCiphertextSize(size_t plaintext_size) const override;
  size_t GetMaxPlaintextSize(size_t ciphertext_size) const override;

 private:


};

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_CRYPTO_AES_BASE_ENCRYPTER_H_
