// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#pragma once

#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <openenclave/enclave.h>
#include <string>
#include "attestation.h"
#include "crypto.h"
#include "common/shared.h"
#include "common/secretsharing_t.h"

using namespace std;

#define IV_SIZE 16
#define WITH_AES_INIT true
#define WITHOUT_AES_INIT false

class ecall_dispatcher
{
  private:
    bool m_initialized;
    bool m_aes_initialized;
    Crypto* m_crypto;
    Attestation* m_attestation;
    string m_name;
    unsigned char m_other_enclave_mrsigner[32];

    mbedtls_aes_context m_aescontext;
    bool m_encrypt;

    encryption_header_t* m_header;

    // initialization vector
    unsigned char m_original_iv[IV_SIZE];
    unsigned char m_operating_iv[IV_SIZE];

    // key for encrypting  data
    unsigned char m_encryption_key[ENCRYPTION_KEY_SIZE_IN_BYTES];
    bool m_encryption_key_set;


  public:
    ecall_dispatcher(const char* name, bool aes_key);
    ~ecall_dispatcher();
    int set_encryption_mode(bool encrypt);
    int encrypt_block(
        bool encrypt,
        const unsigned char* input_buf,
        unsigned char* output_buf,
        size_t size);
    void close();
    int get_remote_report_with_key(
        KeyKind key_kind,
        uint8_t** key,
        size_t* key_size,
        uint8_t** remote_report,
        size_t* remote_report_size);

  private:
    bool initialize(const char* name);
    bool intialize_aes_key();
    int generate_encryption_key(unsigned char* key, unsigned int key_len);
    int encrypt_symmetric_key(const uint8_t pem_public_key[512],
        uint8_t encrypted_key[512], size_t* size);
    int decrypt_symmetric_key(const uint8_t* encrypted_key, size_t size);
    int Sha256(const uint8_t* data, size_t data_size, uint8_t sha256[32]);
    void dump_data(const char* name, unsigned char* data, size_t data_size);
};
