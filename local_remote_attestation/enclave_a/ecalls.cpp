// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#include <common/dispatcher.h>
#include <common/secretsharing_t.h>
#include <openenclave/enclave.h>

// Declare a static dispatcher object for enabling
// for better organizing enclave-wise global variables
static ecall_dispatcher dispatcher("EnclaveA", WITH_AES_INIT);

/**
 * In case of PEM key: Return the key of this enclave along with the hash of the key
 * in the enclave's remote report.
 * In case of AES key: Return the encrypted key of this enclave along with the
 * hash of the key in the enclave's remote report.
 * Another enclave can use the remote report to attest the enclave and verify
 * the integrity of the key.
 */
int get_remote_report_with_key(
    KeyKind key_kind,
    uint8_t** key,
    size_t* key_size,
    uint8_t** remote_report,
    size_t* remote_report_size)
{
    return dispatcher.get_remote_report_with_key(
        key_kind, key, key_size, remote_report, remote_report_size);
}

// Attest and store the key of another enclave.
// In case of AES key: decrypt key with private RSA and store it in enclave.
int verify_report_and_set_key(
    KeyKind key_kind,
    const uint8_t* key,
    size_t key_size,
    const uint8_t* remote_report,
    size_t remote_report_size)
{
    return dispatcher.verify_report_and_set_key(
        key_kind, key, key_size, remote_report, remote_report_size);
}

// Set AES context for encryption or decryption
int initialize_encryptor(bool encrypt)
{
    return dispatcher.set_encryption_mode(encrypt);
}

int encrypt_block(
    bool encrypt,
    unsigned char* input_buf,
    unsigned char* output_buf,
    size_t size)
{
    return dispatcher.encrypt_block(encrypt, input_buf, output_buf, size);
}

void close_encryptor()
{
    return dispatcher.close();
}
