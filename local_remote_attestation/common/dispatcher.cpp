// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "dispatcher.h"
#include <openenclave/enclave.h>

// name of the enclave, is AES key needs to be initialized.
ecall_dispatcher::ecall_dispatcher(
    const char* name, bool aes_key)
    : m_aes_initialized(false), m_crypto(NULL), m_attestation(NULL), 
    m_encrypt(true), m_header(NULL), m_encryption_key_set(false)
{
    m_initialized = initialize(name);
    if (aes_key)
        m_aes_initialized = intialize_aes_key();
}

ecall_dispatcher::~ecall_dispatcher()
{
    if (m_crypto)
        delete m_crypto;

    if (m_attestation)
        delete m_attestation;
}

bool ecall_dispatcher::intialize_aes_key()
{
    int ret = 0;
    unsigned char iv[IV_SIZE] = {0xb2,
                                 0x4b,
                                 0xf2,
                                 0xf7,
                                 0x7a,
                                 0xc5,
                                 0xec,
                                 0x0c,
                                 0x5e,
                                 0x1f,
                                 0x4d,
                                 0xc1,
                                 0xae,
                                 0x46,
                                 0x5e,
                                 0x75};
    memcpy(m_original_iv, iv, IV_SIZE);

    // produce a symmetric encryption key
    TRACE_ENCLAVE("produce a encryption key");
    ret = generate_encryption_key(
        (unsigned char*)m_encryption_key, ENCRYPTION_KEY_SIZE_IN_BYTES);
    if (ret != 0)
    {
        TRACE_ENCLAVE("enclave: m_encryption_key");
        for (unsigned int i = 0; i < ENCRYPTION_KEY_SIZE_IN_BYTES; i++)
            TRACE_ENCLAVE(
                "m_encryption_key[%d] =0x%02x", i, m_encryption_key[i]);
        return false;
    }

    // initialize aes context
    mbedtls_aes_init(&m_aescontext);
    return true;
}

bool ecall_dispatcher::initialize(const char* name)
{
    m_name = name;
    m_crypto = new Crypto();
    if (m_crypto == NULL)
    {
        return false;
    }

    m_attestation = new Attestation(m_crypto);
    if (m_attestation == NULL)
    {
        return false;
    }

    return true;
}

int ecall_dispatcher::set_encryption_mode(bool encrypt)
{
    int ret = 0;
    TRACE_ENCLAVE(
        "ecall_dispatcher::initialize : %s request",
        encrypt ? "encrypting" : "decrypting");

    m_encrypt = encrypt;

    // set aes key to context object
    if (encrypt)
        ret = mbedtls_aes_setkey_enc(
            &m_aescontext, m_encryption_key, ENCRYPTION_KEY_SIZE);
    else
        ret = mbedtls_aes_setkey_dec(
            &m_aescontext, m_encryption_key, ENCRYPTION_KEY_SIZE);

    if (ret != 0)
    {
        TRACE_ENCLAVE("mbedtls_aes_setkey_dec failed with %d", ret);
        goto exit;
    }
    // init iv
    memcpy(m_operating_iv, m_original_iv, IV_SIZE);
exit:
    return ret;
}

int ecall_dispatcher::get_remote_report_with_key(
    KeyKind key_kind,
    uint8_t** key,
    size_t* key_size,
    uint8_t** remote_report,
    size_t* remote_report_size)
{
    uint8_t pem_public_key[512];
    uint8_t key_buf[512];
    uint8_t* key_ptr = NULL;
    size_t key_buf_size = 0;
    uint8_t* report = NULL;
    size_t report_size = 0;
    int ret = 1;

    TRACE_ENCLAVE("get_remote_report_with_key");
    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed.");
        goto exit;
    }

    if (key_kind == KeyKind::PEM) 
    {
        m_crypto->retrieve_public_key(pem_public_key);
        ret = m_attestation->generate_remote_report(
            pem_public_key, sizeof(pem_public_key), &report, &report_size);
        key_buf_size = sizeof(pem_public_key);
        key_ptr = (uint8_t*)oe_host_malloc(key_buf_size);
        if (key_ptr == NULL)
        {
            ret = OE_OUT_OF_MEMORY;
            goto exit;
        }
        memcpy(key_ptr, pem_public_key, sizeof(pem_public_key));
    }
    else if (key_kind == KeyKind::AES)
    {
        if ((ret = encrypt_symmetric_key(m_crypto->get_the_other_enclave_public_key(), key_buf, &key_buf_size))
             || (ret = m_attestation->generate_remote_report(key_buf, key_buf_size, &report, &report_size)))
             goto exit;
        key_ptr = (uint8_t*)oe_host_malloc(key_buf_size);
        if (key_ptr == NULL)
        {
            ret = OE_OUT_OF_MEMORY;
            goto exit;
        }
        memcpy(key_ptr, key_buf, key_buf_size);
    }

    if (ret == 0)
    {
        // Allocate memory on the host and copy the report over.
        *remote_report = (uint8_t*)oe_host_malloc(report_size);
        if (*remote_report == NULL)
        {
            ret = OE_OUT_OF_MEMORY;
            goto exit;
        }
        memcpy(*remote_report, report, report_size);
        *remote_report_size = report_size;
        oe_free_report(report);

        *key = key_ptr;
        *key_size = key_buf_size;

        ret = 0;
        TRACE_ENCLAVE("get_remote_report_with_key succeeded");
    }
    else
    {
        TRACE_ENCLAVE("get_remote_report_with_key failed.");
    }

exit:
    if (ret != 0)
    {
        if (report)
            oe_free_report(report);
        if (key_ptr)
            oe_host_free(key_ptr);
        if (*remote_report)
            oe_host_free(*remote_report);
    }
    return ret;
}

int ecall_dispatcher::verify_report_and_set_key(
    KeyKind key_kind,
    const uint8_t* key,
    size_t key_size,
    const uint8_t* remote_report,
    size_t remote_report_size)
{
    int ret = 1;

    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed.");
        goto exit;
    }

    // Attest the remote report and accompanying key.
    ret = m_attestation->attest_remote_report(
            remote_report, remote_report_size, key, key_size);
    if (ret == 0 && key_kind == KeyKind::PEM)
    {
        memcpy(m_crypto->get_the_other_enclave_public_key(), key, key_size);
    }
    // If AES key, decrypt it
    else if (ret == 0 && key_kind == KeyKind::AES)
    {
        decrypt_symmetric_key(key, key_size);
    } 
    else
    {
        TRACE_ENCLAVE("verify_report_and_set_key failed.");
        goto exit;
    }
    TRACE_ENCLAVE("verify_report_and_set_key succeeded.");

exit:
    return ret;
}

int ecall_dispatcher::encrypt_block(
    bool encrypt,
    unsigned char* input_buf,
    unsigned char* output_buf,
    size_t size)
{
    int ret = 0;
    ret = mbedtls_aes_crypt_cbc(
        &m_aescontext,
        encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT,
        size,           // input data length in bytes,
        m_operating_iv, // Initialization vector (updated after use)
        input_buf,
        output_buf);
    if (ret != 0)
    {
        TRACE_ENCLAVE("mbedtls_aes_crypt_cbc failed with %d", ret);
    }
    return ret;
}

void ecall_dispatcher::close()
{
    if (m_encrypt)
    {
        oe_host_free(m_header);
        m_header = NULL;
    }

    // free aes context
    mbedtls_aes_free(&m_aescontext);
    TRACE_ENCLAVE("ecall_dispatcher::close");
}

int ecall_dispatcher::encrypt_symmetric_key(
    uint8_t pem_public_key[512],
    uint8_t encrypted_key[512], size_t* size) 
{
    uint8_t key_iv[ENCRYPTION_KEY_SIZE_IN_BYTES + IV_SIZE];
    size_t data_size;

    if (m_aes_initialized == false)
    {
        TRACE_ENCLAVE("encrypt_symmetric_key failed: AES key is not initialized.");
        return 1;
    }
    TRACE_ENCLAVE("Starting encryption of symmetric key");

    // The encrypted data is KEY + ORIGINAL_IV concatenated
    memcpy(key_iv, m_encryption_key, ENCRYPTION_KEY_SIZE_IN_BYTES);
    memcpy(&key_iv[ENCRYPTION_KEY_SIZE_IN_BYTES], m_original_iv, IV_SIZE);
    if (!m_crypto->Encrypt(pem_public_key, key_iv, ENCRYPTION_KEY_SIZE_IN_BYTES + IV_SIZE,
        encrypted_key, &data_size)) {
        return 1;
    }
    TRACE_ENCLAVE("Encrypted symmetric key, data has size %zu B", data_size);
    *size = data_size;
    return 0;
}

int ecall_dispatcher::decrypt_symmetric_key(const uint8_t* encrypted_key, size_t size) 
{
    uint8_t key_iv[2048 * 2]; // RSA Decryption output is up to 2048
    size_t data_size;
    int ret = 0;

    TRACE_ENCLAVE("Starting decryption of symmetric key of size %zu b", size);
    if (!m_crypto->decrypt(encrypted_key, size, &key_iv, &data_size)) {
        return 1;
    }
    TRACE_ENCLAVE("Decrypted symmetric key, data has size %zu B", data_size);
    memcpy(&m_encryption_key, key_iv, ENCRYPTION_KEY_SIZE_IN_BYTES);
    memcpy(&m_original_iv, &key_iv[ENCRYPTION_KEY_SIZE_IN_BYTES], IV_SIZE);
    return ret;
}