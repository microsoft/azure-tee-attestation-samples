// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "enclave.h"

oe_enclave_t* create_enclave(const char* enclave_path)
{
    oe_enclave_t* enclave = NULL;

    printf("Host: Enclave library %s\n", enclave_path);
    oe_result_t result = oe_create_secretsharing_enclave(
        enclave_path,
        OE_ENCLAVE_TYPE_SGX,
        OE_ENCLAVE_FLAG_DEBUG,
        NULL,
        0,
        &enclave);

    if (result != OE_OK)
    {
        printf(
            "Host: oe_create_secretsharing_enclave failed. %s",
            oe_result_str(result));
    }
    else
    {
        printf("Host: Enclave successfully created.\n");
    }
    return enclave;
}

void terminate_enclave(oe_enclave_t* enclave)
{
    oe_terminate_enclave(enclave);
    printf("Host: Enclave successfully terminated.\n");
}

// attests enclave 1 to enclave 2
// the pem_key is passed through untrusted area
// the integrity of the key is validated with the hash of the key,
// passed in report_data
int attest_enclave_1_with_2(
    oe_enclave_t* enclave_1, const char enclave_1_id,
    oe_enclave_t* enclave_2, const char enclave_2_id,
    KeyKind key_kind)
{
    oe_result_t result = OE_OK;
    uint8_t* pem_key = NULL;
    size_t pem_key_size = 0;
    uint8_t* remote_report = NULL;
    size_t remote_report_size = 0;
    int ret = 0;

    printf("Host: Requesting a remote report with the hash of key type %d and the encryption key from "
           "enclave %c=====\n", key_kind, enclave_1_id);
    result = get_remote_report_with_key(
        enclave_1,
        &ret,
        key_kind,
        &pem_key,
        &pem_key_size,
        &remote_report,
        &remote_report_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: get_report_with_key of type %d failed. %s",
            key_kind, oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit_at;
    }

    if (key_kind == KeyKind::PEM)
        printf("Host: enclave %c's public key: \n%s", enclave_1_id, pem_key);

    printf("Host: Requesting enclave %c to attest enclave %c's "
           "remote report and set the key type %d=====\n", enclave_2_id, enclave_1_id, key_kind);
    result = verify_report_and_set_key(
        enclave_2,
        &ret,
        key_kind,
        pem_key,
        pem_key_size,
        remote_report,
        remote_report_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: verify_report_and_set_key of type %d failed. %s",
            key_kind, oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit_at;
    }
    printf("Host: Remote attestation Succeeded\n");

exit_at:
    if (pem_key)
        free(pem_key);

    if (remote_report)
        free(remote_report);
    return ret;
}

int main(int argc, const char* argv[])
{
    oe_enclave_t* enclave_a = NULL;
    oe_enclave_t* enclave_b = NULL;
    oe_result_t result = OE_OK;
    int ret = 1;

    /* Check argument count */
    if (argc != 4)
    {
        printf("Usage: %s ENCLAVE_PATH ENCLAVE_PATH_2 FILE_TO_ENCRYPT_PATH\n", argv[0]);
        return ret;
    }

    printf("Host: Creating two enclaves\n");
    enclave_a = create_enclave(argv[1]);
    if (enclave_a == NULL)
    {
        goto exit;
    }
    enclave_b = create_enclave(argv[2]);
    if (enclave_b == NULL)
    {
        goto exit;
    }

    //attest enclave b to enclave a
    //enclave a gets enclave b's RSA public key
    if (attest_enclave_1_with_2(enclave_b, 'b', enclave_a, 'a', KeyKind::PEM))
        goto exit;

    //encrypt file with enclave a's AES key
    if (enclave_a_flow(enclave_a, argv[3]))
        goto exit; 

    //attest enclave a to enclave b
    //enclave b gets enclave a's AES key encrypted by its RSA pub key
    //AES key is decrypted in enclave and stored
    if (attest_enclave_1_with_2(enclave_a, 'a', enclave_b, 'b', KeyKind::AES))
        goto exit;

    //decrypt file with enclave a's AES key
    if (enclave_b_flow(enclave_b, argv[3]))
        goto exit; 
        
    ret = 0;

exit:

    printf("Host: Terminating enclaves\n");
    if (enclave_a)
        terminate_enclave(enclave_a);

    if (enclave_b)
        terminate_enclave(enclave_b);

    printf("Host:  %s \n", (ret == 0) ? "succeeded" : "failed");
    return ret;
}
