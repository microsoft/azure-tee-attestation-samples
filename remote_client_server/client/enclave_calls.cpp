#include "enclave_calls.hpp"

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
// the key is passed through untrusted area
// the integrity of the key is validated with the hash of the key,
// passed in report_data
int get_remote_report(oe_enclave_t* enclave, attestation_data_t& at_data)
{
    oe_result_t result = OE_OK;
    int ret = 0;

    printf("Host: Requesting a remote report with the hash of key type %d and the encryption key from "
           "enclave=====\n", at_data.key_kind);
    result = get_remote_report_with_key(
        enclave,
        &ret,
        at_data.key_kind,
        &at_data.key,
        &at_data.key_size,
        &at_data.remote_report,
        &at_data.remote_report_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: get_report_with_key of type %d failed. %s",
            at_data.key_kind, oe_result_str(result));
        return 1;
    }

    if (at_data.key_kind == KeyKind::PEM)
        printf("Host: enclave public key: \n%s", at_data.key);
    return 0;
}

int verify_remote_report(oe_enclave_t* enclave, attestation_data_t& at_data) {
    oe_result_t result = OE_OK;
    int ret = 0;

    printf("Host: Requesting enclave to attest remote report and use the key of type %d=====\n", at_data.key_kind);
    result = verify_report_and_set_key(
        enclave,
        &ret,
        at_data.key_kind,
        at_data.key,
        at_data.key_size,
        at_data.remote_report,
        at_data.remote_report_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: verify_report_and_set_key of type %d failed. %s",
            at_data.key_kind, oe_result_str(result));
        return 1;
    }

    printf("Host: Remote attestation Succeeded\n");
    return 0;
}

void clear_attestation_data(attestation_data_t& at_data) {
    if (at_data.key) {
        free(at_data.key);
        at_data.key = NULL;
    }
    if (at_data.remote_report) {
        free(at_data.remote_report);
        at_data.remote_report = NULL;
    }
}
