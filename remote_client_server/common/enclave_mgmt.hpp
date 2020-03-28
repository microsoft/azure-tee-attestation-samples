#ifndef ENCLAVE_MGMT_
#define ENCLAVE_MGMT_

#include <openenclave/host.h>
#include "common/shared.h"

enum KeyKind {
    PEM,
    AES
};

typedef struct _attestation_data
{
    KeyKind key_kind;
    uint8_t* key;
    size_t key_size;
    uint8_t* remote_report;
    size_t remote_report_size;
} attestation_data_t;

void terminate_enclave(oe_enclave_t* enclave);
int get_remote_report(oe_enclave_t* enclave, attestation_data_t* at_data);
int verify_remote_report(oe_enclave_t* enclave, attestation_data_t* at_data);
void clear_attestation_data(attestation_data_t* at_data);

#endif