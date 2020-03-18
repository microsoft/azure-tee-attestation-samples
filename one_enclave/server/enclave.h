#ifndef ENCLAVE
#define ENCLAVE

#include <iostream>
#include "encryption.h"

int enclave_b_flow(oe_enclave_t* enclave_b, const char* encrypted_file,
                    const char* decrypted_file);

#endif