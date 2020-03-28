#ifndef ENCLAVE
#define ENCLAVE

#include <iostream>
#include "encryption.h"

int enclave_a_flow(oe_enclave_t* enclave_a, const char* input_file,
                    const char* encrypted_file);

#endif