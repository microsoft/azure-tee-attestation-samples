#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>
#include <openenclave/host.h>
#include "common/shared.h"

#include "secretsharing_u.h"

#define CIPHER_BLOCK_SIZE 16
#define DATA_BLOCK_SIZE 256
#define ENCRYPT_OPERATION true
#define DECRYPT_OPERATION false

void dump_header(encryption_header_t* _header);
int compare_2_files(const char* first_file, const char* second_file);
int encrypt_file(
    oe_enclave_t* enclave,
    bool encrypt,
    const char* input_file,
    const char* output_file);

#endif