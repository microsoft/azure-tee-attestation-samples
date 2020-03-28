#include "enclave.h"

int enclave_a_flow(oe_enclave_t* enclave, const char* input_file,
                    const char* encrypted_file) {
    int ret = 0;

   // encrypt a file
    std::cout << "Host: encrypting file:" << input_file
         << " -> file:" << encrypted_file << std::endl;
    ret = encrypt_file(enclave,
        ENCRYPT_OPERATION, input_file, encrypted_file);
    if (ret != 0)
    {
        std::cerr << "Host: processFile(ENCRYPT_OPERATION) failed with " << ret
             << std::endl;
        return 1;
    }

    // Make sure the encryption was doing something. Input and encrypted files
    // are not equal
    std::cout << "Host: compared file:" << encrypted_file
         << " to file:" << input_file << std::endl;
    ret = compare_2_files(input_file, encrypted_file);
    if (ret == 0)
    {
        std::cerr << "Host: checking failed! " << input_file
             << "'s contents are not supposed to be same as " << encrypted_file
             << std::endl;
        return 1;
    }
    std::cout << "Host: " << input_file << " is NOT equal to " << encrypted_file
         << " as expected" << std::endl;
    std::cout << "Host: encryption was done successfully" << std::endl;
    size_t size = 0;
    uint8_t *buff = NULL;
    return 0;
}