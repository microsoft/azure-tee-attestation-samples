#include "enclave.h"

int enclave_b_flow(oe_enclave_t* enclave, const char* encrypted_file,
                    const char* decrypted_file) {
    int ret = 0;

   // encrypt a file
    std::cout << "Host: decrypting file:" << decrypted_file << std::endl;
    ret = encrypt_file(enclave,
        DECRYPT_OPERATION, encrypted_file, decrypted_file);
    if (ret != 0)
    {
        std::cerr << "Host: processFile(DECRYPT_OPERATION) failed with " << ret
             << std::endl;
        return 1;
    }

    std::cout << "Host: decryption was done successfully" << std::endl;
    return ret;
}