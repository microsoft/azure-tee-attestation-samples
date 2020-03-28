#include "enclave.h"

int enclave_b_flow(oe_enclave_t* enclave, const char* input_file) {
    int ret = 0;
    const char* encrypted_file = "./out.encrypted";
    const char* decrypted_file = "./out.decrypted";

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

    // Make sure the decryption is successfull. Input and decrypted files
    // are equal
    std::cout << "Host: compared file:" << decrypted_file
         << " to file:" << input_file << std::endl;
    ret = compare_2_files(input_file, decrypted_file);
    if (ret != 0)
    {
        std::cerr << "Host: checking failed! " << decrypted_file
             << "'s contents are supposed to be same as " << input_file
             << std::endl;
        return 1;
    }
    std::cout << "Host: " << decrypted_file << " is equal to " << input_file
         << " as expected" << std::endl;
    std::cout << "Host: decryption was done successfully" << std::endl;
    return ret;
}