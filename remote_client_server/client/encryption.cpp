#include "encryption.h"

// get the file size
int get_file_size(FILE* file, size_t* _file_size)
{
    int ret = 0;
    long int oldpos = 0;

    oldpos = ftell(file);
    ret = fseek(file, 0L, SEEK_END);
    if (ret != 0)
        goto exit;

    *_file_size = (size_t)ftell(file);
    fseek(file, oldpos, SEEK_SET);

exit:
    return ret;
}

// Compare file1 and file2: return 0 if the first file1.size bytes of the file2
// is equal to file1's contents  Otherwise it returns 1
int compare_2_files(const char* first_file, const char* second_file)
{
    int ret = 0;
    std::ifstream f1(first_file, std::ios::binary);
    std::ifstream f2(second_file, std::ios::binary);
    std::vector<uint8_t> f1_data_bytes = std::vector<uint8_t>(
        std::istreambuf_iterator<char>(f1), std::istreambuf_iterator<char>());
    std::vector<uint8_t> f2_data_bytes = std::vector<uint8_t>(
        std::istreambuf_iterator<char>(f2), std::istreambuf_iterator<char>());
    std::vector<uint8_t>::iterator f1iterator = f1_data_bytes.begin();
    std::vector<uint8_t>::iterator f2iterator = f2_data_bytes.begin();

    // compare files
    for (; f1iterator != f1_data_bytes.end() - 1; ++f1iterator, ++f2iterator)
    {
        if (!(*f1iterator == *f2iterator))
        {
            ret = 1;
            break;
        }
    }
    std::cout << "Host: two files are " << ((ret == 0) ? "equal" : "not equal")
         << std::endl;
    return ret;
}

int encrypt_file(
    oe_enclave_t* enclave,
    bool encrypt,
    const char* input_file,
    const char* output_file)
{
    oe_result_t result;
    int ret = 0;
    FILE* src_file = NULL;
    FILE* dest_file = NULL;
    unsigned char* r_buffer = NULL;
    unsigned char* w_buffer = NULL;
    size_t bytes_read;
    size_t bytes_written;
    size_t src_file_size = 0;
    size_t src_data_size = 0;
    size_t leftover_bytes = 0;
    size_t bytes_left = 0;
    size_t requested_read_size = 0;

    // allocate read/write buffers
    r_buffer = new unsigned char[DATA_BLOCK_SIZE];
    if (r_buffer == NULL)
    {
        ret = 1;
        goto exit;
    }

    w_buffer = new unsigned char[DATA_BLOCK_SIZE];
    if (w_buffer == NULL)
    {
        std::cerr << "Host: w_buffer allocation error" << std::endl;
        ret = 1;
        goto exit;
    }

    // open source and dest files
    src_file = fopen(input_file, "rb");
    if (!src_file)
    {
        std::cout << "Host: fopen " << input_file << " failed." << std::endl;
        ret = 1;
        goto exit;
    }

    ret = get_file_size(src_file, &src_file_size);
    if (ret != 0)
    {
        ret = 1;
        goto exit;
    }
    src_data_size = src_file_size;
    dest_file = fopen(output_file, "wb");
    if (!dest_file)
    {
        std::cerr << "Host: fopen " << output_file << " failed." << std::endl;
        ret = 1;
        goto exit;
    }

    // Initialize the encryptor inside the enclave
    // Parameters: encrypt: a bool value to set the encryptor mode, true for
    // encryption and false for decryption
    result = initialize_encryptor(enclave, &ret, encrypt);
    if (result != OE_OK)
    {
        ret = 1;
        goto exit;
    }
    if (ret != 0)
    {
        goto exit;
    }

    leftover_bytes = src_data_size % CIPHER_BLOCK_SIZE;

    std::cout << "Host: leftover_bytes " << leftover_bytes << std::endl;

    // Encrypt each block in the source file and write to the dest_file. Process
    // all the blocks except the last one if its size is not a multiple of
    // CIPHER_BLOCK_SIZE when padding is needed
    bytes_left = src_data_size;

    if (leftover_bytes)
    {
        bytes_left = src_data_size - leftover_bytes;
    }
    requested_read_size = DATA_BLOCK_SIZE;
    std::cout << "Host: start " << (encrypt ? "encrypting" : "decrypting") << std::endl;

    // It loops through DATA_BLOCK_SIZE blocks one at a time then followed by
    // processing the last remaining multiple of CIPHER_BLOCK_SIZE blocks. This
    // loop makes sure all the data is processed except leftover_bytes bytes in
    // the end.
    while (
        (bytes_read = fread(
             r_buffer, sizeof(unsigned char), requested_read_size, src_file)) &&
        bytes_read > 0)
    {
        // Request for the enclave to encrypt or decrypt _input_buffer. The
        // block size (bytes_read), needs to be a multiple of CIPHER_BLOCK_SIZE.
        // In this sample, DATA_BLOCK_SIZE is used except the last block, which
        // will have to pad it to be a multiple of CIPHER_BLOCK_SIZE.
        result = encrypt_block(
            enclave, &ret, encrypt, r_buffer, w_buffer, bytes_read);
        if (result != OE_OK)
        {
            std::cerr << "encrypt_block error 1" << std::endl;
            ret = 1;
            goto exit;
        }
        if (ret != 0)
        {
            std::cerr << "encrypt_block error 1" << std::endl;
            goto exit;
        }

        if ((bytes_written = fwrite(
                 w_buffer, sizeof(unsigned char), bytes_read, dest_file)) !=
            bytes_read)
        {
            std::cerr << "Host: fwrite error  " << output_file << std::endl;
            ret = 1;
            goto exit;
        }
        bytes_left -= bytes_written;
        if (bytes_left == 0)
            break;
        if (bytes_left < DATA_BLOCK_SIZE)
        {
            requested_read_size = bytes_left;
        }
    }

    if (encrypt)
    {
        // The CBC mode for AES assumes that we provide data in blocks of
        // CIPHER_BLOCK_SIZE bytes. This sample uses PKCS#5 padding. Pad the
        // whole CIPHER_BLOCK_SIZE block if leftover_bytes is zero. Pad the
        // (CIPHER_BLOCK_SIZE - leftover_bytes) bytes if leftover_bytes is
        // non-zero.
        size_t padded_byte_count = 0;
        unsigned char plaintext_padding_buf[CIPHER_BLOCK_SIZE];
        unsigned char ciphertext_padding_buf[CIPHER_BLOCK_SIZE];

        memset(ciphertext_padding_buf, 0, CIPHER_BLOCK_SIZE);
        memset(plaintext_padding_buf, 0, CIPHER_BLOCK_SIZE);

        if (leftover_bytes == 0)
            padded_byte_count = CIPHER_BLOCK_SIZE;
        else
            padded_byte_count = CIPHER_BLOCK_SIZE - leftover_bytes;

        std::cout << "Host: Working the last block" << std::endl;
        std::cout << "Host: padded_byte_count " << padded_byte_count << std::endl;
        std::cout << "Host: leftover_bytes " << leftover_bytes << std::endl;

        bytes_read = fread(
            plaintext_padding_buf,
            sizeof(unsigned char),
            leftover_bytes,
            src_file);
        if (bytes_read != leftover_bytes)
            goto exit;

        // PKCS5 Padding
        memset(
            (void*)(plaintext_padding_buf + leftover_bytes),
            padded_byte_count,
            padded_byte_count);

        result = encrypt_block(
            enclave,
            &ret,
            encrypt,
            plaintext_padding_buf,
            ciphertext_padding_buf,
            CIPHER_BLOCK_SIZE);
        if (result != OE_OK)
        {
            ret = 1;
            goto exit;
        }
        if (ret != 0)
        {
            goto exit;
        }

        bytes_written = fwrite(
            ciphertext_padding_buf,
            sizeof(unsigned char),
            CIPHER_BLOCK_SIZE,
            dest_file);
        if (bytes_written != CIPHER_BLOCK_SIZE)
            goto exit;
    }

    std::cout << "Host: done  " << (encrypt ? "encrypting" : "decrypting") << std::endl;

    // close files
    fclose(src_file);
    fclose(dest_file);

exit:
    delete[] r_buffer;
    delete[] w_buffer;
    std::cout << "Host: called close_encryptor" << std::endl;

    result = close_encryptor(enclave);
    if (result != OE_OK)
    {
        ret = 1;
    }
    return ret;
}