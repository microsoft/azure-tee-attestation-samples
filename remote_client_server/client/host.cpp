// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "enclave.h"
#include "enclave_calls.hpp"
#include <string>

#include <grpcpp/grpcpp.h>
#include "secretsharing.grpc.pb.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

using secretsharing::AttestationRequest;
using secretsharing::AttestationReply;
using secretsharing::CommandRequest;
using secretsharing::EncryptedData;
using secretsharing::Reply;
using secretsharing::SecretSharing;

/* enclave as global object for simplicity
 * should create an object to store necessary data with
 * grpc instance
 */
oe_enclave_t* enclave = NULL;

int to_key_kind(int cmd, KeyKind* key_kind) {
    switch (cmd) {
        case CommandRequest::ATTESTATION:
            *key_kind = KeyKind::PEM;
            break;
        case CommandRequest::SYNC_SYM:
            *key_kind = KeyKind::AES;
            break;
        default:
            return -1;
    }
    return 0;
}

void parse_reply(attestation_data_t& at_data, const AttestationReply* reply) {
    at_data.key_kind = static_cast<KeyKind>(reply->key_kind());
    at_data.key_size = reply->key().size();
    at_data.remote_report_size = reply->report().size();
    at_data.key = (uint8_t*)malloc(at_data.key_size * sizeof(uint8_t));
    at_data.remote_report = (uint8_t*)malloc(at_data.remote_report_size * sizeof(uint8_t));
    std::copy(reply->key().begin(), reply->key().end(), at_data.key);
    std::copy(reply->report().begin(), reply->report().end(), at_data.remote_report);
}

class SecretSharingClient {
    public:
        SecretSharingClient(std::shared_ptr<Channel> channel) : stub_(SecretSharing::NewStub(channel)) {}

    int GetAttestation(CommandRequest cmd, attestation_data_t& at_data) {
        AttestationRequest request;
        AttestationReply reply;
        ClientContext context;

        request.set_cmd(cmd);


        std::cout << "Host: [GRPC] - GetAttestation" << std::endl;
        Status status = stub_->GetAttestation(&context, request, &reply);

        if(status.ok()){
            std::cout << "Host: [GRPC] - GetAttestation: " << reply.msg() << std::endl;
            parse_reply(at_data, &reply);
        } else {
            std::cout << "Host: [GRPC] - GetAttestation: " << status.error_code() << ": " << status.error_message() << std::endl;
            return -1;
        }
        return 0;
    }

    int VerifyAttestation(CommandRequest cmd, attestation_data_t& at_data) {
        AttestationRequest request;
        AttestationReply reply;
        ClientContext context;

        std::cout << "Host: [GRPC] - VerifyAttestation" << std::endl;

        request.set_cmd(cmd);
        for (int i = 0; i < at_data.remote_report_size; i++) {
            request.add_report(at_data.remote_report[i]);
        }
        for (int i = 0; i < at_data.key_size; i++) {
            request.add_key(at_data.key[i]);
        }
        Status status = stub_->VerifyAttestation(&context, request, &reply);

        if(status.ok()){
            std::cout << "Host: [GRPC] - VerifyAttestation: " << reply.msg() << std::endl;
        } else {
            std::cout << "Host: [GRPC] - VerifyAttestation: " << status.error_code() << ": " << status.error_message() << std::endl;
            return -1;
        }
        return 0;
    }

    int DecryptAttachedData(const char* input_file) {
        ClientContext context;
        EncryptedData request;
        Reply reply;
        std::vector<uint8_t> f_data_bytes;
        Status status;
        int ret = 0;
        const char* encrypted_filename = "./out.encrypted";

        std::cout << "Host: [GRPC] - DecryptAttachedData" << std::endl;

        if (enclave_a_flow(enclave, input_file, encrypted_filename))
            return -1;

        std::ifstream f_decrypted(input_file);
        std::ifstream f_encrypted(encrypted_filename);

        if (f_encrypted.is_open() == false || f_decrypted.is_open() == false) {
            return -1;
        }
        std::cout << input_file << " content:" << std::endl << f_decrypted.rdbuf() << std::endl;
        f_data_bytes = std::vector<uint8_t>(
                std::istreambuf_iterator<char>(f_encrypted), std::istreambuf_iterator<char>());
        *request.mutable_data() = {f_data_bytes.begin(), f_data_bytes.end()}; //copying file bytes to req.data
        status = stub_->DecryptAttachedData(&context, request, &reply);

        if(status.ok()){
            std::cout << "Host: [GRPC] - DecryptAttachedData: " << reply.msg() << std::endl;
            ret = 0;
            goto exit; //return data
        } else {
            std::cout << "Host: [GRPC] - DecryptAttachedData: " << status.error_code() << ": " << status.error_message() << std::endl;
            ret = -1;
            goto exit;
        }

        exit:
            if (f_decrypted.is_open())
                f_decrypted.close();
            if (f_encrypted.is_open())
                f_encrypted.close();
            return ret;
    }

    private:
        std::unique_ptr<SecretSharing::Stub> stub_;
};

int Run(const char* input_file) {
    std::string address("0.0.0.0:5000");
    SecretSharingClient client(
        grpc::CreateChannel(
            address, 
            grpc::InsecureChannelCredentials()
        )
    );

    attestation_data_t at_data{PEM, NULL, 0, NULL, 0};
    if (client.GetAttestation(CommandRequest{CommandRequest::ATTESTATION}, at_data))
        return 1;

    if (verify_remote_report(enclave, at_data))
        return 1;
    clear_attestation_data(at_data);

    at_data.key_kind = AES;
    if (get_remote_report(enclave, at_data))
        return 1;

    if (client.VerifyAttestation(CommandRequest{CommandRequest::SYNC_SYM}, at_data))
        return 1;

    if (client.DecryptAttachedData(input_file))
        return 1;
    return 0;
}

int main(int argc, const char* argv[])
{
    oe_result_t result = OE_OK;
    int ret = 1;
    attestation_data_t* at_data = new attestation_data_t{PEM, NULL, 0, NULL, 0};

    /* Check argument count */
    if (argc != 3)
    {
        printf("Usage: %s ENCLAVE_PATH FILE_TO_ENCRYPT_PATH\n", argv[0]);
        return ret;
    }

    printf("Host: Creating enclave\n");
    enclave = create_enclave(argv[1]);
    if (enclave == NULL)
    {
        return ret;
    }

    ret = Run(argv[2]);

    printf("Host: Terminating enclaves\n");
    if (enclave)
        terminate_enclave(enclave);

    printf("Host:  %s \n", (ret == 0) ? "succeeded" : "failed");
    return ret;
}
