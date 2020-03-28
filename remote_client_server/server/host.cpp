// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "enclave.h"
#include "enclave_calls.hpp"
#include <grpcpp/grpcpp.h>
#include "secretsharing.grpc.pb.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using grpc::StatusCode;

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

void parse_request(attestation_data_t& at_data, const AttestationRequest* request) {
    to_key_kind(request->cmd(), &at_data.key_kind);
    at_data.key_size = request->key().size();
    at_data.remote_report_size = request->report().size();
    at_data.key = (uint8_t*)malloc(at_data.key_size * sizeof(uint8_t));
    at_data.remote_report = (uint8_t*)malloc(at_data.remote_report_size * sizeof(uint8_t));
    std::copy(request->key().begin(), request->key().end(), at_data.key);
    std::copy(request->report().begin(), request->report().end(), at_data.remote_report);
}

uint8_t* parse_encrypted_data(const EncryptedData* request) {
    uint8_t* data = (uint8_t*)malloc(request->data().size() * sizeof(uint8_t));
    std::copy(request->data().begin(), request->data().end(), data);
    return data;
}

class SecretSharingServiceImplementation final : public SecretSharing::Service {
    Status GetAttestation(
        ServerContext* context, 
        const AttestationRequest* request, 
        AttestationReply* reply
    ) override {
        std::cout << "Host: [GRPC] - GetAttestation" << std::endl;
        attestation_data_t at_data{PEM, NULL, 0, NULL, 0};
        if (to_key_kind(request->cmd(), &at_data.key_kind) == -1) {
            return Status(StatusCode::UNIMPLEMENTED, "Unknown command.");
        }

        if (get_remote_report(enclave, at_data)) {
            return Status(StatusCode::INTERNAL, "get_remote_attestation failed.");
        }

        reply->set_ok(true);
        reply->set_key_kind(at_data.key_kind);
        for (int i = 0; i < at_data.remote_report_size; i++) {
            reply->add_report(at_data.remote_report[i]);
        }
        for (int i = 0; i < at_data.key_size; i++) {
            reply->add_key(at_data.key[i]);
        }
        reply->set_msg("Remote report generated successfully.");
        return Status::OK;
    }

    Status VerifyAttestation(
        ServerContext* context, 
        const AttestationRequest* request, 
        AttestationReply* reply
    ) override {
        std::cout << "Host: [GRPC] - VerifyAttestation" << std::endl;
        attestation_data_t at_data{PEM, NULL, 0, NULL, 0};

        if (to_key_kind(request->cmd(), &at_data.key_kind) == -1) {
            return Status(StatusCode::UNIMPLEMENTED, "Unknown command.");
        }
        parse_request(at_data, request);
        if (verify_remote_report(enclave, at_data)) {
            return Status(StatusCode::INTERNAL, "get_remote_attestation failed.");
        }
        clear_attestation_data(at_data);
        reply->set_ok(true);
        reply->set_msg("Remote report verified successfully.");
        return Status::OK;
    }

    Status DecryptAttachedData(
        ServerContext* context, 
        const EncryptedData* request, 
        Reply* reply
    ) override {
        const char* encrypted_filename = "./out.encrypted";
        const char* decrypted_filename = "./out.decrypted";

        std::cout << "Host: [GRPC] - DecryptAttachedData" << std::endl;

        uint8_t *data = parse_encrypted_data(request);
        printf("Received encrypted data content:\n%s\n", data);
        std::ofstream f_encrypted(encrypted_filename);
        if (f_encrypted.is_open() == false) {
            return Status(StatusCode::INTERNAL, "data decryption failed.");
        }
        for (int i = 0; i < request->data().size(); i++) {
            f_encrypted << data[i];
        }
        f_encrypted.close();
        if (enclave_b_flow(enclave, encrypted_filename, decrypted_filename))
            return Status(StatusCode::INTERNAL, "data decryption failed.");

        std::ifstream f_decrypted(decrypted_filename);

        if (f_decrypted.is_open() == false) {
            return Status(StatusCode::INTERNAL, "data decryption failed.");
        }
        std::cout << decrypted_filename << " content:" << std::endl << f_decrypted.rdbuf() << std::endl;
        f_decrypted.close();
        return Status::OK;
    }
};

void Run() {
    std::string address("0.0.0.0:5000");
    SecretSharingServiceImplementation service;

    ServerBuilder builder;

    builder.AddListeningPort(address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);

    std::unique_ptr<Server> server(builder.BuildAndStart());
    std::cout << "Server listening on port: " << address << std::endl;

    server->Wait();
}

int main(int argc, const char* argv[])
{
    oe_result_t result = OE_OK;
    int ret = 1;
    attestation_data_t* at_data = new attestation_data_t{PEM, NULL, 0, NULL, 0};

    /* Check argument count */
    if (argc != 2)
    {
        printf("Usage: %s ENCLAVE_PATH\n", argv[0]);
        return ret;
    }

    printf("Host: Creating enclavee\n");
    enclave = create_enclave(argv[1]);
    if (enclave== NULL)
    {
        goto exit;
    }

    Run();        
    ret = 0;

exit:

    printf("Host: Terminating enclaves\n");
    if (enclave)
        terminate_enclave(enclave);

    printf("Host:  %s \n", (ret == 0) ? "succeeded" : "failed");
    return ret;
}
