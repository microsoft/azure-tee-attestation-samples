// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <grpcpp/grpcpp.h>
#include <curl/curl.h>
#include "secretsharing.grpc.pb.h"
#include "enclave.h"
#include "enclave_calls.hpp"
#include "azure_api.h"

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

        std::string ad_token;
        aad_info_t aad_info{
            "CLIENT_ID",
            "CLIENT_SECRET",
            "TENANT_ID",
            "AAS_URL"
        };
        if (aad_get_token(aad_info, ad_token)) {
            return Status(StatusCode::INTERNAL, "Could not authenticate to Azure Active Directory.");
        }
        
        std::string aas_token;
        if (aas_request(at_data, ad_token, aas_token) != 0) {
            reply->set_ok(false);
            reply->set_msg("Could not verify report with Azure Attestation Service.");
            return Status::OK;
        }

        reply->set_ok(true);
        reply->set_token(aas_token);
        reply->set_msg("Remote report generated successfully.");
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
