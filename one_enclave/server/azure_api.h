#ifndef AZURE_API_H_
#define AZURE_API_H_

#include <string>
#include "enclave_calls.hpp"

typedef struct _aad_info {
    std::string client_id;
    std::string client_secret;
    std::string tenant_id;
    std::string resource;
} aad_info_t;

int aad_get_token(const aad_info_t& add_info, std::string& token, bool verbose = false);
int aas_request(const attestation_data_t& at_data, const std::string& ad_token,
                std::string& aas_token, bool verbose = false);

#endif /* AZURE_API_H_ */