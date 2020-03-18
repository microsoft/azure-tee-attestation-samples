#include <curl/curl.h>
#include <memory>
#include <iostream>
#include <algorithm>
#include "azure_api.h"

int parse_token(const std::string& str, std::string& token) {
    std::string access_token = "access_token";
    size_t pos = str.find(access_token);
    if (pos == std::string::npos) {
        return -1;
    }
    pos += access_token.size() + 3; // size of ":";
    int end = pos;
    while (str[end] != '"' && end < str.size()) {
        end++;
    }
    token = str.substr(pos, end - pos);
    return 0;
}

std::size_t callback(
        const char* in,
        std::size_t size,
        std::size_t num,
        std::string* out)
{
    const std::size_t totalBytes(size * num);
    out->append(in, totalBytes);
    return totalBytes;
}

int aad_get_token(const aad_info_t& add_info, std::string& token, bool verbose) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        printf("curl initialization failure");
        return 1;
    }
    CURLcode res;
    std::string* httpData = new std::string();

    std::string url = "https://login.microsoftonline.com/";
    url += add_info.tenant_id;
    url += "/oauth2/token";
    std::cout << url << std::endl;
    curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

    std::string fields = "grant_type=client_credentials&client_id=";
    fields += add_info.client_id;
    fields += "&client_secret=";
    fields += add_info.client_secret;
    fields += "&resource=";
    fields += add_info.resource;
    
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, fields.c_str());
    curl_easy_setopt(curl, CURLOPT_VERBOSE, verbose);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        printf("curl_easy_perform() failed: %s", curl_easy_strerror(res));
        return 0;
    }

    
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_HTTP_CODE, &http_code);
    if (http_code != 200) {
        printf("\nGot %ld response from %s\n", http_code, url.c_str());
        return 1;
    }
    printf("\nGot successful response from %s\n", url.c_str());

    parse_token(*httpData, token);
    delete httpData;
    
    curl_easy_cleanup(curl);
    return 0;
}

int ptr_arr_to_str(std::string& fields, const uint8_t* data, size_t len) {
    for (int i = 0; i < len; i++) {
        fields += data[i];
    }
}

int aas_request(const attestation_data_t& at_data, const std::string& ad_token,
                std::string& aas_token, bool verbose) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        printf("curl initialization failure");
        return 1;
    }
    CURLcode res;
    std::string* httpData = new std::string();

    constexpr char url[] = "https://aas.us.attest.azure.net/attest/Tee/OpenEnclave?api-version=2018-09-01-preview";
    std::cout << "Curl request to: " << url << std::endl;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);

    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    std::string h_token = "Authorization: Bearer " + ad_token;
    headers = curl_slist_append(headers, h_token.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    std::string fields = "{\"Quote\": \"";
    ptr_arr_to_str(fields, at_data.remote_report, at_data.remote_report_size);
    fields += "\", \"EnclaveHeldData\": \"";
    ptr_arr_to_str(fields, at_data.key, at_data.key_size);
    fields += "\"}";
    //std::cout << fields << std::endl;

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, fields.c_str());
    curl_easy_setopt(curl, CURLOPT_VERBOSE, verbose);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData);

    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        printf("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        return 1;
    }

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_HTTP_CODE, &http_code);
    if (http_code != 200) {
        printf("\nGot %ld response from %s\n", http_code, url);
        return 1;
    }
    printf("\nGot successful response from %s\n", url);
    aas_token = *httpData;
    aas_token.erase(std::remove(aas_token.begin(), aas_token.end(), '\"'), aas_token.end());
    delete httpData;

    curl_easy_cleanup(curl);
    return 0;
}