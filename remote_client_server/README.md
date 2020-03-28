# Remote Attestation - real world example

The server and client host processes are what drives the enclave app. They are responsible for managing the lifetime of the enclave and invoking enclave ECALLs but should be considered an untrusted component that is never allowed to handle plaintext secrets intended for the enclave.

![Remote Attestation](images/remoteattestation_sample_details.jpg)

## Build and run

You must have CMake and protobuf installed.
Then install gRPC following the guide here https://github.com/grpc/grpc/blob/v1.27.0/BUILDING.md
Last tested version with this sample is 1.27

### CMake

Requirements:
- Requirements from [OpenEnclave](https://github.com/openenclave/openenclave/tree/0.8.2)

For server and client:
```bash
cd remote_client_server
mkdir build && cd build
cmake ..
make run_server
make run_client
```

Note: make sure to have started the server before running the client.
