# Azure Confidential Computing VM - Env Setup Instructions (Ubuntu 18.0)

Follow [install_oe_sdk-Ubuntu_18.04.md](https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/install_oe_sdk-Ubuntu_18.04.md) instructions to install manually OpenEnclave.

Then install gRPC following these instructions:

Clone gRPC repository with 1.27.2 release tag
```
$ git clone -b 1.27.2 https://github.com/grpc/grpc
$ cd grpc
$ git submodule update --init
```

Install protobuf dependency:
```
$ mkdir -p third_party/protobuf/cmake/build
$ cd third_party/protobuf/cmake/build
$ cmake -Dprotobuf_BUILD_TESTS=OFF -DCMAKE_BUILD_TYPE=Release ..
$ [sudo] make -j4 install
```

Install gRPC from source (reusing protobuf previous installation):
```
$ cd GRPC_DIRECTORY
$ mkdir -p cmake/build
$ cd cmake/build
$ cmake \
  -DCMAKE_BUILD_TYPE=Release \
  -DgRPC_INSTALL=ON \
  -DgRPC_BUILD_TESTS=OFF \
  -DgRPC_SSL_PROVIDER=package \
  -DgRPC_PROTOBUF_PROVIDER=package \
  ../..
$ [sudo] make -j4 install
```

You can now build the sample projects you want.