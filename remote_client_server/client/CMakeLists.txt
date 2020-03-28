# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_custom_command(OUTPUT secretsharing_u.h secretsharing_u.c secretsharing_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/secretsharing.edl
  COMMAND openenclave::oeedger8r --untrusted ${CMAKE_SOURCE_DIR}/secretsharing.edl)

# Proto file
set(SS_PROTO_PATH "${CMAKE_SOURCE_DIR}/proto/")
set(SS_PROTOS "${SS_PROTO_PATH}secretsharing.proto")

# Generated sources
set(SS_PROTO_SRCS "${PROJECT_BINARY_DIR}/secretsharing.pb.cc")
set(SS_PROTO_HDRS "${PROJECT_BINARY_DIR}/secretsharing.pb.h")
set(SS_GRPC_SRCS "${PROJECT_BINARY_DIR}/secretsharing.grpc.pb.cc")
set(SS_GRPC_HDRS "${PROJECT_BINARY_DIR}/secretsharing.grpc.pb.h")

add_custom_command(
      OUTPUT "${SS_PROTO_SRCS}" "${SS_PROTO_HDRS}" "${SS_GRPC_SRCS}" "${SS_GRPC_HDRS}"
      COMMAND protoc
      ARGS --grpc_out "${PROJECT_BINARY_DIR}"
        --cpp_out "${PROJECT_BINARY_DIR}"
        -I "${SS_PROTO_PATH}"
        --plugin=protoc-gen-grpc="${_GRPC_CPP_PLUGIN_EXECUTABLE}"
        "${SS_PROTOS}"
      DEPENDS "${SS_PROTOS}")

include_directories("${PROJECT_BINARY_DIR}")

add_executable(client_host host.cpp encryption.cpp enclave_a.cpp enclave_calls.cpp ${CMAKE_CURRENT_BINARY_DIR}/secretsharing_u.c
  ${SS_PROTO_SRCS} ${SS_GRPC_SRCS})
target_include_directories(client_host PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../ # For common/shared.h
  ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(client_host openenclave::oehostapp ${_GRPC_GRPCPP_UNSECURE}
  ${_PROTOBUF_LIBPROTOBUF})

if(WIN32)
  add_dcap_client_target(remote_attestation_dcap_target)
  add_dependencies(client_host remote_attestation_dcap_target)
  copy_oedebugrt_target(remote_attestation_oedebugrt_target)
  add_dependencies(client_host remote_attestation_oedebugrt_target)
endif()

