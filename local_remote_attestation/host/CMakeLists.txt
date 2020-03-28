# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_custom_command(OUTPUT secretsharing_u.h secretsharing_u.c secretsharing_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/secretsharing.edl
  COMMAND openenclave::oeedger8r --untrusted ${CMAKE_SOURCE_DIR}/secretsharing.edl)

add_executable(remote_attestation_host host.cpp encryption.cpp enclave_a.cpp enclave_b.cpp ${CMAKE_CURRENT_BINARY_DIR}/secretsharing_u.c)
target_include_directories(remote_attestation_host PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../ # For common/shared.h
  ${CMAKE_CURRENT_BINARY_DIR})

if(WIN32)
  add_dcap_client_target(remote_attestation_dcap_target)
  add_dependencies(remote_attestation_host remote_attestation_dcap_target)
  copy_oedebugrt_target(remote_attestation_oedebugrt_target)
  add_dependencies(remote_attestation_host remote_attestation_oedebugrt_target)
endif()

target_link_libraries(remote_attestation_host openenclave::oehostapp)
