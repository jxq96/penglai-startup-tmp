#ifndef _ATTEST_H
#define _ATTEST_H

#include "sm/enclave.h"

void hash_enclave(struct enclave_t* enclave, void* hash, uintptr_t nonce);

void hash_shadow_enclave(struct shadow_enclave_t* enclave, void* hash, uintptr_t nonce);

void update_enclave_hash(char *output, void* hash, uintptr_t nonce_arg);

void sign_enclave(void* signature, void* hash);

int verify_enclave(void* signature, void* hash);
// void hash_enclave_pt_attr(struct enclave_t* enclave, void* hash, uintptr_t nonce);

#endif /* _ATTEST_H */
