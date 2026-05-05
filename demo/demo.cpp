#define INTRINHASH_HEADER_ONLY
#include "../intrinhash.h"

#include <stdlib.h>
#include <iostream>

const size_t hash_len = 256 / 8;
uint8_t hash[hash_len];

int main(void) {
	uint64_t seed = 0xc0ffee;

	// Block test
	intrinhash("Hello", 5, seed, hash, hash_len, intrinhash_auto());
	std::cout << "First byte of block hash: " << (unsigned int)hash[0] << "\n";

	// Streaming test
	uint8_t in[256 + 100] = { 0 };
    intrinhash_state ps;
    intrinhash_init(&ps, seed, intrinhash_auto());
	
	// NOTE: All input must be divisible by 256 except the last!
    intrinhash_update(&ps, &in[0], 256);
    intrinhash_update(&ps, &in[256], 100);
    intrinhash_finalize(&ps, hash, hash_len);		
	std::cout << "First byte of streaming hash: " << (unsigned int)hash[0] << "\n";
}
