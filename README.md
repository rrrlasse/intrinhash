**intrinhash** is currently (2026) the fastest quality hashing library for C/C++ on x64/ARM for long inputs.

It's designed for use cases where you need 256-bit collision free hash values at high speed. It is not cryptographic and not competitive for small keys.

It uses AES-NI/VAES256 on x64 and NEON on ARMv8 which covers basically every PC and smartphone from 2013 or later. Only a very slow fallback is supported for other architectures.

### Benchmark and quality
intrinhash passes the xxHash collisionsTest (added [here](https://github.com/rrrlasse/xxHash)).

It also passes SMHasher and the much harder SMHasher3 (added [here](https://github.com/rrrlasse/smhasher3)), even with --extra, for bit lengths 32, 64, 128 and 256. Below is its benchmark on a Core i7 for **alignment 0**. Only a few popular hashes are included for the slower ones:


| Placement | Name | GiB/sec @ 3.5 GHz | Passed tests |
|---:|---|---:|---:|
| 1. | intrinhash-256-vaes | 253 | ✓ 250 / 250 |
| 2. | falkhash1 | 176 | 240 / 250 |
| 3. | gxhash | 173 | 225 / 250 |
| 4. | intrinhash-256-aesni | 170 | ✓ 250 / 250 |
| 5. | falkhash2 | 163 | 244 / 250 |
| 6. | AquaHash | 149 | 195 / 250 |
| 7. | FARSH-32 | 141 | 223 / 250 |
| 8. | CLhash | 99.2 | 64 / 250 |
| 12. | XXH3-128 | 97.4 | 214 / 250 |
| 13. | MeowHash | 96.8 | ✓ 250 / 250 |
| 23. | CityHashCrc-256 | 49.4 | 217 / 238 |
| 28. | MetroHash-128 | 38.8 | 233 / 250 |
| 33. | CityHash-64 | 37.4 | 205 / 250 |
| 66. | rapidhash-micro | 20.1 | ✓ 250 / 250 |
| 68. | wyhash | 20.0 | 235 / 250 |
| 70. | komihash | 18.9 | ✓ 250 / 250 |

It's a header-only library with two methods for integration:

### Simple method
```c
#define INTRINHASH_HEADER_ONLY
#include "intrinhash.h"
```
### Better method
From one compilation unit (.c or .cpp file) of your own choice:
```c
#define INTRINHASH_IMPLEMENTATION
#include "intrinhash.h"
```
From any other compilation unit:
```c
#include "intrinhash.h"
```
### API
The block mode is simply one function:
```
intrinhash("Hello", 5, seed, result, hash_len, intrinhash_auto());
```
Streaming mode lets you call `intrinhash_update()` repeatedly with data:
```
intrinhash_state ps;
intrinhash_init(&ps, seed, intrinhash_auto());
intrinhash_update(&ps, &in[0], 256);
intrinhash_update(&ps, &in[256], 100);
intrinhash_finalize(&ps, result, hash_len);
```
The last parameter lets you select what CPU features to use. You can also simply pass the return value of `intrinhash_auto()`.

There is a requirement that all data passed to `intrinhash_update()` must be **divisible by 256** except the last.
### About
It uses a 2048-bit internal state with 8 lanes that are lightly mixed, at the cost of a more complex and slow finalizer.

This is the very first version and is still in prototype state. Any feedback is welcome.

