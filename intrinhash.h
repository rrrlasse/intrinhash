// SPDX-License-Identifier: MIT
// 
// intrinhash v0.01 prototype version - fast hashing library for C/C++ on x64/ARM
//
// Copyright 2026, Lasse Mikkel Reinhold
//
// -----------------------------------------------------------------------------
//
// This is a header-only library. Method 1 (simplest):
//      #define INTRINHASH_HEADER_ONLY
//      #include "intrinhash.h"
//
// Method 2 (best):
//      From one compilation unit (.c or .cpp file) of your own choice:
//      #define INTRINHASH_IMPLEMENTATION
//      #include "intrinhash.h"
//      
//      From any other compilation unit:
//      #include "intrinhash.h"
//
// -----------------------------------------------------------------------------
//
// The hash can be up to 256 bits and passes both SMHasher and the much harder
// SMHasher3 (even with --extra) for all bit lengths. It's not cryptographic.
//
// For performance it needs NEON on ARMv8 or AES-NI OR VAES256 on Intel/AMD which
// covers most PCs and smartphones from 2013 or later.
//
// It's slow for inputs below 200 bytes or so, but here's the SMHasher benchmark
// for its 256 KB test on a Core i7:
//
// intrinhash-128 Alignment   0 - 88.74 bytes/cycle - 289.27 GiB/sec @ 3.5 ghz
// gxhash-64      Alignment   0 - 52.67 bytes/cycle - 171.69 GiB/sec @ 3.5 ghz
// xxh3-128       Alignment   0 - 29.26 bytes/cycle -  95.39 GiB/sec @ 3.5 ghz
//
// It also supports an emergency fallback that runs on anything but run at only
// two gigabytes/s or so
//
// -----------------------------------------------------------------------------
//
// API:
//      Block mode:
//      Simply call intrinhash(in, len, seed, out, hash_len, intrinhash_auto())
//
//      Streaming mode:
//      intrinhash_state ps;
//      intrinhash_init(&ps, seed, intrinhash_auto());
//      intrinhash_update(&ps, in, len);
//      ...
//      intrinhash_update(&ps, in, len);
//      intrinhash_finalize(&ps, out, hash_len);
//
//      The size of all blocks passed to intrinhash_update() must be divisible
//      by 256 except the last call.
//
//      The hash_len is the number of bytes and must be between 1 and 32.
//
//      The intrinhash_auto() function detects CPU features at runtime which can
//      also be set manually through the INTRINHASH_MODE flags - see lower down.
//

#ifndef INTRINHASH_XIMPL_H
#define INTRINHASH_XIMPL_H

#ifdef __cplusplus
extern "C" {
#endif

    // Temporary thing for prototyping
//#define INTRINHASH_XIMPL_DEFINE_MAIN
#ifdef INTRINHASH_XIMPL_DEFINE_MAIN
#define INTRINHASH_HEADER_ONLY
#endif

#if defined(INTRINHASH_IMPLEMENTATION) && defined (INTRINHASH_HEADER_ONLY)
#error You cannot define INTRINHASH_HEADER_ONLY with INTRINHASH_IMPLEMENTATION
#endif

#if defined(INTRINHASH_HEADER_ONLY)

#define INTRINHASH_XIMPL_PUBLIC   static inline
#define INTRINHASH_XIMPL_PRIVATE   static inline

#elif defined(INTRINHASH_IMPLEMENTATION)

#define INTRINHASH_XIMPL_PUBLIC
#define INTRINHASH_XIMPL_PRIVATE static inline

#else

#define INTRINHASH_XIMPL_PUBLIC extern
#define INTRINHASH_XIMPL_PRIVATE static inline

#endif

#include <stdint.h>
#include <stddef.h>
#include <assert.h>

#ifdef __cplusplus
#include <cstring>
#include <cstdlib>
#else
#include <string.h>
#include <stdlib.h>
#endif

#define INTRINHASH_MODE_GENERIC 0 // Emergency fallback (2 gigabyte/s on i7). DOES NOT WORK ON ARM YET
#if defined(__arm__) || defined(__aarch64__)
#define INTRINHASH_MODE_NEONCE 1  // ARMv8, introduced 2011 - 2013
#else
#define INTRINHASH_MODE_AESNI 1   // x64, introduced by Intel/AMD in 2010/2011, 164 gigabyte/s
#define INTRINHASH_MODE_VAES256 2 // x64, introduced by Intel/AMD in 2017/2022, 289 gigabyte/s
#endif
#define INTRINHASH_XPRIV_HIGHEST_MODE 2

    // generic
    typedef struct intrinhash_ximpl_128 {
        uint8_t v[16];
    } intrinhash_ximpl_128;

    typedef struct intrinhash_ximpl_256 {
        intrinhash_ximpl_128 lo;
        intrinhash_ximpl_128 hi;
    } intrinhash_ximpl_256;

    typedef struct intrinhash_ximpl_generic_state {
        intrinhash_ximpl_256 v[8];
    } intrinhash_ximpl_generic_state;

#if defined(__arm__) || defined(__aarch64__)
#include <arm_neon.h>

    typedef struct {
        uint8x16_t v_lo[8];
        uint8x16_t v_hi[8];
    } intrinhash_ximpl_neon_state;

    typedef struct {
        intrinhash_ximpl_neon_state aes256;
        uint64_t seed;
        size_t length;
        int mode;
        int lastodd;
        int inited;
    } intrinhash_state;
#else

#include <immintrin.h>

#if defined(_MSC_VER) || defined(_WIN32)
#include <intrin.h>
#define INTRINHASH_XSAVE
#elif defined(__GNUC__) || defined(__clang__)
#include <cpuid.h>
#define INTRINHASH_XSAVE __attribute__((__target__("xsave")))
#endif

    typedef struct {
        __m256i v[8];
    } intrinhash_ximpl_vaes256_state;

    typedef struct intrinhash_ximpl_m256i {
        __m128i lo, hi;
    } intrinhash_ximpl_m256i;

    typedef struct intrinhash_ximpl_aesni_state {
        intrinhash_ximpl_m256i v[8];
    } intrinhash_ximpl_aesni_state;

    typedef struct intrinhash_state {
        union {
            intrinhash_ximpl_vaes256_state vaes256;
            intrinhash_ximpl_aesni_state aesni;
            intrinhash_ximpl_generic_state generic;
        } state;
        uint64_t seed;
        size_t length;
        int mode;
        int lastodd;
        int inited;
        int finalized;
    } intrinhash_state;
#endif

    INTRINHASH_XIMPL_PUBLIC void intrinhash(const void* in, size_t len, uint64_t seed, void* out, size_t hash_len, int mode);
    INTRINHASH_XIMPL_PUBLIC void intrinhash_finalize(intrinhash_state* ctx, void* hash, size_t hash_len);
    INTRINHASH_XIMPL_PUBLIC void intrinhash_init(intrinhash_state* ctx, uint64_t seed, int mode);
    INTRINHASH_XIMPL_PUBLIC void intrinhash_update(intrinhash_state* ctx, const void* data, size_t len);
    INTRINHASH_XIMPL_PUBLIC int  intrinhash_auto(void);

#if defined(INTRINHASH_HEADER_ONLY) || defined(INTRINHASH_IMPLEMENTATION)

#define INTRINHASH_XIMPL_REPEAT(MAX, X) \
    do { \
        size_t i = 0; if (i < (MAX)) { X } \
        i = 1; if (i < (MAX)) { X } \
        i = 2; if (i < (MAX)) { X } \
        i = 3; if (i < (MAX)) { X } \
        i = 4; if (i < (MAX)) { X } \
        i = 5; if (i < (MAX)) { X } \
        i = 6; if (i < (MAX)) { X } \
        i = 7; if (i < (MAX)) { X } \
    } while (0)

    static const uint64_t intrinhash_ximpl_init_constants[8][4] = {
        {0x082EFA98EC4E6C89ULL, 0xA4093822299F31D0ULL, 0x13198A2E03707344ULL, 0x243F6A8885A308D3ULL},
        {0x3F84D5B5B5470917ULL, 0xC0AC29B7C97C50DDULL, 0xBE5466CF34E90C6CULL, 0x452821E638D01377ULL},
        {0x2155EE07C197CCE2ULL, 0xB49D3E21F2784542ULL, 0xAF16395685459F85ULL, 0x913B01D08F2F35DBULL},
        {0x7E16D142E9439D16ULL, 0x8C161D79E780650EULL, 0x66B0679393B9F27AULL, 0x828D95E98F61D599ULL},
        {0x5A4D5E6F7A8B9C0DULL, 0x458C2C1D2A4D3B4CULL, 0x3D88D701C3024B1EULL, 0xBF58476D1CE08133ULL},
        {0x7E89ABCDEF012345ULL, 0x3456789ABCDEF012ULL, 0xFA72B3C4D5E6F012ULL, 0x1F2E3D4C5B6A7B8CULL},
        {0x66778899AABBCCDDULL, 0x99AABBCCDDEEFF00ULL, 0x1122334455667788ULL, 0x13579BDF02468ACEULL},
        {0xFEDCBA9876543210ULL, 0x0123456789ABCDEFULL, 0x8ACE1357BDF02468ULL, 0xDEADBEEFCAFEBABEULL}
    };

#if defined(__arm__) || defined(__aarch64__)

#define INTRINHASH_NEONCE __attribute__((target("arch=armv8-a+crypto")))

    INTRINHASH_XIMPL_PUBLIC int intrinhash_auto(void) {
        return INTRINHASH_MODE_NEONCE;
    }

    INTRINHASH_NEONCE INTRINHASH_XIMPL_PRIVATE  uint8x16_t intrinhash_ximpl_neon_aesenc(uint8x16_t v, uint8x16_t m) {
        return veorq_u8(vaesmcq_u8(vaeseq_u8(v, vdupq_n_u8(0))), m);
    }

    INTRINHASH_NEONCE INTRINHASH_XIMPL_PRIVATE uint8x16_t intrinhash_ximpl_neon_aesenclast(uint8x16_t v, uint8x16_t m) {
        return veorq_u8(vaeseq_u8(v, vdupq_n_u8(0)), m);
    }

    INTRINHASH_NEONCE INTRINHASH_XIMPL_PRIVATE
        void intrinhash_ximpl_neonce_init(intrinhash_ximpl_neon_state* ctx, uint64_t seed) {
        const uint64_t(*c)[4] = intrinhash_ximpl_init_constants;

        INTRINHASH_XIMPL_REPEAT(8, ctx->v_lo[i] = vld1q_u8((uint8_t*)&c[i][0]););
        INTRINHASH_XIMPL_REPEAT(8, ctx->v_hi[i] = vld1q_u8((uint8_t*)&c[i][2]); );
    }

    INTRINHASH_NEONCE INTRINHASH_XIMPL_PRIVATE void intrinhash_ximpl_neonce_update(intrinhash_ximpl_neon_state* ctx, const void* data, size_t len) {
        uint8x16_t v_lo[8] = {
            ctx->v_lo[0], ctx->v_lo[1], ctx->v_lo[2], ctx->v_lo[3],
            ctx->v_lo[4], ctx->v_lo[5], ctx->v_lo[6], ctx->v_lo[7]
        };

        uint8x16_t v_hi[8] = {
            ctx->v_hi[0], ctx->v_hi[1], ctx->v_hi[2], ctx->v_hi[3],
            ctx->v_hi[4], ctx->v_hi[5], ctx->v_hi[6], ctx->v_hi[7]
        };

        const uint8_t* ptr = (uint8_t*)data;
        const uint8_t* end_ptr = ptr + (len & ~255ULL);

        while (ptr < end_ptr) {
            INTRINHASH_XIMPL_REPEAT(8, v_lo[i] = intrinhash_ximpl_neon_aesenc(v_lo[i], vld1q_u8(ptr + i * 32)););
            INTRINHASH_XIMPL_REPEAT(8, v_hi[i] = intrinhash_ximpl_neon_aesenc(v_hi[i], vld1q_u8(ptr + i * 32 + 16)););

            v_lo[0] = veorq_u8(v_lo[0], v_lo[1]);
            v_hi[0] = veorq_u8(v_hi[0], v_hi[1]);
            v_lo[2] = veorq_u8(v_lo[2], v_lo[3]);
            v_hi[2] = veorq_u8(v_hi[2], v_hi[3]);
            v_lo[4] = veorq_u8(v_lo[4], v_lo[5]);
            v_hi[4] = veorq_u8(v_hi[4], v_hi[5]);
            v_lo[6] = veorq_u8(v_lo[6], v_lo[7]);
            v_hi[6] = veorq_u8(v_hi[6], v_hi[7]);
            ptr += 256;
        }

        len &= 255ULL;

        if (len > 0) {
            if (len >= 128) {
                INTRINHASH_XIMPL_REPEAT(4, v_lo[i] = intrinhash_ximpl_neon_aesenc(v_lo[i], vld1q_u8(ptr + i * 32)););
                INTRINHASH_XIMPL_REPEAT(4, v_hi[i] = intrinhash_ximpl_neon_aesenc(v_hi[i], vld1q_u8(ptr + i * 32 + 16)););
                ptr += 128; len -= 128;
            }

            if (len >= 64) {
                INTRINHASH_XIMPL_REPEAT(2, v_lo[i + 4] = intrinhash_ximpl_neon_aesenc(v_lo[i + 4], vld1q_u8(ptr + (i + 4) * 32)););
                INTRINHASH_XIMPL_REPEAT(2, v_hi[i + 4] = intrinhash_ximpl_neon_aesenc(v_hi[i + 4], vld1q_u8(ptr + (i + 4) * 32 + 16)););
                ptr += 64; len -= 64;
            }

            if (len >= 32) {
                v_lo[6] = intrinhash_ximpl_neon_aesenc(v_lo[6], vld1q_u8(ptr + 0));
                v_hi[6] = intrinhash_ximpl_neon_aesenc(v_hi[6], vld1q_u8(ptr + 16));

                ptr += 32; len -= 32;
            }

            if (len > 0) {
                uint8_t buffer[32] = { 0 };
                memcpy(buffer, ptr, len);

                v_lo[7] = intrinhash_ximpl_neon_aesenc(v_lo[7], vld1q_u8(buffer));
                v_hi[7] = intrinhash_ximpl_neon_aesenc(v_hi[7], vld1q_u8(buffer + 16));
            }

            v_lo[0] = veorq_u8(v_lo[0], v_lo[1]);
            v_hi[0] = veorq_u8(v_hi[0], v_hi[1]);

            v_lo[2] = veorq_u8(v_lo[2], v_lo[3]);
            v_hi[2] = veorq_u8(v_hi[2], v_hi[3]);

            v_lo[4] = veorq_u8(v_lo[4], v_lo[5]);
            v_hi[4] = veorq_u8(v_hi[4], v_hi[5]);

            v_lo[6] = veorq_u8(v_lo[6], v_lo[7]);
            v_hi[6] = veorq_u8(v_hi[6], v_hi[7]);
        }

        for (int i = 0; i < 8; i++) {
            ctx->v_lo[i] = v_lo[i];
            ctx->v_hi[i] = v_hi[i];
        }
    }

    INTRINHASH_XIMPL_PRIVATE void intrinhash_ximpl_neonce_get_bytes(intrinhash_ximpl_neon_state* ctx, uint8_t* out, size_t out_len, uint64_t seed, size_t length)
    {
        assert(out_len <= 32);

        ctx->v_lo[1] = intrinhash_ximpl_neon_aesenc(ctx->v_lo[1], ctx->v_lo[0]);
        ctx->v_hi[1] = intrinhash_ximpl_neon_aesenc(ctx->v_hi[1], ctx->v_hi[0]);

        ctx->v_lo[3] = intrinhash_ximpl_neon_aesenc(ctx->v_lo[3], ctx->v_lo[2]);
        ctx->v_hi[3] = intrinhash_ximpl_neon_aesenc(ctx->v_hi[3], ctx->v_hi[2]);

        ctx->v_lo[5] = intrinhash_ximpl_neon_aesenc(ctx->v_lo[5], ctx->v_lo[4]);
        ctx->v_hi[5] = intrinhash_ximpl_neon_aesenc(ctx->v_hi[5], ctx->v_hi[4]);

        ctx->v_lo[7] = intrinhash_ximpl_neon_aesenc(ctx->v_lo[7], ctx->v_lo[6]);
        ctx->v_hi[7] = intrinhash_ximpl_neon_aesenc(ctx->v_hi[7], ctx->v_hi[6]);

        ctx->v_lo[2] = intrinhash_ximpl_neon_aesenc(ctx->v_lo[2], ctx->v_lo[1]);
        ctx->v_hi[2] = intrinhash_ximpl_neon_aesenc(ctx->v_hi[2], ctx->v_hi[1]);

        ctx->v_lo[4] = intrinhash_ximpl_neon_aesenc(ctx->v_lo[4], ctx->v_lo[3]);
        ctx->v_hi[4] = intrinhash_ximpl_neon_aesenc(ctx->v_hi[4], ctx->v_hi[3]);

        ctx->v_lo[6] = intrinhash_ximpl_neon_aesenc(ctx->v_lo[6], ctx->v_lo[5]);
        ctx->v_hi[6] = intrinhash_ximpl_neon_aesenc(ctx->v_hi[6], ctx->v_hi[5]);

        ctx->v_lo[0] = intrinhash_ximpl_neon_aesenc(ctx->v_lo[0], ctx->v_lo[7]);
        ctx->v_hi[0] = intrinhash_ximpl_neon_aesenc(ctx->v_hi[0], ctx->v_hi[7]);

        uint8x16_t h04l = intrinhash_ximpl_neon_aesenc(ctx->v_lo[0], ctx->v_lo[4]);
        uint8x16_t h04h = intrinhash_ximpl_neon_aesenc(ctx->v_hi[0], ctx->v_hi[4]);

        uint8x16_t h15l = intrinhash_ximpl_neon_aesenc(ctx->v_lo[1], ctx->v_lo[5]);
        uint8x16_t h15h = intrinhash_ximpl_neon_aesenc(ctx->v_hi[1], ctx->v_hi[5]);

        uint8x16_t h26l = intrinhash_ximpl_neon_aesenc(ctx->v_lo[2], ctx->v_lo[6]);
        uint8x16_t h26h = intrinhash_ximpl_neon_aesenc(ctx->v_hi[2], ctx->v_hi[6]);

        uint8x16_t h37l = intrinhash_ximpl_neon_aesenc(ctx->v_lo[3], ctx->v_lo[7]);
        uint8x16_t h37h = intrinhash_ximpl_neon_aesenc(ctx->v_hi[3], ctx->v_hi[7]);

        uint64_t ml[2] = { length ^ 0xFACEB00CULL, seed ^ 0xDEADBEEFULL };

        uint64_t mh[2] = { length, seed };

        uint8x16_t mix_l = vreinterpretq_u8_u64(vld1q_u64(ml));
        uint8x16_t mix_h = vreinterpretq_u8_u64(vld1q_u64(mh));

        h04l = intrinhash_ximpl_neon_aesenc(h04l, mix_l);
        h04h = intrinhash_ximpl_neon_aesenc(h04h, mix_h);

        uint8x16_t hl = intrinhash_ximpl_neon_aesenc(h04l, h15l);
        uint8x16_t hh = intrinhash_ximpl_neon_aesenc(h04h, h15h);

        hl = intrinhash_ximpl_neon_aesenc(hl, h26l);
        hh = intrinhash_ximpl_neon_aesenc(hh, h26h);

        hl = intrinhash_ximpl_neon_aesenc(hl, h37l);
        hh = intrinhash_ximpl_neon_aesenc(hh, h37h);

        uint8x16_t res_l = veorq_u8(hl, hh);
        uint8x16_t res_h = veorq_u8(hh, hl);

        uint8x16_t lo = veorq_u8(res_l, vextq_u8(res_l, res_l, 8));

        uint8x16_t hi = veorq_u8(
            res_h,
            vreinterpretq_u8_u32(
                vrev64q_u32(vreinterpretq_u32_u8(res_h))
            )
        );

        uint8x16_t seedv = vreinterpretq_u8_u64(vdupq_n_u64(seed));

        uint8x16_t r0 = intrinhash_ximpl_neon_aesenc(lo, hi);
        uint8x16_t r1 = intrinhash_ximpl_neon_aesenc(hi, lo);

        uint8x16_t out0 = intrinhash_ximpl_neon_aesenclast(r0, seedv);

        uint8x16_t out1 =
            intrinhash_ximpl_neon_aesenclast(
                r1,
                veorq_u8(
                    seedv,
                    vreinterpretq_u8_u32(vdupq_n_u32(0xA5A5A5A5))
                )
            );

        if (out_len == 8) {
            vst1_u64((uint64_t*)out, vreinterpret_u64_u8(vget_low_u8(out0)));
            return;
        }

        if (out_len == 16) {
            vst1q_u8(out, out0);
            return;
        }

        uint8_t tmp[32];

        vst1q_u8(tmp + 0, out0);
        vst1q_u8(tmp + 16, out1);

        memcpy(out, tmp, out_len <= 32 ? out_len : 32);
    }

#else
    /// <summary>
    /// Detect NEON/AES-NI/VAES CPU features. Pass the result of this funtion to intrinhash() and intrinhash_init() as the mode parameter
    /// </summary>
    /// <param name=""></param>
    /// <returns>INTRINHASH_MODE_GENERIC, INTRINHASH_MODE_NEONCE, INTRINHASH_MODE_AESNI or INTRINHASH_MODE_VAES256</returns>
    INTRINHASH_XSAVE INTRINHASH_XIMPL_PUBLIC int intrinhash_auto(void) {
        long result = -1;

        // --- Fast Path ---
#ifdef _WIN32
        long current_mode = result;
        _ReadWriteBarrier();
#else
        long current_mode = __atomic_load_n(&result, __ATOMIC_ACQUIRE);
#endif

        if (current_mode != -1) {
            return (int)current_mode;
        }

        int f1[4] = { 0 };
        int f7[4] = { 0 };

#ifdef _WIN32
        __cpuidex(f1, 1, 0);
        __cpuidex(f7, 7, 0);
#else
        __cpuid_count(1, 0, f1[0], f1[1], f1[2], f1[3]);
        __cpuid_count(7, 0, f7[0], f7[1], f7[2], f7[3]);
#endif

        int has_aesni = (f1[2] & (1 << 25)) != 0;
        int has_osxsave = (f1[2] & (1 << 27)) != 0;
        int has_avx = (f1[2] & (1 << 28)) != 0;
        int os_saves_avx = 0;

        if (has_osxsave && has_avx) {
            unsigned long long xcr0 = (unsigned long long)_xgetbv(0);
            if ((xcr0 & 0x6) == 0x6) {
                os_saves_avx = 1;
            }
        }

        int has_avx2 = os_saves_avx && ((f7[1] & (1 << 5)) != 0);
        long detected_mode = INTRINHASH_MODE_GENERIC;

        if (has_avx2 && has_aesni)      detected_mode = INTRINHASH_MODE_VAES256;
        else if (has_aesni)             detected_mode = INTRINHASH_MODE_AESNI;
        else                            detected_mode = INTRINHASH_MODE_GENERIC;
#ifdef _WIN32
        _InterlockedExchange(&result, detected_mode);
#else
        __atomic_store_n(&result, detected_mode, __ATOMIC_RELEASE);
#endif

        return (int)detected_mode;
    }

#ifndef _WIN32
#define INTRINHASH_XIMPL_SSE42 __attribute__((target("sse4.2,aes")))
#define INTRINHASH_XIMPL_VAES __attribute__((target("avx2,aes,vaes")))
#else
#define INTRINHASH_XIMPL_SSE42 
#define INTRINHASH_XIMPL_VAES
#endif


    INTRINHASH_XIMPL_VAES INTRINHASH_XIMPL_PRIVATE void intrinhash_ximpl_vaes_init(intrinhash_ximpl_vaes256_state* ctx) {
        const uint64_t(*c)[4] = intrinhash_ximpl_init_constants;
        INTRINHASH_XIMPL_REPEAT(8, ctx->v[i] = _mm256_set_epi64x((long long)c[i][3], (long long)c[i][2], (long long)c[i][1], (long long)c[i][0]););
    }


    INTRINHASH_XIMPL_VAES INTRINHASH_XIMPL_PRIVATE void intrinhash_ximpl_vaes_update(intrinhash_ximpl_vaes256_state* ctx, const void* data, size_t len) {
        const uint8_t* ptr = (uint8_t*)data;
        const uint8_t* end_ptr = ptr + (len & ~255ULL);
        len &= 255ULL;

        if (ptr < end_ptr) {
            __m256i r[8];
            INTRINHASH_XIMPL_REPEAT(8, r[i] = ctx->v[i];);
            while (ptr < end_ptr) {
                INTRINHASH_XIMPL_REPEAT(8, r[i] = _mm256_aesenc_epi128(r[i], _mm256_loadu_si256((__m256i*)(ptr + 32 * i))););
                INTRINHASH_XIMPL_REPEAT(4, r[i * 2] = _mm256_xor_si256(r[i * 2], r[i * 2 + 1]););
                ptr += 256;
            }
            INTRINHASH_XIMPL_REPEAT(8, ctx->v[i] = r[i];);
        }

        if (len > 0) {
            if (len >= 128) {
                INTRINHASH_XIMPL_REPEAT(4, ctx->v[i] = _mm256_aesenc_epi128(ctx->v[i], _mm256_loadu_si256((__m256i*)(ptr + 32 * i))););
                ptr += 128;
                len -= 128;
            }

            if (len >= 64) {
                INTRINHASH_XIMPL_REPEAT(2, ctx->v[i + 4] = _mm256_aesenc_epi128(ctx->v[i + 4], _mm256_loadu_si256((__m256i*)(ptr + 32 * i))););
                ptr += 64;
                len -= 64;
            }

            if (len >= 32) {
                ctx->v[6] = _mm256_aesenc_epi128(ctx->v[6], _mm256_loadu_si256((__m256i*)ptr));
                ptr += 32;
                len -= 32;
            }

            if (len > 0) {
                __m256i m = _mm256_setzero_si256();
                memcpy(&m, ptr, len);
                ctx->v[7] = _mm256_aesenc_epi128(ctx->v[7], m);
            }

            INTRINHASH_XIMPL_REPEAT(4, ctx->v[i * 2] = _mm256_xor_si256(ctx->v[i * 2], ctx->v[i * 2 + 1]););
        }
    }

    INTRINHASH_XIMPL_VAES INTRINHASH_XIMPL_PRIVATE void intrinhash_ximpl_vaes_finalize(intrinhash_ximpl_vaes256_state* ctx, uint8_t* out, size_t out_len, uint64_t seed, size_t length) {
        INTRINHASH_XIMPL_REPEAT(4, ctx->v[i * 2 + 1] = _mm256_aesenc_epi128(ctx->v[i * 2 + 1], ctx->v[i * 2]););
        INTRINHASH_XIMPL_REPEAT(3, ctx->v[i * 2 + 2] = _mm256_aesenc_epi128(ctx->v[i * 2 + 2], ctx->v[i * 2 + 1]););
        ctx->v[0] = _mm256_aesenc_epi128(ctx->v[0], ctx->v[7]);

        __m256i h04 = _mm256_aesenc_epi128(ctx->v[0], ctx->v[4]);
        __m256i h15 = _mm256_aesenc_epi128(ctx->v[1], ctx->v[5]);
        __m256i h26 = _mm256_aesenc_epi128(ctx->v[2], ctx->v[6]);
        __m256i h37 = _mm256_aesenc_epi128(ctx->v[3], ctx->v[7]);

        __m256i mix_vec = _mm256_set_epi64x((long long)seed, (long long)length, (long long)(seed ^ 0xDEADBEEF), (long long)(length ^ 0xFACEB00C));

        h04 = _mm256_aesenc_epi128(h04, mix_vec);

        __m256i h = _mm256_aesenc_epi128(h04, h15);
        h = _mm256_aesenc_epi128(h, h26);
        h = _mm256_aesenc_epi128(h, h37);

        h = _mm256_xor_si256(h, _mm256_permute2x128_si256(h, h, 0x01));

        __m128i lo = _mm256_castsi256_si128(h);
        __m128i hi = _mm256_extracti128_si256(h, 1);

        lo = _mm_xor_si128(lo, _mm_shuffle_epi32(lo, 0x4E));
        hi = _mm_xor_si128(hi, _mm_shuffle_epi32(hi, 0xB1));

        __m128i seedv = _mm_set1_epi64x((long long)seed);

        __m128i res0 = _mm_aesenc_si128(lo, hi);
        __m128i res1 = _mm_aesenc_si128(hi, lo);

        res0 = _mm_aesenclast_si128(res0, seedv);
        res1 = _mm_aesenclast_si128(res1, _mm_xor_si128(seedv, _mm_set1_epi32((int)0xA5A5A5A5)));

        if (out_len == 8) {
            *(uint64_t*)out = (uint64_t)_mm_cvtsi128_si64(res0);
            return;
        }

        if (out_len == 16) {
            _mm_storeu_si128((__m128i*)out, res0);
            return;
        }
        uint8_t tmp[32];
        _mm_storeu_si128((__m128i*)(tmp + 0), res0);
        _mm_storeu_si128((__m128i*)(tmp + 16), res1);
        memcpy(out, tmp, out_len <= 32 ? out_len : 32);
    }

    INTRINHASH_XIMPL_PRIVATE  intrinhash_ximpl_m256i intrinhash_ximpl_aesni_make(__m128i lo, __m128i hi) {
        intrinhash_ximpl_m256i v;
        v.lo = lo;
        v.hi = hi;
        return v;
    }

    // _mm256_setzero_si256
    INTRINHASH_XIMPL_PRIVATE  intrinhash_ximpl_m256i intrinhash_ximpl_aesni_zero(void) {
        return intrinhash_ximpl_aesni_make(_mm_setzero_si128(), _mm_setzero_si128());
    }

    // _mm256_set_epi64x
    INTRINHASH_XIMPL_PRIVATE  intrinhash_ximpl_m256i intrinhash_ximpl_aesni_set(long long q3, long long q2, long long q1, long long q0) {
        return intrinhash_ximpl_aesni_make(_mm_set_epi64x(q1, q0), _mm_set_epi64x(q3, q2));
    }

    // _mm256_loadu_si256
    INTRINHASH_XIMPL_PRIVATE  intrinhash_ximpl_m256i intrinhash_ximpl_aesni_load(const void* ptr) {
        return intrinhash_ximpl_aesni_make(
            _mm_loadu_si128((__m128i*)ptr),
            _mm_loadu_si128((__m128i*)((const char*)ptr + 16))
        );
    }

    // _mm256_aesenc_epi128
    INTRINHASH_XIMPL_SSE42 INTRINHASH_XIMPL_PRIVATE  intrinhash_ximpl_m256i intrinhash_ximpl_aesni_aesenc(intrinhash_ximpl_m256i v, intrinhash_ximpl_m256i m) {
        return intrinhash_ximpl_aesni_make(_mm_aesenc_si128(v.lo, m.lo), _mm_aesenc_si128(v.hi, m.hi));
    }

    // _mm256_xor_si256
    INTRINHASH_XIMPL_PRIVATE  intrinhash_ximpl_m256i intrinhash_ximpl_aesni_xor(intrinhash_ximpl_m256i a, intrinhash_ximpl_m256i b) {
        return intrinhash_ximpl_aesni_make(_mm_xor_si128(a.lo, b.lo), _mm_xor_si128(a.hi, b.hi));
    }

    // _mm256_permute2x128_si256 for imm = 0x01
    INTRINHASH_XIMPL_PRIVATE  intrinhash_ximpl_m256i intrinhash_ximpl_aesni_swap(intrinhash_ximpl_m256i a, intrinhash_ximpl_m256i b) {
        return intrinhash_ximpl_aesni_make(b.hi, a.lo);
    }

    // _mm256_castsi256_si128
    INTRINHASH_XIMPL_PRIVATE  __m128i intrinhash_ximpl_aesni_cast(intrinhash_ximpl_m256i v) {
        return v.lo;
    }

    // _mm256_extracti128_si256
    INTRINHASH_XIMPL_PRIVATE  __m128i intrinhash_ximpl_aesni_extract(intrinhash_ximpl_m256i v, int imm) {
        return (imm == 0) ? v.lo : v.hi;
    }

    INTRINHASH_XIMPL_SSE42 INTRINHASH_XIMPL_PRIVATE  void intrinhash_ximpl_aesni_init(intrinhash_ximpl_aesni_state* ctx) {
        const uint64_t(*c)[4] = intrinhash_ximpl_init_constants;
        INTRINHASH_XIMPL_REPEAT(8, ctx->v[i] = intrinhash_ximpl_aesni_set((long long)c[i][3], (long long)c[i][2], (long long)c[i][1], (long long)c[i][0]););

    }

    INTRINHASH_XIMPL_SSE42 INTRINHASH_XIMPL_PRIVATE  void intrinhash_ximpl_aesni_update(intrinhash_ximpl_aesni_state* ctx, const void* data, size_t len) {
        const uint8_t* ptr = (uint8_t*)data;
        const uint8_t* end_ptr = ptr + (len & ~255ULL);
        len &= 255ULL;

        if (ptr < end_ptr) {
            intrinhash_ximpl_m256i v[8];
            INTRINHASH_XIMPL_REPEAT(8, v[i] = ctx->v[i];);

            while (ptr < end_ptr) {
                INTRINHASH_XIMPL_REPEAT(8, v[i] = intrinhash_ximpl_aesni_aesenc(v[i], intrinhash_ximpl_aesni_load((ptr + 32 * i))););
                INTRINHASH_XIMPL_REPEAT(4, v[i * 2] = intrinhash_ximpl_aesni_xor(v[i * 2], v[i * 2 + 1]););
                ptr += 256;
            }
            INTRINHASH_XIMPL_REPEAT(8, ctx->v[i] = v[i];);
        }

        if (len > 0) {
            if (len >= 128) {
                INTRINHASH_XIMPL_REPEAT(4, ctx->v[i] = intrinhash_ximpl_aesni_aesenc(ctx->v[i], intrinhash_ximpl_aesni_load((ptr + 32 * i))););
                ptr += 128; len -= 128;
            }

            if (len >= 64) {
                INTRINHASH_XIMPL_REPEAT(2, ctx->v[i + 4] = intrinhash_ximpl_aesni_aesenc(ctx->v[i + 4], intrinhash_ximpl_aesni_load((ptr + 32 * i))););
                ptr += 64; len -= 64;
            }

            if (len >= 32) {
                ctx->v[6] = intrinhash_ximpl_aesni_aesenc(ctx->v[6], intrinhash_ximpl_aesni_load((intrinhash_ximpl_m256i*)ptr));
                ptr += 32; len -= 32;
            }

            if (len > 0) {
                intrinhash_ximpl_m256i m = intrinhash_ximpl_aesni_zero();
                memcpy(&m, ptr, len);
                ctx->v[7] = intrinhash_ximpl_aesni_aesenc(ctx->v[7], m);
            }

            INTRINHASH_XIMPL_REPEAT(4, ctx->v[i * 2] = intrinhash_ximpl_aesni_xor(ctx->v[i * 2], ctx->v[i * 2 + 1]););
        }
    }


    INTRINHASH_XIMPL_SSE42 INTRINHASH_XIMPL_PRIVATE  void intrinhash_ximpl_aesni_finalize(intrinhash_ximpl_aesni_state* ctx, uint8_t* out, size_t out_len, uint64_t seed, size_t length) {
        INTRINHASH_XIMPL_REPEAT(4, ctx->v[i * 2 + 1] = intrinhash_ximpl_aesni_aesenc(ctx->v[i * 2 + 1], ctx->v[i * 2]););
        INTRINHASH_XIMPL_REPEAT(4, size_t idx = (i == 3) ? 0 : (i * 2 + 2); ctx->v[idx] = intrinhash_ximpl_aesni_aesenc(ctx->v[idx], ctx->v[i * 2 + 1]););

        intrinhash_ximpl_m256i h04 = intrinhash_ximpl_aesni_aesenc(ctx->v[0], ctx->v[4]);
        intrinhash_ximpl_m256i h15 = intrinhash_ximpl_aesni_aesenc(ctx->v[1], ctx->v[5]);
        intrinhash_ximpl_m256i h26 = intrinhash_ximpl_aesni_aesenc(ctx->v[2], ctx->v[6]);
        intrinhash_ximpl_m256i h37 = intrinhash_ximpl_aesni_aesenc(ctx->v[3], ctx->v[7]);

        intrinhash_ximpl_m256i mix_vec = intrinhash_ximpl_aesni_set(
            (long long)seed,
            (long long)length,
            (long long)(seed ^ 0xDEADBEEF),
            (long long)(length ^ 0xFACEB00C)
        );

        h04 = intrinhash_ximpl_aesni_aesenc(h04, mix_vec);

        intrinhash_ximpl_m256i h = intrinhash_ximpl_aesni_aesenc(h04, h15);
        h = intrinhash_ximpl_aesni_aesenc(h, h26);
        h = intrinhash_ximpl_aesni_aesenc(h, h37);

        h = intrinhash_ximpl_aesni_xor(h, intrinhash_ximpl_aesni_swap(h, h));

        __m128i lo = intrinhash_ximpl_aesni_cast(h);
        __m128i hi = intrinhash_ximpl_aesni_extract(h, 1);

        lo = _mm_xor_si128(lo, _mm_shuffle_epi32(lo, 0x4E));
        hi = _mm_xor_si128(hi, _mm_shuffle_epi32(hi, 0xB1));

        __m128i seedv = _mm_set1_epi64x((long long)seed);

        __m128i res0 = _mm_aesenc_si128(lo, hi);
        __m128i res1 = _mm_aesenc_si128(hi, lo);

        res0 = _mm_aesenclast_si128(res0, seedv);
        res1 = _mm_aesenclast_si128(res1, _mm_xor_si128(seedv, _mm_set1_epi32((int)0xA5A5A5A5)));

        if (out_len == 8) {
            *(uint64_t*)out = (uint64_t)_mm_cvtsi128_si64(res0);
            return;
        }

        if (out_len == 16) {
            _mm_storeu_si128((__m128i*)out, res0);
            return;
        }
        uint8_t tmp[32];
        _mm_storeu_si128((__m128i*)(tmp + 0), res0);
        _mm_storeu_si128((__m128i*)(tmp + 16), res1);
        memcpy(out, tmp, out_len <= 32 ? out_len : 32);
    }

    static const uint8_t intrinhash_ximpl_sbox[256] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };

#define intrinhash_ximpl_AES_XTIME(x) (uint8_t)(((x) << 1) ^ (((x) & 0x80) ? 0x1b : 0x00))

    INTRINHASH_XIMPL_PRIVATE void
        intrinhash_ximpl_generic_subbytes_shiftrows(const uint8_t* s, uint8_t* t) {
        const uint8_t* b = intrinhash_ximpl_sbox;
        t[0] = b[s[0]];   t[1] = b[s[5]];   t[2] = b[s[10]];  t[3] = b[s[15]];
        t[4] = b[s[4]];   t[5] = b[s[9]];   t[6] = b[s[14]];  t[7] = b[s[3]];
        t[8] = b[s[8]];   t[9] = b[s[13]];  t[10] = b[s[2]];   t[11] = b[s[7]];
        t[12] = b[s[12]];  t[13] = b[s[1]];   t[14] = b[s[6]];   t[15] = b[s[11]];
    }

    INTRINHASH_XIMPL_PRIVATE intrinhash_ximpl_128 emu_xor_si128(intrinhash_ximpl_128 a, intrinhash_ximpl_128 b) {
        intrinhash_ximpl_128 res;
        uint64_t ak, bk, resk;
        memcpy(&ak, &a.v[0], 8);
        memcpy(&bk, &b.v[0], 8);
        resk = ak ^ bk;
        memcpy(&res.v[0], &resk, 8);
        memcpy(&ak, &a.v[8], 8);
        memcpy(&bk, &b.v[8], 8);
        resk = ak ^ bk;
        memcpy(&res.v[8], &resk, 8);
        return res;
    }

    INTRINHASH_XIMPL_PRIVATE intrinhash_ximpl_128 intrinhash_ximpl_generic_aesenc_128(intrinhash_ximpl_128 state, intrinhash_ximpl_128 key) {
        uint8_t t[16];
        intrinhash_ximpl_128 interim_res;
        intrinhash_ximpl_generic_subbytes_shiftrows(state.v, t);
        for (int i = 0; i < 4; i++) {
            uint8_t a = t[i * 4 + 0];
            uint8_t b = t[i * 4 + 1];
            uint8_t c = t[i * 4 + 2];
            uint8_t d = t[i * 4 + 3];

            uint8_t h = a ^ b ^ c ^ d;

            interim_res.v[i * 4 + 0] = a ^ h ^ intrinhash_ximpl_AES_XTIME(a ^ b);
            interim_res.v[i * 4 + 1] = b ^ h ^ intrinhash_ximpl_AES_XTIME(b ^ c);
            interim_res.v[i * 4 + 2] = c ^ h ^ intrinhash_ximpl_AES_XTIME(c ^ d);
            interim_res.v[i * 4 + 3] = d ^ h ^ intrinhash_ximpl_AES_XTIME(d ^ a);
        }
        return emu_xor_si128(interim_res, key);
    }

    INTRINHASH_XIMPL_PRIVATE intrinhash_ximpl_128 intrinhash_ximpl_generic_aesenclast_128(intrinhash_ximpl_128 state, intrinhash_ximpl_128 key) {
        uint8_t s[16], t[16];
        memcpy(s, state.v, 16);

        intrinhash_ximpl_generic_subbytes_shiftrows(s, t);
        intrinhash_ximpl_128 interim_res;
        memcpy(interim_res.v, t, 16);
        return emu_xor_si128(interim_res, key);
    }

    INTRINHASH_XIMPL_PRIVATE intrinhash_ximpl_128 emu_set_epi64x(long long upper, long long lower) {
        intrinhash_ximpl_128 res;
        memcpy(&res.v[0], &lower, 8);
        memcpy(&res.v[8], &upper, 8);
        return res;
    }

    // _mm256_setzero_si256
    INTRINHASH_XIMPL_PRIVATE intrinhash_ximpl_256 intrinhash_ximpl_generic_zero(void) {
        intrinhash_ximpl_256 r;
        r.hi = emu_set_epi64x(0, 0);
        r.lo = emu_set_epi64x(0, 0);
        return r;
    }

    INTRINHASH_XIMPL_PRIVATE intrinhash_ximpl_256 intrinhash_ximpl_generic_set(long long q3, long long q2, long long q1, long long q0) {
        intrinhash_ximpl_256 r;
        r.lo = emu_set_epi64x(q1, q0);
        r.hi = emu_set_epi64x(q3, q2);
        return r;
    }


    // _mm256_loadu_si256
    INTRINHASH_XIMPL_PRIVATE intrinhash_ximpl_256 intrinhash_ximpl_generic_load(const void* ptr) {
        intrinhash_ximpl_256 r;
        memcpy(r.lo.v, ptr, 16);
        memcpy(r.hi.v, (const char*)ptr + 16, 16);
        return r;
    }


    // _mm256_xor_si256
    INTRINHASH_XIMPL_PRIVATE intrinhash_ximpl_256 intrinhash_ximpl_generic_xor(intrinhash_ximpl_256 a, intrinhash_ximpl_256 b) {
        intrinhash_ximpl_256 r;
        r.lo = emu_xor_si128(a.lo, b.lo);
        r.hi = emu_xor_si128(a.hi, b.hi);
        return r;
    }

    // _mm256_aesenc_epi128
    INTRINHASH_XIMPL_PRIVATE  intrinhash_ximpl_256 intrinhash_ximpl_generic_aesenc(intrinhash_ximpl_256 v, intrinhash_ximpl_256 m) {
        intrinhash_ximpl_256 r = { intrinhash_ximpl_generic_aesenc_128(v.lo, m.lo), intrinhash_ximpl_generic_aesenc_128(v.hi, m.hi) };
        return r;
    }

    // _mm256_permute2x128_si256
    INTRINHASH_XIMPL_PRIVATE intrinhash_ximpl_256 intrinhash_ximpl_generic_permute(intrinhash_ximpl_256 a, intrinhash_ximpl_256 b, int imm) {
        intrinhash_ximpl_256 r;
        int l = imm & 0x03, h = (imm >> 4) & 0x03;
        r.lo = (l == 0) ? a.lo : (l == 1) ? a.hi : (l == 2) ? b.lo : b.hi;
        r.hi = (h == 0) ? a.lo : (h == 1) ? a.hi : (h == 2) ? b.lo : b.hi;
        if (imm & 0x08) r.lo = emu_set_epi64x(0, 0);
        if (imm & 0x80) r.hi = emu_set_epi64x(0, 0);
        return r;
    }


    // _mm256_castsi256_si128
    INTRINHASH_XIMPL_PRIVATE intrinhash_ximpl_128 intrinhash_ximpl_generic_cast(intrinhash_ximpl_256 v) { return v.lo; }

    // _mm256_extracti128_si256
    INTRINHASH_XIMPL_PRIVATE intrinhash_ximpl_128 intrinhash_ximpl_generic_extract(intrinhash_ximpl_256 v, int imm) { return (imm & 1) ? v.hi : v.lo; }


    INTRINHASH_XIMPL_PRIVATE  void intrinhash_ximpl_generic_init(intrinhash_ximpl_generic_state* ctx) {
        const uint64_t(*c)[4] = intrinhash_ximpl_init_constants;

        INTRINHASH_XIMPL_REPEAT(8, ctx->v[i] = intrinhash_ximpl_generic_set((long long)c[i][3], (long long)c[i][2], (long long)c[i][1], (long long)c[i][0]););
    }

    INTRINHASH_XIMPL_PRIVATE void intrinhash_ximpl_generic_update(intrinhash_ximpl_generic_state* ctx, const void* data, size_t len) {
        const uint8_t* ptr = (uint8_t*)data;
        const uint8_t* end_ptr = ptr + (len & ~255ULL);
        len &= 255ULL;

        if (ptr < end_ptr) {
            intrinhash_ximpl_256 vv[8];
            INTRINHASH_XIMPL_REPEAT(8, vv[i] = ctx->v[i];);

            while (ptr < end_ptr) {
                INTRINHASH_XIMPL_REPEAT(8, vv[i] = intrinhash_ximpl_generic_aesenc(vv[i], intrinhash_ximpl_generic_load((ptr + 32 * i))););
                INTRINHASH_XIMPL_REPEAT(4, vv[i * 2] = intrinhash_ximpl_generic_xor(vv[i * 2], vv[i * 2 + 1]););
                ptr += 256;
            }

            INTRINHASH_XIMPL_REPEAT(8, ctx->v[i] = vv[i];);
        }


        if (len > 0) {
            if (len >= 128) {
                INTRINHASH_XIMPL_REPEAT(4, ctx->v[i] = intrinhash_ximpl_generic_aesenc(ctx->v[i], intrinhash_ximpl_generic_load((ptr + 32 * i))););
                ptr += 128; len -= 128;
            }


            if (len >= 64) {
                INTRINHASH_XIMPL_REPEAT(2, ctx->v[i + 4] = intrinhash_ximpl_generic_aesenc(ctx->v[i + 4], intrinhash_ximpl_generic_load((ptr + 32 * i))););

                ptr += 64; len -= 64;
            }

            if (len >= 32) {
                ctx->v[6] = intrinhash_ximpl_generic_aesenc(ctx->v[6], intrinhash_ximpl_generic_load((intrinhash_ximpl_256*)ptr));
                ptr += 32; len -= 32;
            }

            if (len > 0) {
                intrinhash_ximpl_256 m = intrinhash_ximpl_generic_zero();
                memcpy(&m, ptr, len);
                ctx->v[7] = intrinhash_ximpl_generic_aesenc(ctx->v[7], m);
            }
            INTRINHASH_XIMPL_REPEAT(4, ctx->v[i * 2] = intrinhash_ximpl_generic_xor(ctx->v[i * 2], ctx->v[i * 2 + 1]););

        }


    }

    INTRINHASH_XIMPL_PRIVATE intrinhash_ximpl_128 emu_shuffle_epi32(intrinhash_ximpl_128 in, int imm) {
        uint32_t words[4];
        uint32_t shuffled[4];
        intrinhash_ximpl_128 res;
        memcpy(words, in.v, 16);
        shuffled[0] = words[imm & 0x03];
        shuffled[1] = words[(imm >> 2) & 0x03];
        shuffled[2] = words[(imm >> 4) & 0x03];
        shuffled[3] = words[(imm >> 6) & 0x03];
        memcpy(res.v, shuffled, 16);
        return res;
    }

#include <string.h>

    INTRINHASH_XIMPL_PRIVATE intrinhash_ximpl_128 emu_set1_epi64x(long long val) {
        intrinhash_ximpl_128 res;
        memcpy(&res.v[0], &val, 8);
        memcpy(&res.v[8], &val, 8);
        return res;
    }


    INTRINHASH_XIMPL_PRIVATE intrinhash_ximpl_128 emu_set1_epi32(uint32_t val) {
        intrinhash_ximpl_128 res;
        for (int i = 0; i < 4; i++) {
            memcpy(&res.v[i * 4], &val, 4);
        }
        return res;
    }

    INTRINHASH_XIMPL_PRIVATE void intrinhash_ximpl_generic_finalize(intrinhash_ximpl_generic_state* ctx, uint8_t* out, size_t out_len, uint64_t seed, size_t length) {
        INTRINHASH_XIMPL_REPEAT(4, ctx->v[i * 2 + 1] = intrinhash_ximpl_generic_aesenc(ctx->v[i * 2 + 1], ctx->v[i * 2]););
        INTRINHASH_XIMPL_REPEAT(4, size_t idx = (i == 3) ? 0 : (i * 2 + 2); ctx->v[idx] = intrinhash_ximpl_generic_aesenc(ctx->v[idx], ctx->v[i * 2 + 1]););

        intrinhash_ximpl_256 h04 = intrinhash_ximpl_generic_aesenc(ctx->v[0], ctx->v[4]);
        intrinhash_ximpl_256 h15 = intrinhash_ximpl_generic_aesenc(ctx->v[1], ctx->v[5]);
        intrinhash_ximpl_256 h26 = intrinhash_ximpl_generic_aesenc(ctx->v[2], ctx->v[6]);
        intrinhash_ximpl_256 h37 = intrinhash_ximpl_generic_aesenc(ctx->v[3], ctx->v[7]);

        intrinhash_ximpl_256 mix_vec = intrinhash_ximpl_generic_set(
            (long long)seed,
            (long long)length,
            (long long)(seed ^ 0xDEADBEEF),
            (long long)(length ^ 0xFACEB00C)
        );

        h04 = intrinhash_ximpl_generic_aesenc(h04, mix_vec);

        intrinhash_ximpl_256 h = intrinhash_ximpl_generic_aesenc(h04, h15);
        h = intrinhash_ximpl_generic_aesenc(h, h26);
        h = intrinhash_ximpl_generic_aesenc(h, h37);

        h = intrinhash_ximpl_generic_xor(h, intrinhash_ximpl_generic_permute(h, h, 0x01));

        intrinhash_ximpl_128 lo = intrinhash_ximpl_generic_cast(h);
        intrinhash_ximpl_128 hi = intrinhash_ximpl_generic_extract(h, 1);

        lo = emu_xor_si128(lo, emu_shuffle_epi32(lo, 0x4E));
        hi = emu_xor_si128(hi, emu_shuffle_epi32(hi, 0xB1));


        intrinhash_ximpl_128 seedv = emu_set1_epi64x((long long)seed);

        intrinhash_ximpl_128 res0 = intrinhash_ximpl_generic_aesenc_128(lo, hi);
        intrinhash_ximpl_128 res1 = intrinhash_ximpl_generic_aesenc_128(hi, lo);

        res0 = intrinhash_ximpl_generic_aesenclast_128(res0, seedv);
        res1 = intrinhash_ximpl_generic_aesenclast_128(res1, emu_xor_si128(seedv, emu_set1_epi32(0xA5A5A5A5)));

        if (out_len == 8) {
            memcpy(out, res0.v, sizeof(uint64_t));
            return;
        }

        if (out_len == 16) {
            memcpy(out, res0.v, 16);
            return;
        }
        uint8_t tmp[32];
        memcpy(tmp + 0, res0.v, 16);
        memcpy(tmp + 16, res1.v, 16);
        memcpy(out, tmp, out_len <= 32 ? out_len : 32);
    }

#endif // x64

#if defined(__arm__) || defined(__aarch64__)
    INTRINHASH_NEONCE INTRINHASH_XIMPL_PUBLIC  void intrinhash_init(intrinhash_state* ctx, uint64_t seed, int mode) {
        (void)mode; // only INTRINHASH_NEONCE supported
        intrinhash_ximpl_neonce_init(&ctx->aes256, seed);
        ctx->seed = seed;
        ctx->length = 0;
    }

    INTRINHASH_NEONCE INTRINHASH_XIMPL_PUBLIC  void intrinhash_update(intrinhash_state* ctx, const void* data, size_t len) {
        if (len == 0) {
            return;
        }
        ctx->length += len;
        intrinhash_ximpl_neonce_update(&ctx->aes256, data, len);
    }

    INTRINHASH_NEONCE INTRINHASH_XIMPL_PUBLIC  void intrinhash_finalize(intrinhash_state* ctx, void* hash, size_t hash_len) {
        intrinhash_ximpl_neonce_get_bytes(&ctx->aes256, (uint8_t*)hash, hash_len, ctx->seed, ctx->length);
    }

#else
    /// <summary>
    /// Initialize a starte variable for streaming mode. Call intrinhash_update() repeatedly afterwards.
    /// </summary>
    /// <param name="ctx"></param>
    /// <param name="seed"></param>
    /// <param name="mode">Specify a INTRINHASH_MODE constant or pass the result of intrinhash_auto()</param>
    /// <returns></returns>
    INTRINHASH_XIMPL_PUBLIC void intrinhash_init(intrinhash_state* ctx, uint64_t seed, int mode) {
        ctx->mode = mode;
        ctx->lastodd = 0;
        ctx->inited = 1;
        ctx->length = 0;
        ctx->seed = seed;
        ctx->finalized = 0;

        if (ctx->mode == INTRINHASH_MODE_VAES256) {
            intrinhash_ximpl_vaes_init(&ctx->state.vaes256);
        }
        else if (ctx->mode == INTRINHASH_MODE_GENERIC) {
            intrinhash_ximpl_generic_init(&ctx->state.generic);
        }
        else if (ctx->mode == INTRINHASH_MODE_AESNI) {
            intrinhash_ximpl_aesni_init(&ctx->state.aesni);
        }
        else {
            assert(0);
        }
    }

    /// <summary>
    /// Process a block of data in streaming mode. All blocks must be divisible by 256 except the last.
    /// </summary>
    /// <param name="ctx"></param>
    /// <param name="data"></param>
    /// <param name="len">Must be divisible by 256 except for the last call</param>
    /// <returns></returns>
    INTRINHASH_XIMPL_PUBLIC void intrinhash_update(intrinhash_state* ctx, const void* data, size_t len) {
        assert(!ctx->lastodd);
        assert(ctx->inited == 1);
        assert(ctx->finalized == 0);

        if (len == 0) {
            return;
        }

        ctx->length += len;
        ctx->lastodd = (len % 256);

        if (ctx->mode == INTRINHASH_MODE_VAES256) {
            intrinhash_ximpl_vaes_update(&ctx->state.vaes256, data, len);
        }
        else if (ctx->mode == INTRINHASH_MODE_GENERIC) {
            intrinhash_ximpl_generic_update(&ctx->state.generic, data, len);
        }
        else if (ctx->mode == INTRINHASH_MODE_AESNI) {
            intrinhash_ximpl_aesni_update(&ctx->state.aesni, data, len);
        }
        else {
            assert(0);
        }
    }

    /// <summary>
    /// Return the hash result from streaming mode. It can be be up to 256 bits (32 bytes)
    /// </summary>
    /// <param name="ctx"></param>
    /// <param name="hash"></param>
    /// <param name="hash_len">Size in bytes of the hash value</param>
    /// <returns></returns>
    INTRINHASH_XIMPL_PUBLIC  void intrinhash_finalize(intrinhash_state* ctx, void* hash, size_t hash_len) {
        assert(ctx->inited == 1);
        assert(hash_len <= 32);
        assert(ctx->finalized != 1);

        ctx->finalized = 1;

        if (ctx->mode == INTRINHASH_MODE_VAES256) {
            intrinhash_ximpl_vaes_finalize(&ctx->state.vaes256, (uint8_t*)hash, hash_len, ctx->seed, ctx->length);
        }
        else if (ctx->mode == INTRINHASH_MODE_GENERIC) {
            intrinhash_ximpl_generic_finalize(&ctx->state.generic, (uint8_t*)hash, hash_len, ctx->seed, ctx->length);
        }
        else if (ctx->mode == INTRINHASH_MODE_AESNI) {
            intrinhash_ximpl_aesni_finalize(&ctx->state.aesni, (uint8_t*)hash, hash_len, ctx->seed, ctx->length);
        }
        else {
            assert(0);
        }
    }

#endif // x64

    /// <summary>
    /// Generate a hash value of up to 256 bits (32 bytes)
    /// </summary>
    /// <param name="in"></param>
    /// <param name="len"></param>
    /// <param name="seed"></param>
    /// <param name="out"></param>
    /// <param name="hash_len">Size in bytes of the hash value (1 to 32)</param>
    /// <param name="mode">Specify a INTRINHASH_MODE constant or pass the result of intrinhash_auto()</param>
    /// <returns></returns>
    INTRINHASH_XIMPL_PUBLIC void intrinhash(const void* in, size_t len, uint64_t seed, void* out, size_t hash_len, int mode) {
        assert(hash_len <= 32);
        intrinhash_state ps;
        intrinhash_init(&ps, seed, mode);
        intrinhash_update(&ps, in, len);
        intrinhash_finalize(&ps, out, hash_len);
    }

#endif // #if defined(INTRINHASH_HEADER_ONLY) || defined(INTRINHASH_IMPLEMENTATION)

#ifdef __cplusplus
} // extern C
#endif

#endif /* INTRINHASH_XIMPL_H */

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#ifdef INTRINHASH_XIMPL_DEFINE_MAIN

#include <stdlib.h>
#include <stdio.h>

int mode = 0;
uint8_t out[32];
uint8_t in[4096] = { 0 };
uint32_t seed = 0xc0ffee;

struct block { size_t len; uint64_t exp; };

struct stream { size_t a; size_t b; uint64_t exp; };

uint64_t sum(void) {
    uint64_t s = 0;
    for (size_t i = 0; i < 32; i++) { s += out[i]; }
    return s;
}

void check(uint64_t expected) {
    if (sum() != expected) {
        printf("error\n");
        exit(1);
    }
}

void test_block(size_t len, uint64_t expected) {
    intrinhash(in, len, seed, out, 32, mode);
    check(expected);
}

void test_stream(size_t a, size_t b, uint64_t expected) {
    intrinhash_state ps;
    intrinhash_init(&ps, seed, mode);
    intrinhash_update(&ps, in, a);
    intrinhash_update(&ps, in + a, b);
    intrinhash_finalize(&ps, out, 32);
    check(expected);
}

int main(void) {
    size_t i;

    struct block blocks[] = {
        {0,3913}, {1,5232}, {31,4470}, {32,4310}, {33,3768}, {127,3981},
        {128,3908}, {129,3963}, {255,3404}, {256,4581}, {257,3936},
        {511,3639}, {512,2969}, {513,4867}
    };

    struct stream streams[] = {
        {256, 512, 3476}, {512, 256, 3476}, {768, 0, 3476},
        {256, 513, 4670}, {512, 257, 4670}, {768, 1, 4670},
        {256, 511, 4418}, {512, 255, 4418},
        {256, 542, 3752}, {512, 286, 3752},
        {256, 632, 3623}, {512, 376, 3623},
        {256, 712, 4160}, {512, 456, 4160}
    };

    for (mode = 0; mode < INTRINHASH_XPRIV_HIGHEST_MODE + 1; mode++) {
        intrinhash_state ps;
        intrinhash_init(&ps, seed, mode);
        intrinhash_finalize(&ps, out, 32);
        check(3913);

        for (i = 0; i < 14; i++) {
            test_block(blocks[i].len, blocks[i].exp);
        }
        for (i = 0; i < 14; i++) {
            test_stream(streams[i].a, streams[i].b, streams[i].exp);
        }
    }

    seed = 0x404;
    for (mode = 0; mode < 3; mode++) {
        test_block(100, 3489);
    }

    printf("ok\n");
    return 0;
}

#endif
