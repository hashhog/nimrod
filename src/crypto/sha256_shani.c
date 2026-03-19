/* Hardware-accelerated SHA-256 using Intel SHA-NI
 *
 * Based on Bitcoin Core's sha256_x86_shani.cpp (public domain)
 * Original by Jeffrey Walton, Intel, and Sean Gulley
 */

#if defined(__x86_64__) || defined(__amd64__) || defined(__i386__)
#if defined(__SHA__) && defined(__SSE4_1__)

#include <stdint.h>
#include <stddef.h>
#include <immintrin.h>

/* Byte-swap mask for converting between big-endian (SHA) and little-endian (x86) */
static const uint8_t MASK[16] __attribute__((aligned(16))) = {
    0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04,
    0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c
};

/* Initial SHA-256 state (already shuffled for SHA-NI) */
static const uint8_t INIT0[16] __attribute__((aligned(16))) = {
    0x8c, 0x68, 0x05, 0x9b, 0x7f, 0x52, 0x0e, 0x51,
    0x85, 0xae, 0x67, 0xbb, 0x67, 0xe6, 0x09, 0x6a
};

static const uint8_t INIT1[16] __attribute__((aligned(16))) = {
    0x19, 0xcd, 0xe0, 0x5b, 0xab, 0xd9, 0x83, 0x1f,
    0x3a, 0xf5, 0x4f, 0xa5, 0x72, 0xf3, 0x6e, 0x3c
};

static inline void QuadRound(__m128i* state0, __m128i* state1, uint64_t k1, uint64_t k0)
{
    __m128i msg = _mm_set_epi64x(k1, k0);
    *state1 = _mm_sha256rnds2_epu32(*state1, *state0, msg);
    *state0 = _mm_sha256rnds2_epu32(*state0, *state1, _mm_shuffle_epi32(msg, 0x0e));
}

static inline void QuadRoundMsg(__m128i* state0, __m128i* state1, __m128i m, uint64_t k1, uint64_t k0)
{
    __m128i msg = _mm_add_epi32(m, _mm_set_epi64x(k1, k0));
    *state1 = _mm_sha256rnds2_epu32(*state1, *state0, msg);
    *state0 = _mm_sha256rnds2_epu32(*state0, *state1, _mm_shuffle_epi32(msg, 0x0e));
}

static inline void ShiftMessageA(__m128i* m0, __m128i m1)
{
    *m0 = _mm_sha256msg1_epu32(*m0, m1);
}

static inline void ShiftMessageC(__m128i* m0, __m128i m1, __m128i* m2)
{
    *m2 = _mm_sha256msg2_epu32(_mm_add_epi32(*m2, _mm_alignr_epi8(m1, *m0, 4)), m1);
}

static inline void ShiftMessageB(__m128i* m0, __m128i m1, __m128i* m2)
{
    ShiftMessageC(m0, m1, m2);
    ShiftMessageA(m0, m1);
}

static inline void Shuffle(__m128i* s0, __m128i* s1)
{
    __m128i t1 = _mm_shuffle_epi32(*s0, 0xB1);
    __m128i t2 = _mm_shuffle_epi32(*s1, 0x1B);
    *s0 = _mm_alignr_epi8(t1, t2, 0x08);
    *s1 = _mm_blend_epi16(t2, t1, 0xF0);
}

static inline void Unshuffle(__m128i* s0, __m128i* s1)
{
    __m128i t1 = _mm_shuffle_epi32(*s0, 0x1B);
    __m128i t2 = _mm_shuffle_epi32(*s1, 0xB1);
    *s0 = _mm_blend_epi16(t1, t2, 0xF0);
    *s1 = _mm_alignr_epi8(t2, t1, 0x08);
}

static inline __m128i Load(const unsigned char* in)
{
    return _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)in),
                            _mm_load_si128((const __m128i*)MASK));
}

static inline void Save(unsigned char* out, __m128i s)
{
    _mm_storeu_si128((__m128i*)out,
                     _mm_shuffle_epi8(s, _mm_load_si128((const __m128i*)MASK)));
}

/* Single SHA-256 transform: hash 64-byte blocks */
void sha256_shani_transform(uint32_t* state, const unsigned char* data, size_t blocks)
{
    __m128i m0, m1, m2, m3, s0, s1, so0, so1;

    /* Load state */
    s0 = _mm_loadu_si128((const __m128i*)state);
    s1 = _mm_loadu_si128((const __m128i*)(state + 4));
    Shuffle(&s0, &s1);

    while (blocks--) {
        /* Remember old state */
        so0 = s0;
        so1 = s1;

        /* Load data and transform */
        m0 = Load(data);
        QuadRoundMsg(&s0, &s1, m0, 0xe9b5dba5b5c0fbcfull, 0x71374491428a2f98ull);
        m1 = Load(data + 16);
        QuadRoundMsg(&s0, &s1, m1, 0xab1c5ed5923f82a4ull, 0x59f111f13956c25bull);
        ShiftMessageA(&m0, m1);
        m2 = Load(data + 32);
        QuadRoundMsg(&s0, &s1, m2, 0x550c7dc3243185beull, 0x12835b01d807aa98ull);
        ShiftMessageA(&m1, m2);
        m3 = Load(data + 48);
        QuadRoundMsg(&s0, &s1, m3, 0xc19bf1749bdc06a7ull, 0x80deb1fe72be5d74ull);
        ShiftMessageB(&m2, m3, &m0);
        QuadRoundMsg(&s0, &s1, m0, 0x240ca1cc0fc19dc6ull, 0xefbe4786e49b69c1ull);
        ShiftMessageB(&m3, m0, &m1);
        QuadRoundMsg(&s0, &s1, m1, 0x76f988da5cb0a9dcull, 0x4a7484aa2de92c6full);
        ShiftMessageB(&m0, m1, &m2);
        QuadRoundMsg(&s0, &s1, m2, 0xbf597fc7b00327c8ull, 0xa831c66d983e5152ull);
        ShiftMessageB(&m1, m2, &m3);
        QuadRoundMsg(&s0, &s1, m3, 0x1429296706ca6351ull, 0xd5a79147c6e00bf3ull);
        ShiftMessageB(&m2, m3, &m0);
        QuadRoundMsg(&s0, &s1, m0, 0x53380d134d2c6dfcull, 0x2e1b213827b70a85ull);
        ShiftMessageB(&m3, m0, &m1);
        QuadRoundMsg(&s0, &s1, m1, 0x92722c8581c2c92eull, 0x766a0abb650a7354ull);
        ShiftMessageB(&m0, m1, &m2);
        QuadRoundMsg(&s0, &s1, m2, 0xc76c51a3c24b8b70ull, 0xa81a664ba2bfe8a1ull);
        ShiftMessageB(&m1, m2, &m3);
        QuadRoundMsg(&s0, &s1, m3, 0x106aa070f40e3585ull, 0xd6990624d192e819ull);
        ShiftMessageB(&m2, m3, &m0);
        QuadRoundMsg(&s0, &s1, m0, 0x34b0bcb52748774cull, 0x1e376c0819a4c116ull);
        ShiftMessageB(&m3, m0, &m1);
        QuadRoundMsg(&s0, &s1, m1, 0x682e6ff35b9cca4full, 0x4ed8aa4a391c0cb3ull);
        ShiftMessageC(&m0, m1, &m2);
        QuadRoundMsg(&s0, &s1, m2, 0x8cc7020884c87814ull, 0x78a5636f748f82eeull);
        ShiftMessageC(&m1, m2, &m3);
        QuadRoundMsg(&s0, &s1, m3, 0xc67178f2bef9a3f7ull, 0xa4506ceb90befffaull);

        /* Combine with old state */
        s0 = _mm_add_epi32(s0, so0);
        s1 = _mm_add_epi32(s1, so1);

        /* Advance */
        data += 64;
    }

    Unshuffle(&s0, &s1);
    _mm_storeu_si128((__m128i*)state, s0);
    _mm_storeu_si128((__m128i*)(state + 4), s1);
}

/* Double SHA-256 of a 64-byte block (for Merkle tree nodes) */
void sha256d64_shani(unsigned char* out, const unsigned char* in)
{
    __m128i m0, m1, m2, m3, s0, s1, so0, so1;

    /* Transform 1: Hash the input */
    s0 = _mm_load_si128((const __m128i*)INIT0);
    s1 = _mm_load_si128((const __m128i*)INIT1);

    m0 = Load(in);
    QuadRoundMsg(&s0, &s1, m0, 0xe9b5dba5b5c0fbcfull, 0x71374491428a2f98ull);
    m1 = Load(in + 16);
    QuadRoundMsg(&s0, &s1, m1, 0xab1c5ed5923f82a4ull, 0x59f111f13956c25bull);
    ShiftMessageA(&m0, m1);
    m2 = Load(in + 32);
    QuadRoundMsg(&s0, &s1, m2, 0x550c7dc3243185beull, 0x12835b01d807aa98ull);
    ShiftMessageA(&m1, m2);
    m3 = Load(in + 48);
    QuadRoundMsg(&s0, &s1, m3, 0xc19bf1749bdc06a7ull, 0x80deb1fe72be5d74ull);
    ShiftMessageB(&m2, m3, &m0);
    QuadRoundMsg(&s0, &s1, m0, 0x240ca1cc0fc19dc6ull, 0xefbe4786e49b69c1ull);
    ShiftMessageB(&m3, m0, &m1);
    QuadRoundMsg(&s0, &s1, m1, 0x76f988da5cb0a9dcull, 0x4a7484aa2de92c6full);
    ShiftMessageB(&m0, m1, &m2);
    QuadRoundMsg(&s0, &s1, m2, 0xbf597fc7b00327c8ull, 0xa831c66d983e5152ull);
    ShiftMessageB(&m1, m2, &m3);
    QuadRoundMsg(&s0, &s1, m3, 0x1429296706ca6351ull, 0xd5a79147c6e00bf3ull);
    ShiftMessageB(&m2, m3, &m0);
    QuadRoundMsg(&s0, &s1, m0, 0x53380d134d2c6dfcull, 0x2e1b213827b70a85ull);
    ShiftMessageB(&m3, m0, &m1);
    QuadRoundMsg(&s0, &s1, m1, 0x92722c8581c2c92eull, 0x766a0abb650a7354ull);
    ShiftMessageB(&m0, m1, &m2);
    QuadRoundMsg(&s0, &s1, m2, 0xc76c51a3c24b8b70ull, 0xa81a664ba2bfe8a1ull);
    ShiftMessageB(&m1, m2, &m3);
    QuadRoundMsg(&s0, &s1, m3, 0x106aa070f40e3585ull, 0xd6990624d192e819ull);
    ShiftMessageB(&m2, m3, &m0);
    QuadRoundMsg(&s0, &s1, m0, 0x34b0bcb52748774cull, 0x1e376c0819a4c116ull);
    ShiftMessageB(&m3, m0, &m1);
    QuadRoundMsg(&s0, &s1, m1, 0x682e6ff35b9cca4full, 0x4ed8aa4a391c0cb3ull);
    ShiftMessageC(&m0, m1, &m2);
    QuadRoundMsg(&s0, &s1, m2, 0x8cc7020884c87814ull, 0x78a5636f748f82eeull);
    ShiftMessageC(&m1, m2, &m3);
    QuadRoundMsg(&s0, &s1, m3, 0xc67178f2bef9a3f7ull, 0xa4506ceb90befffaull);

    s0 = _mm_add_epi32(s0, _mm_load_si128((const __m128i*)INIT0));
    s1 = _mm_add_epi32(s1, _mm_load_si128((const __m128i*)INIT1));

    /* Transform 2: Apply SHA-256 padding for 64-byte message */
    so0 = s0;
    so1 = s1;

    /* Precomputed rounds for padding: 0x80 at byte 64, length = 512 bits = 0x200 at end */
    QuadRound(&s0, &s1, 0xe9b5dba5b5c0fbcfull, 0x71374491c28a2f98ull);
    QuadRound(&s0, &s1, 0xab1c5ed5923f82a4ull, 0x59f111f13956c25bull);
    QuadRound(&s0, &s1, 0x550c7dc3243185beull, 0x12835b01d807aa98ull);
    QuadRound(&s0, &s1, 0xc19bf3749bdc06a7ull, 0x80deb1fe72be5d74ull);
    QuadRound(&s0, &s1, 0x240cf2540fe1edc6ull, 0xf0fe4786649b69c1ull);
    QuadRound(&s0, &s1, 0x16f988fa61b9411eull, 0x6cc984be4fe9346full);
    QuadRound(&s0, &s1, 0xb9d99ec7b019fc65ull, 0xa88e5a6df2c65152ull);
    QuadRound(&s0, &s1, 0xc7353eb0fdb1232bull, 0xe70eeaa09a1231c3ull);
    QuadRound(&s0, &s1, 0xdc1eeefd5a0f118full, 0xcb976d5f3069bad5ull);
    QuadRound(&s0, &s1, 0xe15d5b1658f4ca9dull, 0xde0b7a040a35b689ull);
    QuadRound(&s0, &s1, 0x6fab9537a507ea32ull, 0x37088980007f3e86ull);
    QuadRound(&s0, &s1, 0xc0bbbe37cdaa3b6dull, 0x0d8cd6f117406110ull);
    QuadRound(&s0, &s1, 0x6fd15ca70b02e931ull, 0xdb48a36383613bdaull);
    QuadRound(&s0, &s1, 0x6d4378906ed41a95ull, 0x31338431521afacaull);
    QuadRound(&s0, &s1, 0x532fb63cb5c9a0e6ull, 0x9eccabbdc39c91f2ull);
    QuadRound(&s0, &s1, 0x4c191d76a4954b68ull, 0x07237ea3d2c741c6ull);

    s0 = _mm_add_epi32(s0, so0);
    s1 = _mm_add_epi32(s1, so1);

    /* Extract intermediate hash */
    Unshuffle(&s0, &s1);
    m0 = s0;
    m1 = s1;

    /* Transform 3: Hash the 32-byte intermediate with padding */
    s0 = _mm_load_si128((const __m128i*)INIT0);
    s1 = _mm_load_si128((const __m128i*)INIT1);

    QuadRoundMsg(&s0, &s1, m0, 0xe9b5dba5b5c0fbcfull, 0x71374491428a2f98ull);
    QuadRoundMsg(&s0, &s1, m1, 0xab1c5ed5923f82a4ull, 0x59f111f13956c25bull);
    ShiftMessageA(&m0, m1);

    /* m2 = 0x80000000 (padding) */
    m2 = _mm_set_epi64x(0x0ull, 0x80000000ull);
    QuadRound(&s0, &s1, 0x550c7dc3243185beull, 0x12835b015807aa98ull);
    ShiftMessageA(&m1, m2);

    /* m3 = length (256 bits = 0x100) */
    m3 = _mm_set_epi64x(0x10000000000ull, 0x0ull);
    QuadRound(&s0, &s1, 0xc19bf2749bdc06a7ull, 0x80deb1fe72be5d74ull);
    ShiftMessageB(&m2, m3, &m0);
    QuadRoundMsg(&s0, &s1, m0, 0x240ca1cc0fc19dc6ull, 0xefbe4786e49b69c1ull);
    ShiftMessageB(&m3, m0, &m1);
    QuadRoundMsg(&s0, &s1, m1, 0x76f988da5cb0a9dcull, 0x4a7484aa2de92c6full);
    ShiftMessageB(&m0, m1, &m2);
    QuadRoundMsg(&s0, &s1, m2, 0xbf597fc7b00327c8ull, 0xa831c66d983e5152ull);
    ShiftMessageB(&m1, m2, &m3);
    QuadRoundMsg(&s0, &s1, m3, 0x1429296706ca6351ull, 0xd5a79147c6e00bf3ull);
    ShiftMessageB(&m2, m3, &m0);
    QuadRoundMsg(&s0, &s1, m0, 0x53380d134d2c6dfcull, 0x2e1b213827b70a85ull);
    ShiftMessageB(&m3, m0, &m1);
    QuadRoundMsg(&s0, &s1, m1, 0x92722c8581c2c92eull, 0x766a0abb650a7354ull);
    ShiftMessageB(&m0, m1, &m2);
    QuadRoundMsg(&s0, &s1, m2, 0xc76c51a3c24b8b70ull, 0xa81a664ba2bfe8a1ull);
    ShiftMessageB(&m1, m2, &m3);
    QuadRoundMsg(&s0, &s1, m3, 0x106aa070f40e3585ull, 0xd6990624d192e819ull);
    ShiftMessageB(&m2, m3, &m0);
    QuadRoundMsg(&s0, &s1, m0, 0x34b0bcb52748774cull, 0x1e376c0819a4c116ull);
    ShiftMessageB(&m3, m0, &m1);
    QuadRoundMsg(&s0, &s1, m1, 0x682e6ff35b9cca4full, 0x4ed8aa4a391c0cb3ull);
    ShiftMessageC(&m0, m1, &m2);
    QuadRoundMsg(&s0, &s1, m2, 0x8cc7020884c87814ull, 0x78a5636f748f82eeull);
    ShiftMessageC(&m1, m2, &m3);
    QuadRoundMsg(&s0, &s1, m3, 0xc67178f2bef9a3f7ull, 0xa4506ceb90befffaull);

    s0 = _mm_add_epi32(s0, _mm_load_si128((const __m128i*)INIT0));
    s1 = _mm_add_epi32(s1, _mm_load_si128((const __m128i*)INIT1));

    /* Output final hash */
    Unshuffle(&s0, &s1);
    Save(out, s0);
    Save(out + 16, s1);
}

/* 2-way parallel sha256d64 for processing two 64-byte blocks at once */
void sha256d64_shani_2way(unsigned char* out, const unsigned char* in)
{
    __m128i am0, am1, am2, am3, as0, as1, aso0, aso1;
    __m128i bm0, bm1, bm2, bm3, bs0, bs1, bso0, bso1;

    /* Transform 1 */
    bs0 = as0 = _mm_load_si128((const __m128i*)INIT0);
    bs1 = as1 = _mm_load_si128((const __m128i*)INIT1);
    am0 = Load(in);
    bm0 = Load(in + 64);
    QuadRoundMsg(&as0, &as1, am0, 0xe9b5dba5b5c0fbcfull, 0x71374491428a2f98ull);
    QuadRoundMsg(&bs0, &bs1, bm0, 0xe9b5dba5b5c0fbcfull, 0x71374491428a2f98ull);
    am1 = Load(in + 16);
    bm1 = Load(in + 80);
    QuadRoundMsg(&as0, &as1, am1, 0xab1c5ed5923f82a4ull, 0x59f111f13956c25bull);
    QuadRoundMsg(&bs0, &bs1, bm1, 0xab1c5ed5923f82a4ull, 0x59f111f13956c25bull);
    ShiftMessageA(&am0, am1);
    ShiftMessageA(&bm0, bm1);
    am2 = Load(in + 32);
    bm2 = Load(in + 96);
    QuadRoundMsg(&as0, &as1, am2, 0x550c7dc3243185beull, 0x12835b01d807aa98ull);
    QuadRoundMsg(&bs0, &bs1, bm2, 0x550c7dc3243185beull, 0x12835b01d807aa98ull);
    ShiftMessageA(&am1, am2);
    ShiftMessageA(&bm1, bm2);
    am3 = Load(in + 48);
    bm3 = Load(in + 112);
    QuadRoundMsg(&as0, &as1, am3, 0xc19bf1749bdc06a7ull, 0x80deb1fe72be5d74ull);
    QuadRoundMsg(&bs0, &bs1, bm3, 0xc19bf1749bdc06a7ull, 0x80deb1fe72be5d74ull);
    ShiftMessageB(&am2, am3, &am0);
    ShiftMessageB(&bm2, bm3, &bm0);
    QuadRoundMsg(&as0, &as1, am0, 0x240ca1cc0fc19dc6ull, 0xefbe4786e49b69c1ull);
    QuadRoundMsg(&bs0, &bs1, bm0, 0x240ca1cc0fc19dc6ull, 0xefbe4786e49b69c1ull);
    ShiftMessageB(&am3, am0, &am1);
    ShiftMessageB(&bm3, bm0, &bm1);
    QuadRoundMsg(&as0, &as1, am1, 0x76f988da5cb0a9dcull, 0x4a7484aa2de92c6full);
    QuadRoundMsg(&bs0, &bs1, bm1, 0x76f988da5cb0a9dcull, 0x4a7484aa2de92c6full);
    ShiftMessageB(&am0, am1, &am2);
    ShiftMessageB(&bm0, bm1, &bm2);
    QuadRoundMsg(&as0, &as1, am2, 0xbf597fc7b00327c8ull, 0xa831c66d983e5152ull);
    QuadRoundMsg(&bs0, &bs1, bm2, 0xbf597fc7b00327c8ull, 0xa831c66d983e5152ull);
    ShiftMessageB(&am1, am2, &am3);
    ShiftMessageB(&bm1, bm2, &bm3);
    QuadRoundMsg(&as0, &as1, am3, 0x1429296706ca6351ull, 0xd5a79147c6e00bf3ull);
    QuadRoundMsg(&bs0, &bs1, bm3, 0x1429296706ca6351ull, 0xd5a79147c6e00bf3ull);
    ShiftMessageB(&am2, am3, &am0);
    ShiftMessageB(&bm2, bm3, &bm0);
    QuadRoundMsg(&as0, &as1, am0, 0x53380d134d2c6dfcull, 0x2e1b213827b70a85ull);
    QuadRoundMsg(&bs0, &bs1, bm0, 0x53380d134d2c6dfcull, 0x2e1b213827b70a85ull);
    ShiftMessageB(&am3, am0, &am1);
    ShiftMessageB(&bm3, bm0, &bm1);
    QuadRoundMsg(&as0, &as1, am1, 0x92722c8581c2c92eull, 0x766a0abb650a7354ull);
    QuadRoundMsg(&bs0, &bs1, bm1, 0x92722c8581c2c92eull, 0x766a0abb650a7354ull);
    ShiftMessageB(&am0, am1, &am2);
    ShiftMessageB(&bm0, bm1, &bm2);
    QuadRoundMsg(&as0, &as1, am2, 0xc76c51a3c24b8b70ull, 0xa81a664ba2bfe8a1ull);
    QuadRoundMsg(&bs0, &bs1, bm2, 0xc76c51a3c24b8b70ull, 0xa81a664ba2bfe8a1ull);
    ShiftMessageB(&am1, am2, &am3);
    ShiftMessageB(&bm1, bm2, &bm3);
    QuadRoundMsg(&as0, &as1, am3, 0x106aa070f40e3585ull, 0xd6990624d192e819ull);
    QuadRoundMsg(&bs0, &bs1, bm3, 0x106aa070f40e3585ull, 0xd6990624d192e819ull);
    ShiftMessageB(&am2, am3, &am0);
    ShiftMessageB(&bm2, bm3, &bm0);
    QuadRoundMsg(&as0, &as1, am0, 0x34b0bcb52748774cull, 0x1e376c0819a4c116ull);
    QuadRoundMsg(&bs0, &bs1, bm0, 0x34b0bcb52748774cull, 0x1e376c0819a4c116ull);
    ShiftMessageB(&am3, am0, &am1);
    ShiftMessageB(&bm3, bm0, &bm1);
    QuadRoundMsg(&as0, &as1, am1, 0x682e6ff35b9cca4full, 0x4ed8aa4a391c0cb3ull);
    QuadRoundMsg(&bs0, &bs1, bm1, 0x682e6ff35b9cca4full, 0x4ed8aa4a391c0cb3ull);
    ShiftMessageC(&am0, am1, &am2);
    ShiftMessageC(&bm0, bm1, &bm2);
    QuadRoundMsg(&as0, &as1, am2, 0x8cc7020884c87814ull, 0x78a5636f748f82eeull);
    QuadRoundMsg(&bs0, &bs1, bm2, 0x8cc7020884c87814ull, 0x78a5636f748f82eeull);
    ShiftMessageC(&am1, am2, &am3);
    ShiftMessageC(&bm1, bm2, &bm3);
    QuadRoundMsg(&as0, &as1, am3, 0xc67178f2bef9a3f7ull, 0xa4506ceb90befffaull);
    QuadRoundMsg(&bs0, &bs1, bm3, 0xc67178f2bef9a3f7ull, 0xa4506ceb90befffaull);
    as0 = _mm_add_epi32(as0, _mm_load_si128((const __m128i*)INIT0));
    bs0 = _mm_add_epi32(bs0, _mm_load_si128((const __m128i*)INIT0));
    as1 = _mm_add_epi32(as1, _mm_load_si128((const __m128i*)INIT1));
    bs1 = _mm_add_epi32(bs1, _mm_load_si128((const __m128i*)INIT1));

    /* Transform 2 */
    aso0 = as0;
    bso0 = bs0;
    aso1 = as1;
    bso1 = bs1;
    QuadRound(&as0, &as1, 0xe9b5dba5b5c0fbcfull, 0x71374491c28a2f98ull);
    QuadRound(&bs0, &bs1, 0xe9b5dba5b5c0fbcfull, 0x71374491c28a2f98ull);
    QuadRound(&as0, &as1, 0xab1c5ed5923f82a4ull, 0x59f111f13956c25bull);
    QuadRound(&bs0, &bs1, 0xab1c5ed5923f82a4ull, 0x59f111f13956c25bull);
    QuadRound(&as0, &as1, 0x550c7dc3243185beull, 0x12835b01d807aa98ull);
    QuadRound(&bs0, &bs1, 0x550c7dc3243185beull, 0x12835b01d807aa98ull);
    QuadRound(&as0, &as1, 0xc19bf3749bdc06a7ull, 0x80deb1fe72be5d74ull);
    QuadRound(&bs0, &bs1, 0xc19bf3749bdc06a7ull, 0x80deb1fe72be5d74ull);
    QuadRound(&as0, &as1, 0x240cf2540fe1edc6ull, 0xf0fe4786649b69c1ull);
    QuadRound(&bs0, &bs1, 0x240cf2540fe1edc6ull, 0xf0fe4786649b69c1ull);
    QuadRound(&as0, &as1, 0x16f988fa61b9411eull, 0x6cc984be4fe9346full);
    QuadRound(&bs0, &bs1, 0x16f988fa61b9411eull, 0x6cc984be4fe9346full);
    QuadRound(&as0, &as1, 0xb9d99ec7b019fc65ull, 0xa88e5a6df2c65152ull);
    QuadRound(&bs0, &bs1, 0xb9d99ec7b019fc65ull, 0xa88e5a6df2c65152ull);
    QuadRound(&as0, &as1, 0xc7353eb0fdb1232bull, 0xe70eeaa09a1231c3ull);
    QuadRound(&bs0, &bs1, 0xc7353eb0fdb1232bull, 0xe70eeaa09a1231c3ull);
    QuadRound(&as0, &as1, 0xdc1eeefd5a0f118full, 0xcb976d5f3069bad5ull);
    QuadRound(&bs0, &bs1, 0xdc1eeefd5a0f118full, 0xcb976d5f3069bad5ull);
    QuadRound(&as0, &as1, 0xe15d5b1658f4ca9dull, 0xde0b7a040a35b689ull);
    QuadRound(&bs0, &bs1, 0xe15d5b1658f4ca9dull, 0xde0b7a040a35b689ull);
    QuadRound(&as0, &as1, 0x6fab9537a507ea32ull, 0x37088980007f3e86ull);
    QuadRound(&bs0, &bs1, 0x6fab9537a507ea32ull, 0x37088980007f3e86ull);
    QuadRound(&as0, &as1, 0xc0bbbe37cdaa3b6dull, 0x0d8cd6f117406110ull);
    QuadRound(&bs0, &bs1, 0xc0bbbe37cdaa3b6dull, 0x0d8cd6f117406110ull);
    QuadRound(&as0, &as1, 0x6fd15ca70b02e931ull, 0xdb48a36383613bdaull);
    QuadRound(&bs0, &bs1, 0x6fd15ca70b02e931ull, 0xdb48a36383613bdaull);
    QuadRound(&as0, &as1, 0x6d4378906ed41a95ull, 0x31338431521afacaull);
    QuadRound(&bs0, &bs1, 0x6d4378906ed41a95ull, 0x31338431521afacaull);
    QuadRound(&as0, &as1, 0x532fb63cb5c9a0e6ull, 0x9eccabbdc39c91f2ull);
    QuadRound(&bs0, &bs1, 0x532fb63cb5c9a0e6ull, 0x9eccabbdc39c91f2ull);
    QuadRound(&as0, &as1, 0x4c191d76a4954b68ull, 0x07237ea3d2c741c6ull);
    QuadRound(&bs0, &bs1, 0x4c191d76a4954b68ull, 0x07237ea3d2c741c6ull);
    as0 = _mm_add_epi32(as0, aso0);
    bs0 = _mm_add_epi32(bs0, bso0);
    as1 = _mm_add_epi32(as1, aso1);
    bs1 = _mm_add_epi32(bs1, bso1);

    /* Extract hash */
    Unshuffle(&as0, &as1);
    Unshuffle(&bs0, &bs1);
    am0 = as0;
    bm0 = bs0;
    am1 = as1;
    bm1 = bs1;

    /* Transform 3 */
    bs0 = as0 = _mm_load_si128((const __m128i*)INIT0);
    bs1 = as1 = _mm_load_si128((const __m128i*)INIT1);
    QuadRoundMsg(&as0, &as1, am0, 0xe9b5dba5b5c0fbcfull, 0x71374491428a2f98ull);
    QuadRoundMsg(&bs0, &bs1, bm0, 0xe9b5dba5b5c0fbcfull, 0x71374491428a2f98ull);
    QuadRoundMsg(&as0, &as1, am1, 0xab1c5ed5923f82a4ull, 0x59f111f13956c25bull);
    QuadRoundMsg(&bs0, &bs1, bm1, 0xab1c5ed5923f82a4ull, 0x59f111f13956c25bull);
    ShiftMessageA(&am0, am1);
    ShiftMessageA(&bm0, bm1);
    bm2 = am2 = _mm_set_epi64x(0x0ull, 0x80000000ull);
    QuadRound(&as0, &as1, 0x550c7dc3243185beull, 0x12835b015807aa98ull);
    QuadRound(&bs0, &bs1, 0x550c7dc3243185beull, 0x12835b015807aa98ull);
    ShiftMessageA(&am1, am2);
    ShiftMessageA(&bm1, bm2);
    bm3 = am3 = _mm_set_epi64x(0x10000000000ull, 0x0ull);
    QuadRound(&as0, &as1, 0xc19bf2749bdc06a7ull, 0x80deb1fe72be5d74ull);
    QuadRound(&bs0, &bs1, 0xc19bf2749bdc06a7ull, 0x80deb1fe72be5d74ull);
    ShiftMessageB(&am2, am3, &am0);
    ShiftMessageB(&bm2, bm3, &bm0);
    QuadRoundMsg(&as0, &as1, am0, 0x240ca1cc0fc19dc6ull, 0xefbe4786e49b69c1ull);
    QuadRoundMsg(&bs0, &bs1, bm0, 0x240ca1cc0fc19dc6ull, 0xefbe4786e49b69c1ull);
    ShiftMessageB(&am3, am0, &am1);
    ShiftMessageB(&bm3, bm0, &bm1);
    QuadRoundMsg(&as0, &as1, am1, 0x76f988da5cb0a9dcull, 0x4a7484aa2de92c6full);
    QuadRoundMsg(&bs0, &bs1, bm1, 0x76f988da5cb0a9dcull, 0x4a7484aa2de92c6full);
    ShiftMessageB(&am0, am1, &am2);
    ShiftMessageB(&bm0, bm1, &bm2);
    QuadRoundMsg(&as0, &as1, am2, 0xbf597fc7b00327c8ull, 0xa831c66d983e5152ull);
    QuadRoundMsg(&bs0, &bs1, bm2, 0xbf597fc7b00327c8ull, 0xa831c66d983e5152ull);
    ShiftMessageB(&am1, am2, &am3);
    ShiftMessageB(&bm1, bm2, &bm3);
    QuadRoundMsg(&as0, &as1, am3, 0x1429296706ca6351ull, 0xd5a79147c6e00bf3ull);
    QuadRoundMsg(&bs0, &bs1, bm3, 0x1429296706ca6351ull, 0xd5a79147c6e00bf3ull);
    ShiftMessageB(&am2, am3, &am0);
    ShiftMessageB(&bm2, bm3, &bm0);
    QuadRoundMsg(&as0, &as1, am0, 0x53380d134d2c6dfcull, 0x2e1b213827b70a85ull);
    QuadRoundMsg(&bs0, &bs1, bm0, 0x53380d134d2c6dfcull, 0x2e1b213827b70a85ull);
    ShiftMessageB(&am3, am0, &am1);
    ShiftMessageB(&bm3, bm0, &bm1);
    QuadRoundMsg(&as0, &as1, am1, 0x92722c8581c2c92eull, 0x766a0abb650a7354ull);
    QuadRoundMsg(&bs0, &bs1, bm1, 0x92722c8581c2c92eull, 0x766a0abb650a7354ull);
    ShiftMessageB(&am0, am1, &am2);
    ShiftMessageB(&bm0, bm1, &bm2);
    QuadRoundMsg(&as0, &as1, am2, 0xc76c51a3c24b8b70ull, 0xa81a664ba2bfe8a1ull);
    QuadRoundMsg(&bs0, &bs1, bm2, 0xc76c51a3c24b8b70ull, 0xa81a664ba2bfe8a1ull);
    ShiftMessageB(&am1, am2, &am3);
    ShiftMessageB(&bm1, bm2, &bm3);
    QuadRoundMsg(&as0, &as1, am3, 0x106aa070f40e3585ull, 0xd6990624d192e819ull);
    QuadRoundMsg(&bs0, &bs1, bm3, 0x106aa070f40e3585ull, 0xd6990624d192e819ull);
    ShiftMessageB(&am2, am3, &am0);
    ShiftMessageB(&bm2, bm3, &bm0);
    QuadRoundMsg(&as0, &as1, am0, 0x34b0bcb52748774cull, 0x1e376c0819a4c116ull);
    QuadRoundMsg(&bs0, &bs1, bm0, 0x34b0bcb52748774cull, 0x1e376c0819a4c116ull);
    ShiftMessageB(&am3, am0, &am1);
    ShiftMessageB(&bm3, bm0, &bm1);
    QuadRoundMsg(&as0, &as1, am1, 0x682e6ff35b9cca4full, 0x4ed8aa4a391c0cb3ull);
    QuadRoundMsg(&bs0, &bs1, bm1, 0x682e6ff35b9cca4full, 0x4ed8aa4a391c0cb3ull);
    ShiftMessageC(&am0, am1, &am2);
    ShiftMessageC(&bm0, bm1, &bm2);
    QuadRoundMsg(&as0, &as1, am2, 0x8cc7020884c87814ull, 0x78a5636f748f82eeull);
    QuadRoundMsg(&bs0, &bs1, bm2, 0x8cc7020884c87814ull, 0x78a5636f748f82eeull);
    ShiftMessageC(&am1, am2, &am3);
    ShiftMessageC(&bm1, bm2, &bm3);
    QuadRoundMsg(&as0, &as1, am3, 0xc67178f2bef9a3f7ull, 0xa4506ceb90befffaull);
    QuadRoundMsg(&bs0, &bs1, bm3, 0xc67178f2bef9a3f7ull, 0xa4506ceb90befffaull);
    as0 = _mm_add_epi32(as0, _mm_load_si128((const __m128i*)INIT0));
    bs0 = _mm_add_epi32(bs0, _mm_load_si128((const __m128i*)INIT0));
    as1 = _mm_add_epi32(as1, _mm_load_si128((const __m128i*)INIT1));
    bs1 = _mm_add_epi32(bs1, _mm_load_si128((const __m128i*)INIT1));

    /* Output final hashes */
    Unshuffle(&as0, &as1);
    Unshuffle(&bs0, &bs1);
    Save(out, as0);
    Save(out + 16, as1);
    Save(out + 32, bs0);
    Save(out + 48, bs1);
}

#else
/* Stubs when SHA-NI not available at compile time */
void sha256_shani_transform(uint32_t* state, const unsigned char* data, size_t blocks) { (void)state; (void)data; (void)blocks; }
void sha256d64_shani(unsigned char* out, const unsigned char* in) { (void)out; (void)in; }
void sha256d64_shani_2way(unsigned char* out, const unsigned char* in) { (void)out; (void)in; }
#endif

#else
/* Non-x86 platforms: stubs */
void sha256_shani_transform(uint32_t* state, const unsigned char* data, size_t blocks) { (void)state; (void)data; (void)blocks; }
void sha256d64_shani(unsigned char* out, const unsigned char* in) { (void)out; (void)in; }
void sha256d64_shani_2way(unsigned char* out, const unsigned char* in) { (void)out; (void)in; }
#endif
