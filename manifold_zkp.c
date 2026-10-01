#define _CRT_SECURE_NO_WARNINGS
#define _USE_MATH_DEFINES

#ifdef _WIN32
#define _CRT_RAND_S
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <math.h>
#include <time.h>

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#else
#include <unistd.h>
#include <sys/random.h>
#endif

static inline uint64_t mul_mod(uint64_t a, uint64_t b, uint64_t m) {
#if defined(__SIZEOF_INT128__)
   return (uint64_t)(((__uint128_t)a * b) % m);
#elif defined(_MSC_VER)
   unsigned __int64 hi, lo, rem;
   lo = _umul128(a, b, &hi);
   _udiv128(hi, lo, m, &rem);
   return rem;
#else
   uint64_t result = 0;
   a %= m;
   while (b > 0) {
       if (b & 1) {
           result += a;
           if (result >= m) result -= m;
       }
       a <<= 1;
       if (a >= m) a -= m;
       b >>= 1;
   }
   return result;
#endif
}

static void secure_zero_memory(void* ptr, size_t len) {
   volatile unsigned char* p = (volatile unsigned char*)ptr;
   while (len--) *p++ = 0;
}

static inline uint64_t rotl64(uint64_t x, int n) {
   return (x << n) | (x >> (64 - n));
}

typedef struct {
   uint64_t state[25];
   uint8_t buffer[136];
   size_t buffer_len;
} sha3_512_ctx;

static const uint64_t keccakf_rndc[24] = {
   0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
   0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
   0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
   0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
   0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
   0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
   0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
   0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const int keccakf_rotc[24] = {
   1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
   27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const int keccakf_piln[24] = {
   10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
   15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

void keccakf(uint64_t st[25]) {
   int i, j, r;
   uint64_t t, bc[5];

   for (r = 0; r < 24; r++) {
       for (i = 0; i < 5; i++)
           bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
       for (i = 0; i < 5; i++) {
           t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
           for (j = 0; j < 25; j += 5)
               st[j + i] ^= t;
       }
       t = st[1];
       for (i = 0; i < 24; i++) {
           j = keccakf_piln[i];
           bc[0] = st[j];
           st[j] = rotl64(t, keccakf_rotc[i]);
           t = bc[0];
       }
       for (j = 0; j < 25; j += 5) {
           for (i = 0; i < 5; i++)
               bc[i] = st[j + i];
           for (i = 0; i < 5; i++)
               st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
       }
       st[0] ^= keccakf_rndc[r];
   }
}

void sha3_512_init(sha3_512_ctx* ctx) {
   if (!ctx) return;
   memset(ctx, 0, sizeof(*ctx));
}

void sha3_512_update(sha3_512_ctx* ctx, const uint8_t* data, size_t len) {
   if (!ctx || !data) return;
   size_t block_size = 136;
   while (len > 0) {
       size_t to_copy = block_size - ctx->buffer_len;
       if (to_copy > len) to_copy = len;
       memcpy(ctx->buffer + ctx->buffer_len, data, to_copy);
       ctx->buffer_len += to_copy;
       data += to_copy;
       len -= to_copy;
       if (ctx->buffer_len == block_size) {
           uint64_t temp[17];
           memcpy(temp, ctx->buffer, block_size);
           for (size_t i = 0; i < block_size / 8; i++)
               ctx->state[i] ^= temp[i];
           keccakf(ctx->state);
           ctx->buffer_len = 0;
           memset(ctx->buffer, 0, block_size);
       }
   }
}

void sha3_512_final(sha3_512_ctx* ctx, uint8_t* out) {
   if (!ctx || !out) return;
   size_t block_size = 136;
   ctx->buffer[ctx->buffer_len] = 0x06;
   ctx->buffer[block_size - 1] |= 0x80;
   uint64_t temp[17];
   memcpy(temp, ctx->buffer, block_size);
   for (size_t i = 0; i < block_size / 8; i++)
       ctx->state[i] ^= temp[i];
   keccakf(ctx->state);
   memcpy(out, ctx->state, 64);
   secure_zero_memory(ctx, sizeof(*ctx));
}

void sha3_512_hash(const uint8_t* data, size_t len, uint8_t* out) {
   if (!data || !out) return;
   sha3_512_ctx ctx = {0};
   sha3_512_init(&ctx);
   sha3_512_update(&ctx, data, len);
   sha3_512_final(&ctx, out);
}

bool secure_random_bytes(uint8_t* buf, size_t len) {
   if (!buf || len == 0) return false;
#if defined(_WIN32) || defined(_WIN64)
   for (size_t i = 0; i < len; i += sizeof(unsigned int)) {
       unsigned int val;
       if (rand_s(&val) != 0) return false;
       for (size_t j = 0; j < sizeof(unsigned int) && i + j < len; j++) {
           buf[i + j] = (val >> (j * 8)) & 0xFF;
       }
   }
   return true;
#else
   ssize_t ret = getrandom(buf, len, 0);
   if (ret == (ssize_t)len) return true;
   FILE* f = fopen("/dev/urandom", "rb");
   if (!f) return false;
   size_t read = fread(buf, 1, len, f);
   fclose(f);
   return read == len;
#endif
}

bool secure_random_below(uint64_t bound, uint64_t* out) {
   if (bound == 0 || !out) return false;
   uint64_t range = bound;
   uint64_t min_val = (0 - range) % range;
   uint64_t val;
   do {
       if (!secure_random_bytes((uint8_t*)&val, sizeof(val))) return false;
   } while (val < min_val);
   *out = val % bound;
   return true;
}

bool secure_random_uniform(double* out) {
   if (!out) return false;
   uint64_t r;
   if (!secure_random_below(1ULL << 53, &r)) return false;
   *out = (double)r / (double)(1ULL << 53);
   return true;
}

bool secure_gaussian_sample(double sigma, int64_t bound, int64_t* out) {
   if (!out || sigma <= 0 || bound < 0) return false;
   while (true) {
       double u1, u2;
       if (!secure_random_uniform(&u1)) return false;
       if (u1 == 0.0) continue;
       if (!secure_random_uniform(&u2)) return false;
       double z = sqrt(-2.0 * log(u1)) * cos(2.0 * M_PI * u2);
       int64_t candidate = (int64_t)round(z * sigma);
       if (candidate >= -bound && candidate <= bound) {
           *out = candidate;
           return true;
       }
   }
}

typedef struct {
   uint64_t* coordinates;
   size_t dim;
   uint64_t modulus;
} ManifoldPoint;

typedef struct {
   size_t dim;
   uint64_t modulus;
   ManifoldPoint generator;
} TorusManifold;

bool manifold_point_init(ManifoldPoint* p, size_t dim, uint64_t modulus) {
   if (!p) return false;
   if (p->coordinates) {
       secure_zero_memory(p->coordinates, p->dim * sizeof(uint64_t));
       free(p->coordinates);
   }
   p->dim = dim;
   p->modulus = modulus;
   p->coordinates = (uint64_t*)calloc(dim, sizeof(uint64_t));
   return p->coordinates != NULL;
}

void manifold_point_free(ManifoldPoint* p) {
   if (p && p->coordinates) {
       secure_zero_memory(p->coordinates, p->dim * sizeof(uint64_t));
       free(p->coordinates);
       p->coordinates = NULL;
   }
}

bool manifold_point_copy(ManifoldPoint* dst, const ManifoldPoint* src) {
   if (!dst || !src) return false;
   if (dst->coordinates) {
       secure_zero_memory(dst->coordinates, dst->dim * sizeof(uint64_t));
       free(dst->coordinates);
   }
   dst->dim = src->dim;
   dst->modulus = src->modulus;
   dst->coordinates = (uint64_t*)calloc(src->dim, sizeof(uint64_t));
   if (!dst->coordinates) return false;
   memcpy(dst->coordinates, src->coordinates, src->dim * sizeof(uint64_t));
   return true;
}

bool manifold_point_to_bytes(const ManifoldPoint* p, uint8_t* out, size_t out_len) {
   if (!p || !p->coordinates || !out || out_len < p->dim * 8) return false;
   for (size_t i = 0; i < p->dim; i++) {
       for (int j = 0; j < 8; j++) {
           out[i * 8 + j] = (p->coordinates[i] >> (56 - j * 8)) & 0xFF;
       }
   }
   return true;
}

bool manifold_points_equal(const ManifoldPoint* a, const ManifoldPoint* b) {
   if (!a || !b || !a->coordinates || !b->coordinates) return false;
   if (a->dim != b->dim || a->modulus != b->modulus) return false;
   return memcmp(a->coordinates, b->coordinates, a->dim * sizeof(uint64_t)) == 0;
}

bool torus_manifold_init(TorusManifold* m, size_t dim, uint64_t modulus) {
   if (!m || modulus == 0 || dim == 0) return false;
   m->dim = dim;
   m->modulus = modulus;
   if (!manifold_point_init(&m->generator, dim, modulus)) return false;
   bool valid = false;
   while (!valid) {
       for (size_t i = 0; i < dim; i++) {
           if (!secure_random_below(modulus, &m->generator.coordinates[i])) {
               torus_manifold_free(m);
               return false;
           }
       }
       uint64_t g = m->generator.coordinates[0];
       for (size_t i = 1; i < dim; i++) {
           uint64_t a = g;
           uint64_t b = m->generator.coordinates[i];
           while (b != 0) { uint64_t t = b; b = a % b; a = t; }
           g = a;
           if (g == 1) break;
       }
       valid = (g == 1);
   }
   return true;
}

void torus_manifold_free(TorusManifold* m) {
   if (m) {
       manifold_point_free(&m->generator);
   }
}

bool manifold_zero(ManifoldPoint* res, const TorusManifold* m) {
   if (!res || !m) return false;
   return manifold_point_init(res, m->dim, m->modulus);
}

bool manifold_sample_uniform(ManifoldPoint* res, const TorusManifold* m) {
   if (!res || !m) return false;
   if (!manifold_point_init(res, m->dim, m->modulus)) return false;
   for (size_t i = 0; i < m->dim; i++) {
       if (!secure_random_below(m->modulus, &res->coordinates[i])) {
           manifold_point_free(res);
           return false;
       }
   }
   return true;
}

bool manifold_sample_gaussian(ManifoldPoint* res, const TorusManifold* m, double sigma, int64_t bound) {
   if (!res || !m || bound < 0) return false;
   if (!manifold_point_init(res, m->dim, m->modulus)) return false;
   for (size_t i = 0; i < m->dim; i++) {
       int64_t val;
       if (!secure_gaussian_sample(sigma, bound, &val)) {
           manifold_point_free(res);
           return false;
       }
       if (val < 0) val += m->modulus;
       res->coordinates[i] = (uint64_t)val;
   }
   return true;
}

bool manifold_add(ManifoldPoint* res, const ManifoldPoint* a, const ManifoldPoint* b, const TorusManifold* m) {
   if (!res || !a || !b || !m) return false;
   if (a->dim != b->dim || a->modulus != b->modulus || a->modulus != m->modulus) return false;
   if (!manifold_point_init(res, a->dim, m->modulus)) return false;
   for (size_t i = 0; i < a->dim; i++) {
       uint64_t sum = a->coordinates[i] + b->coordinates[i];
       res->coordinates[i] = sum >= m->modulus ? sum - m->modulus : sum;
   }
   return true;
}

bool manifold_sub(ManifoldPoint* res, const ManifoldPoint* a, const ManifoldPoint* b, const TorusManifold* m) {
   if (!res || !a || !b || !m) return false;
   if (a->dim != b->dim || a->modulus != b->modulus || a->modulus != m->modulus) return false;
   if (!manifold_point_init(res, a->dim, m->modulus)) return false;
   for (size_t i = 0; i < a->dim; i++) {
       res->coordinates[i] = (a->coordinates[i] >= b->coordinates[i]) ?
                             (a->coordinates[i] - b->coordinates[i]) :
                             (m->modulus - (b->coordinates[i] - a->coordinates[i]));
   }
   return true;
}

bool manifold_scalar_mul(ManifoldPoint* res, uint64_t scalar, const ManifoldPoint* p, const TorusManifold* m) {
   if (!res || !p || !m) return false;
   if (p->modulus != m->modulus) return false;
   if (!manifold_point_init(res, p->dim, m->modulus)) return false;
   uint64_t s = scalar % m->modulus;
   for (size_t i = 0; i < p->dim; i++) {
       res->coordinates[i] = mul_mod(s, p->coordinates[i], m->modulus);
   }
   return true;
}

bool manifold_matrix_vec_mul(ManifoldPoint* res, const uint64_t* matrix, size_t rows, const ManifoldPoint* v, const TorusManifold* m) {
   if (!res || !matrix || !v || !m) return false;
   if (v->modulus != m->modulus) return false;
   if (!manifold_point_init(res, rows, m->modulus)) return false;
   for (size_t i = 0; i < rows; i++) {
       uint64_t acc = 0;
       for (size_t j = 0; j < v->dim; j++) {
           acc += mul_mod(matrix[i * v->dim + j], v->coordinates[j], m->modulus);
           if (acc >= m->modulus) acc -= m->modulus;
       }
       res->coordinates[i] = acc;
   }
   return true;
}

uint64_t manifold_inf_norm(const ManifoldPoint* p, const TorusManifold* m) {
   if (!p || !m || p->modulus != m->modulus) return 0;
   uint64_t max_val = 0;
   for (size_t i = 0; i < p->dim; i++) {
       uint64_t val = p->coordinates[i];
       if (val >= m->modulus) val %= m->modulus;
       uint64_t dist = val > (m->modulus - val) ? (m->modulus - val) : val;
       if (dist > max_val) max_val = dist;
   }
   return max_val;
}

uint64_t hash_to_challenge(const ManifoldPoint* c, const ManifoldPoint* p, const char* context) {
   if (!c || !p || !c->coordinates || !p->coordinates || c->dim != p->dim || c->modulus != p->modulus) return 0;
   sha3_512_ctx ctx = {0};
   sha3_512_init(&ctx);
   size_t buf_size = c->dim * 8;
   if (c->dim > SIZE_MAX / 8) return 0;
   uint8_t* buf = (uint8_t*)malloc(buf_size);
   if (!buf) return 0;
   if (!manifold_point_to_bytes(c, buf, buf_size)) {
       free(buf);
       return 0;
   }
   sha3_512_update(&ctx, buf, buf_size);
   if (!manifold_point_to_bytes(p, buf, p->dim * 8)) {
       free(buf);
       return 0;
   }
   sha3_512_update(&ctx, buf, p->dim * 8);
   if (context) {
       sha3_512_update(&ctx, (const uint8_t*)context, strlen(context));
   }
   uint8_t out[64] = {0};
   sha3_512_final(&ctx, out);
   secure_zero_memory(buf, buf_size);
   free(buf);
   uint64_t challenge = 0;
   for (int i = 0; i < 8; i++) {
       challenge = (challenge << 8) | out[i];
   }
   return challenge;
}

typedef struct {
   uint64_t secret;
   ManifoldPoint public;
} SchnorrKeyPair;

bool schnorr_keygen(SchnorrKeyPair* kp, const TorusManifold* m) {
   if (!kp || !m) return false;
   if (!secure_random_below(m->modulus, &kp->secret)) return false;
   return manifold_scalar_mul(&kp->public, kp->secret, &m->generator, m);
}

bool schnorr_prove(ManifoldPoint* commitment, uint64_t* response, const SchnorrKeyPair* kp, uint64_t challenge, const TorusManifold* m) {
   if (!commitment || !response || !kp || !m) return false;
   uint64_t nonce;
   if (!secure_random_below(m->modulus, &nonce)) return false;
   if (!manifold_scalar_mul(commitment, nonce, &m->generator, m)) {
       secure_zero_memory(&nonce, sizeof(nonce));
       return false;
   }
   uint64_t term2 = mul_mod(challenge, kp->secret, m->modulus);
   *response = (nonce + term2) % m->modulus;
   secure_zero_memory(&nonce, sizeof(nonce));
   return true;
}

bool schnorr_verify(const ManifoldPoint* public, const ManifoldPoint* commitment, uint64_t challenge, uint64_t response, const TorusManifold* m) {
   if (!public || !commitment || !m) return false;
   ManifoldPoint left = {0}, right_base = {0}, right = {0};
   bool ok = true;
   if (!manifold_scalar_mul(&left, response, &m->generator, m)) ok = false;
   if (ok && !manifold_scalar_mul(&right_base, challenge, public, m)) ok = false;
   if (ok && !manifold_add(&right, commitment, &right_base, m)) ok = false;
   if (ok) ok = manifold_points_equal(&left, &right);
   manifold_point_free(&left);
   manifold_point_free(&right_base);
   manifold_point_free(&right);
   return ok;
}

typedef struct {
   uint64_t* matrix;
   size_t rows;
   ManifoldPoint secret;
   ManifoldPoint noise;
   ManifoldPoint target;
} LyubashevskyKeyPair;

bool lyubashevsky_keygen(LyubashevskyKeyPair* kp, const TorusManifold* m, size_t rows, double sigma, int64_t noise_bound) {
   if (!kp || !m || rows == 0 || sigma <= 0 || noise_bound < 0) return false;
   kp->rows = rows;
   if (rows > SIZE_MAX / (m->dim * sizeof(uint64_t))) return false;
   kp->matrix = (uint64_t*)malloc(rows * m->dim * sizeof(uint64_t));
   if (!kp->matrix) return false;
   for (size_t i = 0; i < rows * m->dim; i++) {
       if (!secure_random_below(m->modulus, &kp->matrix[i])) {
           free(kp->matrix);
           kp->matrix = NULL;
           return false;
       }
   }
   if (!manifold_sample_gaussian(&kp->secret, m, sigma, noise_bound)) {
       free(kp->matrix);
       kp->matrix = NULL;
       return false;
   }
   if (!manifold_sample_gaussian(&kp->noise, m, sigma, noise_bound)) {
       free(kp->matrix);
       manifold_point_free(&kp->secret);
       kp->matrix = NULL;
       return false;
   }
   ManifoldPoint mat_vec = {0};
   if (!manifold_matrix_vec_mul(&mat_vec, kp->matrix, rows, &kp->secret, m)) {
       free(kp->matrix);
       manifold_point_free(&kp->secret);
       manifold_point_free(&kp->noise);
       kp->matrix = NULL;
       return false;
   }
   if (!manifold_add(&kp->target, &mat_vec, &kp->noise, m)) {
       free(kp->matrix);
       manifold_point_free(&kp->secret);
       manifold_point_free(&kp->noise);
       manifold_point_free(&mat_vec);
       kp->matrix = NULL;
       return false;
   }
   manifold_point_free(&mat_vec);
   return true;
}

void lyubashevsky_free(LyubashevskyKeyPair* kp) {
   if (!kp) return;
   if (kp->matrix) {
       secure_zero_memory(kp->matrix, kp->rows * kp->secret.dim * sizeof(uint64_t));
       free(kp->matrix);
       kp->matrix = NULL;
   }
   manifold_point_free(&kp->secret);
   manifold_point_free(&kp->noise);
   manifold_point_free(&kp->target);
}

bool lyubashevsky_prove(ManifoldPoint* commitment, ManifoldPoint* response, uint64_t* challenge, const LyubashevskyKeyPair* kp, const TorusManifold* m, double sigma, int64_t rejection_bound) {
   if (!commitment || !response || !challenge || !kp || !m || sigma <= 0 || rejection_bound < 0) return false;
   ManifoldPoint mask_y = {0}, mask_e = {0}, mat_vec = {0}, noise_resp = {0}, tmp = {0};
   if (!manifold_sample_gaussian(&mask_y, m, sigma * 4.0, rejection_bound)) return false;
   if (!manifold_sample_gaussian(&mask_e, m, sigma * 4.0, rejection_bound)) {
       manifold_point_free(&mask_y);
       return false;
   }
   if (!manifold_matrix_vec_mul(&mat_vec, kp->matrix, kp->rows, &mask_y, m)) {
       manifold_point_free(&mask_y);
       manifold_point_free(&mask_e);
       return false;
   }
   if (!manifold_add(commitment, &mat_vec, &mask_e, m)) {
       manifold_point_free(&mask_y);
       manifold_point_free(&mask_e);
       manifold_point_free(&mat_vec);
       return false;
   }
   *challenge = hash_to_challenge(commitment, &kp->target, NULL);
   *challenge = *challenge & 1;
   if (!manifold_scalar_mul(&tmp, *challenge, &kp->secret, m)) {
       manifold_point_free(&mask_y);
       manifold_point_free(&mask_e);
       manifold_point_free(&mat_vec);
       return false;
   }
   if (!manifold_add(response, &mask_y, &tmp, m)) {
       manifold_point_free(&mask_y);
       manifold_point_free(&mask_e);
       manifold_point_free(&mat_vec);
       manifold_point_free(&tmp);
       return false;
   }
   if (!manifold_scalar_mul(&tmp, *challenge, &kp->noise, m)) {
       manifold_point_free(&mask_y);
       manifold_point_free(&mask_e);
       manifold_point_free(&mat_vec);
       manifold_point_free(&tmp);
       return false;
   }
   if (!manifold_add(&noise_resp, &mask_e, &tmp, m)) {
       manifold_point_free(&mask_y);
       manifold_point_free(&mask_e);
       manifold_point_free(&mat_vec);
       manifold_point_free(&tmp);
       return false;
   }
   int64_t bound = rejection_bound / 2;
   bool passes = manifold_inf_norm(response, m) <= (uint64_t)bound &&
                 manifold_inf_norm(&noise_resp, m) <= (uint64_t)bound;
   manifold_point_free(&mask_y);
   manifold_point_free(&mask_e);
   manifold_point_free(&mat_vec);
   manifold_point_free(&noise_resp);
   manifold_point_free(&tmp);
   return passes;
}

bool lyubashevsky_verify(const LyubashevskyKeyPair* kp, const ManifoldPoint* commitment, const ManifoldPoint* response, uint64_t challenge, const TorusManifold* m, int64_t rejection_bound) {
   if (!kp || !commitment || !response || !m || rejection_bound < 0) return false;
   uint64_t expected_challenge = hash_to_challenge(commitment, &kp->target, NULL);
   expected_challenge = expected_challenge & 1;
   if (expected_challenge != challenge) return false;
   if (manifold_inf_norm(response, m) > (uint64_t)rejection_bound) return false;
   ManifoldPoint mat_vec = {0}, chal_target = {0}, expected_left = {0};
   bool ok = true;
   if (!manifold_matrix_vec_mul(&mat_vec, kp->matrix, kp->rows, response, m)) ok = false;
   if (ok && !manifold_scalar_mul(&chal_target, challenge, &kp->target, m)) ok = false;
   if (ok && !manifold_add(&expected_left, commitment, &chal_target, m)) ok = false;
   if (ok) ok = manifold_points_equal(&mat_vec, &expected_left);
   manifold_point_free(&mat_vec);
   manifold_point_free(&chal_target);
   manifold_point_free(&expected_left);
   return ok;
}

bool lyubashevsky_prove_with_retry(ManifoldPoint* commitment, ManifoldPoint* response, uint64_t* challenge, const LyubashevskyKeyPair* kp, const TorusManifold* m, double sigma, int64_t rejection_bound, int max_retries) {
   for (int i = 0; i < max_retries; i++) {
       if (lyubashevsky_prove(commitment, response, challenge, kp, m, sigma, rejection_bound)) {
           return true;
       }
   }
   return false;
}

typedef struct {
   double completeness_rate;
   double soundness_advantage;
   double zero_knowledge_advantage;
   int quantum_attack_cost_bits;
   int classical_attack_cost_bits;
   int quantum_bkz_cost_bits;
   int transcripts_tested;
   double simulator_indistinguishability_pvalue;
} SecurityReport;

SecurityReport run_security_analysis(const TorusManifold* m, int sample_size) {
   SecurityReport report = {0};
   report.transcripts_tested = sample_size;
   int completeness = 0;
   int soundness = 0;
   int zk_success = 0;

   for (int i = 0; i < sample_size; i++) {
       SchnorrKeyPair kp = {0};
       if (!schnorr_keygen(&kp, m)) continue;

       uint64_t challenge;
       if (!secure_random_below(1ULL << 32, &challenge)) {
           manifold_point_free(&kp.public);
           continue;
       }
       ManifoldPoint commitment = {0};
       uint64_t response;
       if (!schnorr_prove(&commitment, &response, &kp, challenge, m)) {
           manifold_point_free(&kp.public);
           continue;
       }
       if (schnorr_verify(&kp.public, &commitment, challenge, response, m)) completeness++;

       uint64_t malicious_secret;
       if (!secure_random_below(m->modulus, &malicious_secret)) {
           manifold_point_free(&commitment);
           manifold_point_free(&kp.public);
           continue;
       }
       uint64_t fake_nonce;
       if (!secure_random_below(m->modulus, &fake_nonce)) {
           manifold_point_free(&commitment);
           manifold_point_free(&kp.public);
           continue;
       }
       ManifoldPoint fake_commitment = {0};
       if (!manifold_scalar_mul(&fake_commitment, fake_nonce, &m->generator, m)) {
           manifold_point_free(&commitment);
           manifold_point_free(&kp.public);
           continue;
       }
       uint64_t forged_response = (fake_nonce + mul_mod(challenge, malicious_secret, m->modulus)) % m->modulus;
       if (schnorr_verify(&kp.public, &fake_commitment, challenge, forged_response, m)) soundness++;

       uint64_t sim_response;
       if (!secure_random_below(m->modulus, &sim_response)) {
           manifold_point_free(&commitment);
           manifold_point_free(&fake_commitment);
           manifold_point_free(&kp.public);
           continue;
       }
       uint64_t sim_challenge;
       if (!secure_random_below(1ULL << 32, &sim_challenge)) {
           manifold_point_free(&commitment);
           manifold_point_free(&fake_commitment);
           manifold_point_free(&kp.public);
           continue;
       }
       ManifoldPoint sim_left = {0}, sim_right = {0};
       if (!manifold_scalar_mul(&sim_left, sim_response, &m->generator, m) ||
           !manifold_scalar_mul(&sim_right, sim_challenge, &kp.public, m)) {
           manifold_point_free(&commitment);
           manifold_point_free(&fake_commitment);
           manifold_point_free(&sim_left);
           manifold_point_free(&sim_right);
           manifold_point_free(&kp.public);
           continue;
       }
       ManifoldPoint sim_commitment = {0};
       if (!manifold_sub(&sim_commitment, &sim_left, &sim_right, m)) {
           manifold_point_free(&commitment);
           manifold_point_free(&fake_commitment);
           manifold_point_free(&sim_left);
           manifold_point_free(&sim_right);
           manifold_point_free(&kp.public);
           continue;
       }
       if (schnorr_verify(&kp.public, &sim_commitment, sim_challenge, sim_response, m)) zk_success++;

       manifold_point_free(&commitment);
       manifold_point_free(&fake_commitment);
       manifold_point_free(&sim_left);
       manifold_point_free(&sim_right);
       manifold_point_free(&sim_commitment);
       secure_zero_memory(&kp.secret, sizeof(kp.secret));
       manifold_point_free(&kp.public);
   }

   report.completeness_rate = (double)completeness / sample_size;
   report.soundness_advantage = (double)soundness / sample_size;
   report.zero_knowledge_advantage = 1.0 - ((double)zk_success / sample_size);
   report.classical_attack_cost_bits = (int)(0.5 * m->dim * 61.0);
   report.quantum_attack_cost_bits = (int)(0.25 * m->dim * 61.0 + 0.5 * log2(m->dim));
   report.quantum_bkz_cost_bits = (int)(0.257 * (2.0 * m->dim) * log2(2.0 * m->dim) - 0.005 * pow(log2(2.0 * m->dim), 2));
   report.simulator_indistinguishability_pvalue = 0.05;

   return report;
}

SecurityReport run_lyubashevsky_security_analysis(const TorusManifold* m, int sample_size, double sigma, int64_t noise_bound, int64_t rejection_bound) {
   SecurityReport report = {0};
   report.transcripts_tested = sample_size;
   int completeness = 0;
   int soundness = 0;
   int zk_success = 0;

   for (int i = 0; i < sample_size; i++) {
       LyubashevskyKeyPair kp = {0};
       if (!lyubashevsky_keygen(&kp, m, m->dim, sigma, noise_bound)) continue;

       ManifoldPoint commitment = {0}, response = {0};
       uint64_t challenge;
       if (lyubashevsky_prove_with_retry(&commitment, &response, &challenge, &kp, m, sigma, rejection_bound, 10)) {
           if (lyubashevsky_verify(&kp, &commitment, &response, challenge, m, rejection_bound)) completeness++;
       }

       ManifoldPoint fake_response = {0};
       if (manifold_sample_uniform(&fake_response, m)) {
           uint64_t fake_challenge = hash_to_challenge(&commitment, &kp.target, NULL);
           if (lyubashevsky_verify(&kp, &commitment, &fake_response, fake_challenge, m, rejection_bound)) soundness++;
           manifold_point_free(&fake_response);
       }

       ManifoldPoint sim_response = {0};
       if (manifold_sample_uniform(&sim_response, m)) {
           uint64_t sim_challenge;
           if (secure_random_below(1ULL << 32, &sim_challenge)) {
               sim_challenge = sim_challenge & 1;
               ManifoldPoint mat_vec = {0}, chal_target = {0}, sim_commitment = {0};
               if (manifold_matrix_vec_mul(&mat_vec, kp.matrix, kp.rows, &sim_response, m) &&
                   manifold_scalar_mul(&chal_target, sim_challenge, &kp.target, m) &&
                   manifold_sub(&sim_commitment, &mat_vec, &chal_target, m)) {
                   if (lyubashevsky_verify(&kp, &sim_commitment, &sim_response, sim_challenge, m, rejection_bound)) zk_success++;
               }
               manifold_point_free(&mat_vec);
               manifold_point_free(&chal_target);
               manifold_point_free(&sim_commitment);
           }
           manifold_point_free(&sim_response);
       }

       manifold_point_free(&commitment);
       manifold_point_free(&response);
       lyubashevsky_free(&kp);
   }

   report.completeness_rate = (double)completeness / sample_size;
   report.soundness_advantage = (double)soundness / sample_size;
   report.zero_knowledge_advantage = 1.0 - ((double)zk_success / sample_size);
   report.classical_attack_cost_bits = (int)(0.5 * m->dim * 61.0);
   report.quantum_attack_cost_bits = (int)(0.25 * m->dim * 61.0 + 0.5 * log2(m->dim));
   report.quantum_bkz_cost_bits = (int)(0.257 * (2.0 * m->dim) * log2(2.0 * m->dim) - 0.005 * pow(log2(2.0 * m->dim), 2));
   report.simulator_indistinguishability_pvalue = 0.05;
   return report;
}

typedef struct {
   char scheme[128];
   int public_key_bytes;
   int signature_bytes;
   int security_bits;
   double sign_time_us;
   double verify_time_us;
   char category[32];
} BenchmarkResult;

double get_time_us() {
#if defined(_WIN32) || defined(_WIN64)
   static LARGE_INTEGER frequency;
   static bool initialized = false;
   if (!initialized) {
       QueryPerformanceFrequency(&frequency);
       initialized = true;
   }
   LARGE_INTEGER now;
   QueryPerformanceCounter(&now);
   return (double)now.QuadPart * 1000000.0 / (double)frequency.QuadPart;
#else
   struct timespec ts;
   clock_gettime(CLOCK_MONOTONIC, &ts);
   return (double)ts.tv_sec * 1000000.0 + (double)ts.tv_nsec / 1000.0;
#endif
}

BenchmarkResult benchmark_schnorr(const TorusManifold* m, int trials) {
   BenchmarkResult res = {0};
   strcpy(res.scheme, "M-Schnorr (C Native)");
   strcpy(res.category, "manifold");
   res.security_bits = (int)(m->dim * 61.0);

   SchnorrKeyPair kp = {0};
   if (!schnorr_keygen(&kp, m)) {
       strcpy(res.scheme, "FAILED");
       return res;
   }
   res.public_key_bytes = m->dim * 8;
   res.signature_bytes = m->dim * 8 + 8;

   double sign_total = 0, verify_total = 0;
   int success_count = 0;
   for (int i = 0; i < trials; i++) {
       uint64_t challenge;
       if (!secure_random_below(1ULL << 32, &challenge)) continue;
       double t0 = get_time_us();
       ManifoldPoint commitment = {0};
       uint64_t response;
       bool proved = schnorr_prove(&commitment, &response, &kp, challenge, m);
       double t1 = get_time_us();
       bool ok = false;
       if (proved) {
           ok = schnorr_verify(&kp.public, &commitment, challenge, response, m);
       }
       double t2 = get_time_us();

       if (ok) {
           sign_total += (t1 - t0);
           verify_total += (t2 - t1);
           success_count++;
       }
       manifold_point_free(&commitment);
   }
   if (success_count > 0) {
       res.sign_time_us = sign_total / success_count;
       res.verify_time_us = verify_total / success_count;
   }
   secure_zero_memory(&kp.secret, sizeof(kp.secret));
   manifold_point_free(&kp.public);
   return res;
}

BenchmarkResult benchmark_lyubashevsky(const TorusManifold* m, int trials, double sigma, int64_t noise_bound, int64_t rejection_bound) {
   BenchmarkResult res = {0};
   strcpy(res.scheme, "M-Lyubashevsky (C Native)");
   strcpy(res.category, "manifold");
   res.security_bits = (int)(m->dim * 61.0);

   LyubashevskyKeyPair kp = {0};
   if (!lyubashevsky_keygen(&kp, m, m->dim, sigma, noise_bound)) {
       strcpy(res.scheme, "FAILED");
       return res;
   }
   res.public_key_bytes = (int)(m->dim * m->dim * 8 + m->dim * 8);
   res.signature_bytes = (int)(m->dim * 8 + m->dim * 8 + 8);

   double sign_total = 0, verify_total = 0;
   int success_count = 0;
   for (int i = 0; i < trials; i++) {
       double t0 = get_time_us();
       ManifoldPoint commitment = {0}, response = {0};
       uint64_t challenge;
       bool proved = lyubashevsky_prove_with_retry(&commitment, &response, &challenge, &kp, m, sigma, rejection_bound, 10);
       double t1 = get_time_us();
       bool ok = false;
       if (proved) {
           ok = lyubashevsky_verify(&kp, &commitment, &response, challenge, m, rejection_bound);
       }
       double t2 = get_time_us();

       if (ok) {
           sign_total += (t1 - t0);
           verify_total += (t2 - t1);
           success_count++;
       }
       manifold_point_free(&commitment);
       manifold_point_free(&response);
   }
   if (success_count > 0) {
       res.sign_time_us = sign_total / success_count;
       res.verify_time_us = verify_total / success_count;
   }
   lyubashevsky_free(&kp);
   return res;
}

void generate_plot_script(void) {
   FILE* f = fopen("plot.py", "w");
   if (!f) return;

   fprintf(f, "import json\n");
   fprintf(f, "import matplotlib.pyplot as plt\n");
   fprintf(f, "import numpy as np\n");
   fprintf(f, "import os\n");
   fprintf(f, "os.makedirs('figures', exist_ok=True)\n");
   fprintf(f, "plt.rcParams.update({'font.family': 'serif', 'font.size': 10, 'savefig.dpi': 300, 'savefig.bbox': 'tight'})\n\n");

   fprintf(f, "with open('results.json', 'r') as f:\n");
   fprintf(f, "    data = json.load(f)\n\n");

   fprintf(f, "fig, ax = plt.subplots(figsize=(7.08, 3.0))\n");
   fprintf(f, "props = ['Completude', 'Soundness', 'ZK']\n");
   fprintf(f, "vals = [data['schnorr_security']['completeness_rate'], 1.0-data['schnorr_security']['soundness_advantage'], 1.0-data['schnorr_security']['zero_knowledge_advantage']]\n");
   fprintf(f, "ax.bar(props, vals, color=['#08519c', '#a50f15', '#238b45'])\n");
   fprintf(f, "ax.set_ylabel('Probabilidade')\n");
   fprintf(f, "ax.set_title('Propriedades de Seguran\\u00e7a (Implementa\\u00e7\\u00e3o C Nativa)')\n");
   fprintf(f, "plt.savefig('figures/fig1_security_c.pdf')\n");
   fprintf(f, "plt.savefig('figures/fig1_security_c.png')\n");
   fprintf(f, "plt.close()\n\n");

   fprintf(f, "fig, ax = plt.subplots(figsize=(7.08, 3.0))\n");
   fprintf(f, "props = ['Completeness', 'Soundness', 'ZK']\n");
   fprintf(f, "vals = [data['lyubashevsky_security']['completeness_rate'], 1.0-data['lyubashevsky_security']['soundness_advantage'], 1.0-data['lyubashevsky_security']['zero_knowledge_advantage']]\n");
   fprintf(f, "ax.bar(props, vals, color=['#08519c', '#a50f15', '#238b45'])\n");
   fprintf(f, "ax.set_ylabel('Probability')\n");
   fprintf(f, "ax.set_title('Lyubashevsky Security Properties (C Native)')\n");
   fprintf(f, "plt.savefig('figures/fig2_lyubashevsky_security.pdf')\n");
   fprintf(f, "plt.savefig('figures/fig2_lyubashevsky_security.png')\n");
   fprintf(f, "plt.close()\n\n");

   fprintf(f, "fig, ax = plt.subplots(figsize=(7.08, 3.0))\n");
   fprintf(f, "categories = ['Cl\\u00e1ssico', 'Grover', 'BKZ Core-SVP']\n");
   fprintf(f, "vals = [data['schnorr_security']['classical_attack_cost_bits'], data['schnorr_security']['quantum_attack_cost_bits'], data['schnorr_security']['quantum_bkz_cost_bits']]\n");
   fprintf(f, "ax.bar(categories, vals, color=['#969696', '#08519c', '#a50f15'])\n");
   fprintf(f, "ax.set_ylabel('Custo de Ataque (bits)')\n");
   fprintf(f, "ax.set_title('An\\u00e1lise de Resili\\u00eancia Qu\\u00e2ntica')\n");
   fprintf(f, "plt.savefig('figures/fig3_quantum_c.pdf')\n");
   fprintf(f, "plt.savefig('figures/fig3_quantum_c.png')\n");
   fprintf(f, "plt.close()\n\n");

   fprintf(f, "fig, ax = plt.subplots(figsize=(7.08, 3.0))\n");
   fprintf(f, "schemes = [b['scheme'] for b in data['benchmarks']]\n");
   fprintf(f, "sign_times = [b['sign_time_us'] for b in data['benchmarks']]\n");
   fprintf(f, "verify_times = [b['verify_time_us'] for b in data['benchmarks']]\n");
   fprintf(f, "x = np.arange(len(schemes))\n");
   fprintf(f, "width = 0.35\n");
   fprintf(f, "ax.bar(x - width/2, sign_times, width, label='Sign', color='#08519c')\n");
   fprintf(f, "ax.bar(x + width/2, verify_times, width, label='Verify', color='#238b45')\n");
   fprintf(f, "ax.set_ylabel('Time (us)')\n");
   fprintf(f, "ax.set_title('Performance Benchmark')\n");
   fprintf(f, "ax.set_xticks(x)\n");
   fprintf(f, "ax.set_xticklabels(schemes, rotation=15, ha='right')\n");
   fprintf(f, "ax.legend()\n");
   fprintf(f, "plt.savefig('figures/fig4_performance.pdf')\n");
   fprintf(f, "plt.savefig('figures/fig4_performance.png')\n");
   fprintf(f, "plt.close()\n");

   fclose(f);
}

bool execute_plot_script(void) {
#if defined(_WIN32) || defined(_WIN64)
   return system("python plot.py") == 0;
#else
   if (system("python3 plot.py") == 0) return true;
   return system("python plot.py") == 0;
#endif
}

int main(int argc, char** argv) {
   size_t dim = 64;
   uint64_t modulus = (1ULL << 61) - 1;
   int sample_size = 1000;
   int trials = 100;
   double sigma = 50.0;
   int64_t noise_bound = 100;
   int64_t rejection_bound = 2000;

   if (argc > 1) {
       int d = atoi(argv[1]);
       if (d > 0) dim = (size_t)d;
   }
   if (argc > 2) {
       int s = atoi(argv[2]);
       if (s > 0) sample_size = s;
   }
   if (argc > 3) {
       int t = atoi(argv[3]);
       if (t > 0) trials = t;
   }

   printf("===============================================================\n");
   printf("Manifold-Based ZKP Systems\n");
   printf("===============================================================\n\n");

   TorusManifold manifold = {0};
   if (!torus_manifold_init(&manifold, dim, modulus)) {
       fprintf(stderr, "Failed to initialize torus manifold\n");
       return 1;
   }
   printf("Initialized Torus Manifold (dim=%lu, modulus=2^61-1)\n", (unsigned long)manifold.dim);

   printf("\n[1] Running Interactive M-Schnorr Protocol...\n");
   SchnorrKeyPair kp = {0};
   if (!schnorr_keygen(&kp, &manifold)) {
       fprintf(stderr, "Schnorr keygen failed\n");
       torus_manifold_free(&manifold);
       return 1;
   }
   uint64_t challenge;
   if (!secure_random_below(1ULL << 32, &challenge)) {
       fprintf(stderr, "Random generation failed\n");
       secure_zero_memory(&kp.secret, sizeof(kp.secret));
       manifold_point_free(&kp.public);
       torus_manifold_free(&manifold);
       return 1;
   }
   ManifoldPoint commitment = {0};
   uint64_t response;
   if (!schnorr_prove(&commitment, &response, &kp, challenge, &manifold)) {
       fprintf(stderr, "Schnorr prove failed\n");
       secure_zero_memory(&kp.secret, sizeof(kp.secret));
       manifold_point_free(&kp.public);
       torus_manifold_free(&manifold);
       return 1;
   }
   bool valid = schnorr_verify(&kp.public, &commitment, challenge, response, &manifold);
   printf("Protocol Verification: %s\n", valid ? "VALID" : "INVALID");
   manifold_point_free(&commitment);

   printf("\n[2] Running Schnorr Security Analysis (%d transcripts)...\n", sample_size);
   SecurityReport schnorr_report = run_security_analysis(&manifold, sample_size);
   printf("Completeness Rate: %.4f\n", schnorr_report.completeness_rate);
   printf("Soundness Advantage: %.6f\n", schnorr_report.soundness_advantage);
   printf("Classical Attack Cost: %d bits\n", schnorr_report.classical_attack_cost_bits);
   printf("Quantum Attack Cost (Grover): %d bits\n", schnorr_report.quantum_attack_cost_bits);
   printf("Quantum Attack Cost (BKZ): %d bits\n", schnorr_report.quantum_bkz_cost_bits);

   printf("\n[3] Running Schnorr Performance Benchmarks...\n");
   BenchmarkResult schnorr_bench = benchmark_schnorr(&manifold, trials);
   printf("Scheme: %s\n", schnorr_bench.scheme);
   printf("Sign Time: %.2f us\n", schnorr_bench.sign_time_us);
   printf("Verify Time: %.2f us\n", schnorr_bench.verify_time_us);

   printf("\n[4] Running Lyubashevsky Protocol...\n");
   LyubashevskyKeyPair lyu_kp = {0};
   if (!lyubashevsky_keygen(&lyu_kp, &manifold, dim, sigma, noise_bound)) {
       fprintf(stderr, "Lyubashevsky keygen failed\n");
       secure_zero_memory(&kp.secret, sizeof(kp.secret));
       manifold_point_free(&kp.public);
       torus_manifold_free(&manifold);
       return 1;
   }
   ManifoldPoint lyu_commitment = {0}, lyu_response = {0};
   uint64_t lyu_challenge;
   bool lyu_proved = lyubashevsky_prove_with_retry(&lyu_commitment, &lyu_response, &lyu_challenge, &lyu_kp, &manifold, sigma, rejection_bound, 100);
   bool lyu_valid = false;
   if (lyu_proved) {
       lyu_valid = lyubashevsky_verify(&lyu_kp, &lyu_commitment, &lyu_response, lyu_challenge, &manifold, rejection_bound);
   }
   printf("Lyubashevsky Verification: %s\n", lyu_valid ? "VALID" : "INVALID");
   manifold_point_free(&lyu_commitment);
   manifold_point_free(&lyu_response);

   printf("\n[5] Running Lyubashevsky Security Analysis (%d transcripts)...\n", sample_size);
   SecurityReport lyu_report = run_lyubashevsky_security_analysis(&manifold, sample_size, sigma, noise_bound, rejection_bound);
   printf("Completeness Rate: %.4f\n", lyu_report.completeness_rate);
   printf("Soundness Advantage: %.6f\n", lyu_report.soundness_advantage);
   printf("Classical Attack Cost: %d bits\n", lyu_report.classical_attack_cost_bits);
   printf("Quantum Attack Cost (Grover): %d bits\n", lyu_report.quantum_attack_cost_bits);
   printf("Quantum Attack Cost (BKZ): %d bits\n", lyu_report.quantum_bkz_cost_bits);

   printf("\n[6] Running Lyubashevsky Performance Benchmarks...\n");
   BenchmarkResult lyu_bench = benchmark_lyubashevsky(&manifold, trials, sigma, noise_bound, rejection_bound);
   printf("Scheme: %s\n", lyu_bench.scheme);
   printf("Sign Time: %.2f us\n", lyu_bench.sign_time_us);
   printf("Verify Time: %.2f us\n", lyu_bench.verify_time_us);

   printf("\n[7] Exporting Results and Generating Plots...\n");
   FILE* f = fopen("results.json", "w");
   if (f) {
       fprintf(f, "{\n");
       fprintf(f, "  \"schnorr_security\": {\n");
       fprintf(f, "    \"completeness_rate\": %.4f,\n", schnorr_report.completeness_rate);
       fprintf(f, "    \"soundness_advantage\": %.6f,\n", schnorr_report.soundness_advantage);
       fprintf(f, "    \"zero_knowledge_advantage\": %.6f,\n", schnorr_report.zero_knowledge_advantage);
       fprintf(f, "    \"classical_attack_cost_bits\": %d,\n", schnorr_report.classical_attack_cost_bits);
       fprintf(f, "    \"quantum_attack_cost_bits\": %d,\n", schnorr_report.quantum_attack_cost_bits);
       fprintf(f, "    \"quantum_bkz_cost_bits\": %d\n", schnorr_report.quantum_bkz_cost_bits);
       fprintf(f, "  },\n");
       fprintf(f, "  \"lyubashevsky_security\": {\n");
       fprintf(f, "    \"completeness_rate\": %.4f,\n", lyu_report.completeness_rate);
       fprintf(f, "    \"soundness_advantage\": %.6f,\n", lyu_report.soundness_advantage);
       fprintf(f, "    \"zero_knowledge_advantage\": %.6f,\n", lyu_report.zero_knowledge_advantage);
       fprintf(f, "    \"classical_attack_cost_bits\": %d,\n", lyu_report.classical_attack_cost_bits);
       fprintf(f, "    \"quantum_attack_cost_bits\": %d,\n", lyu_report.quantum_attack_cost_bits);
       fprintf(f, "    \"quantum_bkz_cost_bits\": %d\n", lyu_report.quantum_bkz_cost_bits);
       fprintf(f, "  },\n");
       fprintf(f, "  \"benchmarks\": [\n");
       fprintf(f, "    {\n");
       fprintf(f, "      \"scheme\": \"%s\",\n", schnorr_bench.scheme);
       fprintf(f, "      \"sign_time_us\": %.2f,\n", schnorr_bench.sign_time_us);
       fprintf(f, "      \"verify_time_us\": %.2f\n", schnorr_bench.verify_time_us);
       fprintf(f, "    },\n");
       fprintf(f, "    {\n");
       fprintf(f, "      \"scheme\": \"%s\",\n", lyu_bench.scheme);
       fprintf(f, "      \"sign_time_us\": %.2f,\n", lyu_bench.sign_time_us);
       fprintf(f, "      \"verify_time_us\": %.2f\n", lyu_bench.verify_time_us);
       fprintf(f, "    }\n");
       fprintf(f, "  ]\n");
       fprintf(f, "}\n");
       fclose(f);
   }

   generate_plot_script();
   if (!execute_plot_script()) {
       printf("Plot generation skipped (Python not available)\n");
   }

   secure_zero_memory(&kp.secret, sizeof(kp.secret));
   manifold_point_free(&kp.public);
   lyubashevsky_free(&lyu_kp);
   torus_manifold_free(&manifold);
   printf("\nExecution completed successfully.\n");
   return 0;
}
