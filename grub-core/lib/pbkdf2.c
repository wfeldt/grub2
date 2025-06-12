/* gc-pbkdf2-sha1.c --- Password-Based Key Derivation Function a'la PKCS#5
   Copyright (C) 2002, 2003, 2004, 2005, 2006, 2009 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.  */

/* Written by Simon Josefsson.  */
/* Imported from gnulib.  */

#pragma GCC diagnostic ignored "-Wvla"

#include <grub/crypto.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/time.h>
#include <grub/dl.h>

GRUB_MOD_LICENSE ("GPLv2+");

/* Implement PKCS#5 PBKDF2 as per RFC 2898.  The PRF to use is HMAC variant
   of digest supplied by MD.  Inputs are the password P of length PLEN,
   the salt S of length SLEN, the iteration counter C (> 0), and the
   desired derived output length DKLEN.  Output buffer is DK which
   must have room for at least DKLEN octets.  The output buffer will
   be filled with the derived data.  */

void
grub_crypto_pbkdf2_sha (
		    const grub_uint8_t *P, grub_size_t Plen,
		    const grub_uint8_t *S, grub_size_t Slen,
		    unsigned int c,
		    grub_uint8_t *DK, grub_size_t dkLen);

gcry_err_code_t
grub_crypto_pbkdf2 (const struct gcry_md_spec *md,
		    const grub_uint8_t *P, grub_size_t Plen,
		    const grub_uint8_t *S, grub_size_t Slen,
		    unsigned int c,
		    grub_uint8_t *DK, grub_size_t dkLen)
{
  unsigned int hLen = md->mdlen;
  grub_uint8_t U[GRUB_CRYPTO_MAX_MDLEN];
  grub_uint8_t T[GRUB_CRYPTO_MAX_MDLEN];
  unsigned int u;
  unsigned int l;
  unsigned int r;
  unsigned int i;
  unsigned int k;
  gcry_err_code_t rc;
  grub_uint8_t *tmp;
  grub_size_t tmplen = Slen + 4;

  if (md->mdlen > GRUB_CRYPTO_MAX_MDLEN || md->mdlen == 0)
    return GPG_ERR_INV_ARG;

  if (c == 0)
    return GPG_ERR_INV_ARG;

  if (dkLen == 0)
    return GPG_ERR_INV_ARG;

  if (dkLen > 4294967295U)
    return GPG_ERR_INV_ARG;

  if (!grub_strcasecmp (md->name, "SHA256"))
    {
      grub_crypto_pbkdf2_sha (P, Plen, S, Slen, c, DK, dkLen);

      return GPG_ERR_NO_ERROR;
    }

  l = ((dkLen - 1) / hLen) + 1;
  r = dkLen - (l - 1) * hLen;

  tmp = grub_malloc (tmplen);
  if (tmp == NULL)
    return GPG_ERR_OUT_OF_MEMORY;

  grub_memcpy (tmp, S, Slen);

  for (i = 1; i - 1 < l; i++)
    {
      grub_memset (T, 0, hLen);

      for (u = 0; u < c; u++)
	{
	  if (u == 0)
	    {
	      tmp[Slen + 0] = (i & 0xff000000) >> 24;
	      tmp[Slen + 1] = (i & 0x00ff0000) >> 16;
	      tmp[Slen + 2] = (i & 0x0000ff00) >> 8;
	      tmp[Slen + 3] = (i & 0x000000ff) >> 0;

	      rc = grub_crypto_hmac_buffer (md, P, Plen, tmp, tmplen, U);
	    }
	  else
	    rc = grub_crypto_hmac_buffer (md, P, Plen, U, hLen, U);

	  if (rc != GPG_ERR_NO_ERROR)
	    {
	      grub_free (tmp);
	      return rc;
	    }

	  for (k = 0; k < hLen; k++)
	    T[k] ^= U[k];
	}

      grub_memcpy (DK + (i - 1) * hLen, T, i == l ? r : hLen);
    }

  grub_free (tmp);

  return GPG_ERR_NO_ERROR;
}


typedef __UINT8_TYPE__ uint8_t;
typedef __UINT32_TYPE__ uint32_t;
typedef __UINT64_TYPE__ uint64_t;

typedef enum { f_default = 0, f_normal, f_slow, f_fast } func_t;

typedef struct {
  uint8_t *buf;
  unsigned len;
} data_t;

#define SHA_STATE_SIZE	8
#define SHA_INITIAL_STATE { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 }
#define SHA_HASH_SIZE	(SHA_STATE_SIZE * 4)
#define SHA_BLOCK_SIZE	64
#define SHA_LEN_SIZE	8

#define MEM_COPY(dst, src, n) do { for(unsigned u = 0; u < (n); u++) { (dst)[u] = (src)[u]; } } while(0)
#define MEM_XOR(dst, src, n) do { for(unsigned u = 0; u < (n); u++) { (dst)[u] ^= (src)[u]; } } while(0)
#define MEM_XOR_CONST(dst, val, n) do { for(unsigned u = 0; u < (n); u++) { (dst)[u] ^= val; } } while(0)

typedef struct {
  uint32_t data[SHA_STATE_SIZE];
} sha_state_t;

typedef struct {
  sha_state_t state;
  uint64_t len;
  struct {
    uint8_t buf[SHA_BLOCK_SIZE];
    unsigned len;
  } last;
} sha_t;

typedef struct {
  uint8_t blk[SHA_BLOCK_SIZE];
  sha_state_t state1, state2;
} sha_hmac_state_t;

static unsigned cpu_has_sha(void)
{
#if defined(__i386__) || defined (__x86_64__)
  uint32_t a, b, c, d;

  asm volatile (
    "cpuid"
    : "=a" (a), "=b" (b), "=c" (c), "=d" (d)
    : "a" (7), "c" (0)
    :
  );

  return (b >> 29) & 1;
#else
  return 0;
#endif
}

uint32_t get_uint32_be(uint8_t *buf);
uint64_t get_uint64_be(uint8_t *buf);
void put_uint32_be(uint8_t *buf, uint32_t val);
void put_uint64_be(uint8_t *buf, uint64_t val);

void sha_pbkdf2(data_t *key, data_t *password, data_t *salt, unsigned iterations);
void sha_hmac_pbkdf2_prep(sha_hmac_state_t *hmac_state, data_t *password);
void sha_hmac_pbkdf2_step(sha_hmac_state_t *hmac_state);
void sha_hmac(uint8_t sum[SHA_HASH_SIZE], data_t *data, data_t *password);
void sha_sum(uint8_t sum[SHA_HASH_SIZE], data_t *data);
void sha_sum2(uint8_t sum[SHA_HASH_SIZE], data_t *data1, data_t *data2);

void sha_init(sha_t *sha);
void sha_finish(sha_t *sha);
void sha_set_sum(sha_t *sha, uint8_t sum[SHA_HASH_SIZE]);
void sha_process_data(sha_t *sha, data_t *data);

void sha_process_block(sha_t *sha, uint8_t *buf);

#if defined(__i386__) || defined (__x86_64__)
void sha_process_block_fast(sha_t *sha, uint8_t *buffer);
#endif
void sha_process_block_slow(sha_t *sha, uint8_t *buffer);

void
grub_crypto_pbkdf2_sha (
		    const grub_uint8_t *P, grub_size_t Plen,
		    const grub_uint8_t *S, grub_size_t Slen,
		    unsigned int c,
		    grub_uint8_t *DK, grub_size_t dkLen)
{
  sha_pbkdf2(
    &(data_t) { .buf = DK, .len = dkLen },
    &(data_t) { .buf = (uint8_t *) P, .len = Plen },
    &(data_t) { .buf = (uint8_t *) S, .len = Slen },
    c
  );
}

static func_t sha_func = f_default;

uint32_t get_uint32_be(uint8_t *buf)
{
  return ((uint32_t) buf[0] << 24) + ((uint32_t) buf[1] << 16) + ((uint32_t) buf[2] << 8) + buf[3];
}

uint64_t get_uint64_be(uint8_t *buf)
{
  return ((uint64_t) get_uint32_be(buf) << 32) + get_uint32_be(buf + 4);
}

void put_uint32_be(uint8_t *buf, uint32_t val)
{
  buf[3] = val;
  buf[2] = val >> 8;
  buf[1] = val >> 16;
  buf[0] = val >> 24;
}

void put_uint64_be(uint8_t *buf, uint64_t val)
{
  put_uint32_be(buf + 4, val);
  put_uint32_be(buf, val >> 32);
}

void sha_pbkdf2(data_t *key, data_t *password, data_t *salt, unsigned iterations)
{
  if(!iterations || !key->len) return;

  unsigned hash_len = SHA_HASH_SIZE;
  unsigned blocks = (key->len - 1) / hash_len + 1;
  unsigned r = key->len - (blocks - 1) * hash_len;

  uint8_t __attribute__((aligned(8))) salt_buf[salt->len + 4];

  MEM_COPY(salt_buf, salt->buf, salt->len);

  sha_hmac_state_t __attribute__((aligned(16))) hmac_state;

  sha_hmac_pbkdf2_prep(&hmac_state, password);

  for(unsigned block = 0; block < blocks; block++) {
    uint8_t __attribute__((aligned(8))) T[hash_len];

    put_uint32_be(salt_buf + salt->len, block + 1);

    sha_hmac(hmac_state.blk, &(data_t) { .buf = salt_buf, .len = salt->len + 4 }, password);

    MEM_COPY(T, hmac_state.blk, hash_len);

    for(unsigned cnt = 1; cnt < iterations; cnt++) {
      sha_hmac_pbkdf2_step(&hmac_state);

      MEM_XOR(T, hmac_state.blk, hash_len);
    }

    unsigned count = block == blocks - 1 ? r : hash_len;
    unsigned ofs = block * hash_len;

    MEM_COPY(key->buf + ofs, T, count);
  }
}

void sha_hmac_pbkdf2_prep(sha_hmac_state_t *hmac_state, data_t *password)
{
  *hmac_state = (sha_hmac_state_t) { };
  data_t blk_data = { .buf = hmac_state->blk, .len = sizeof hmac_state->blk };

  if(password->len > sizeof hmac_state->blk) {
    sha_sum(hmac_state->blk, password);
  }
  else {
    MEM_COPY(hmac_state->blk, password->buf, password->len);
  }

  MEM_XOR_CONST(hmac_state->blk, 0x36, sizeof hmac_state->blk);

  sha_t __attribute__ ((aligned(16))) sha;

  sha_init(&sha);
  sha_process_data(&sha, &blk_data);

  hmac_state->state1 = sha.state;

  MEM_XOR_CONST(hmac_state->blk, 0x36 ^ 0x5c, sizeof hmac_state->blk);

  sha_init(&sha);
  sha_process_data(&sha, &blk_data);

  hmac_state->state2 = sha.state;

  blk_data.len = SHA_HASH_SIZE;

  sha_process_data(&sha, &blk_data);
  sha_finish(&sha);

  MEM_COPY(hmac_state->blk, sha.last.buf, sizeof hmac_state->blk);
}

void sha_hmac_pbkdf2_step(sha_hmac_state_t *hmac_state)
{
  sha_t __attribute__ ((aligned(16))) sha;

  sha.state = hmac_state->state1;

  sha_process_block(&sha, hmac_state->blk);

  sha_set_sum(&sha, hmac_state->blk);

  sha.state = hmac_state->state2;

  sha_process_block(&sha, hmac_state->blk);

  sha_set_sum(&sha, hmac_state->blk);
}

void sha_hmac(uint8_t sum[SHA_HASH_SIZE], data_t *data, data_t *password)
{
  uint8_t __attribute__((aligned(16))) blk[SHA_BLOCK_SIZE] = { };
  data_t blk_data = { .buf = blk, .len = sizeof blk };

  if(password->len > sizeof blk) {
    sha_sum(blk, password);
  }
  else {
    MEM_COPY(blk, password->buf, password->len);
  }

  MEM_XOR_CONST(blk, 0x36, sizeof blk);

  uint8_t __attribute__((aligned(16))) sum1[SHA_HASH_SIZE];

  sha_sum2(sum1, &blk_data, data);

  MEM_XOR_CONST(blk, 0x36 ^ 0x5c, sizeof blk);

  sha_sum2(sum, &blk_data, &(data_t) { .buf = sum1, .len = sizeof sum1 });
}

void sha_sum(uint8_t sum[SHA_HASH_SIZE], data_t *data)
{
  sha_t __attribute__((aligned(16))) sha;

  sha_init(&sha);
  sha_process_data(&sha, data);
  sha_finish(&sha);
  sha_set_sum(&sha, sum);
}

void sha_sum2(uint8_t sum[SHA_HASH_SIZE], data_t *data1, data_t *data2)
{
  sha_t __attribute__((aligned(16))) sha;

  sha_init(&sha);
  sha_process_data(&sha, data1);
  sha_process_data(&sha, data2);
  sha_finish(&sha);
  sha_set_sum(&sha, sum);
}

void __attribute__((noinline)) sha_init(sha_t *sha)
{
  sha->state = (sha_state_t) { .data = SHA_INITIAL_STATE };

  sha->len = 0;
  sha->last.len = 0;

  if(sha_func == f_default) {
    sha_func = cpu_has_sha() ? f_fast : f_normal;
  }
}

void __attribute__((noinline)) sha_finish(sha_t *sha)
{
  unsigned len = sha->last.len;

  sha->len += len;

  // add '1' bit
  sha->last.buf[len++] = 0x80;

  // len is <= SHA_BLOCK_SIZE

  if(len > SHA_BLOCK_SIZE - SHA_LEN_SIZE) {
    for(unsigned u = len; u < SHA_BLOCK_SIZE; u++) { sha->last.buf[u] = 0; }
    sha_process_block(sha, sha->last.buf);
    len = 0;
  }

  for(unsigned u = len; u < SHA_BLOCK_SIZE - SHA_LEN_SIZE; u++) { sha->last.buf[u] = 0; }

  // add length in bits
  put_uint64_be(&sha->last.buf[SHA_BLOCK_SIZE - SHA_LEN_SIZE], sha->len << 3);

  sha_process_block(sha, sha->last.buf);
}

void __attribute__((noinline)) sha_set_sum(sha_t *sha, uint8_t sum[SHA_HASH_SIZE])
{
  for(unsigned u = 0; u < sizeof sha->state.data / sizeof *sha->state.data ; u++) {
    put_uint32_be(&sum[sizeof (uint32_t) * u], sha->state.data[u]);
  }
}

/*
 * FIXME: does not handle data not in SHA_BLOCK_SIZE chunks, except in the last call
 */
void __attribute__((noinline)) sha_process_data(sha_t *sha, data_t *data)
{
  unsigned len = data->len;
  unsigned pos = 0;

  while(len >= SHA_BLOCK_SIZE) {
    sha_process_block(sha, data->buf + pos);
    sha->len += SHA_BLOCK_SIZE;
    pos += SHA_BLOCK_SIZE;
    len -= SHA_BLOCK_SIZE;
  }

  if(len) {
    uint8_t *src = &data->buf[pos];
    MEM_COPY(sha->last.buf, src, len);
    sha->last.len = len;
  }
}

void sha_process_block(sha_t *sha, uint8_t *buffer)
{
  switch(sha_func) {
    case f_default:
    case f_normal:
    case f_slow:
      sha_process_block_slow(sha, buffer);
      break;
#if (defined(__i386__) || defined (__x86_64__))
    case f_fast:
      sha_process_block_fast(sha, buffer);
      break;
#else
    default:
      sha_process_block_slow(sha, buffer);
#endif
  }
}

#if (defined(__i386__) || defined (__x86_64__))
void sha_process_block_fast(sha_t *sha, uint8_t *buffer)
{
  static const uint32_t __attribute__ ((aligned (16))) sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  };

  static const uint32_t __attribute__ ((aligned (16))) shuffle_be[4] = {
    0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f
  };

  // necessary for asm
  void *tmp;

  // code is generated; taken from sha256_inline.S
  asm volatile (
    "lea %4, %0\n"
    "movdqu %3,%%xmm5\n"

    "pshufd $0x1b,(%1),%%xmm6\n"
    "pshufd $0xb1,0x10(%1),%%xmm7\n"
    "movdqa %%xmm6,%%xmm0\n"
    "pblendw $0xf,%%xmm7,%%xmm6\n"
    "pblendw $0xf0,%%xmm7,%%xmm0\n"
    "pshufd $0x4e,%%xmm0,%%xmm7\n"
    "movdqu (%2),%%xmm0\n"
    "pshufb %%xmm5,%%xmm0\n"
    "movdqa %%xmm0,%%xmm1\n"
    "paddd  (%0),%%xmm0\n"
    "sha256rnds2 %%xmm0,%%xmm6,%%xmm7\n"
    "pshufd $0xe,%%xmm0,%%xmm0\n"
    "sha256rnds2 %%xmm0,%%xmm7,%%xmm6\n"
    "movdqu 0x10(%2),%%xmm0\n"
    "pshufb %%xmm5,%%xmm0\n"
    "movdqa %%xmm0,%%xmm2\n"
    "paddd  0x10(%0),%%xmm0\n"
    "sha256rnds2 %%xmm0,%%xmm6,%%xmm7\n"
    "pshufd $0xe,%%xmm0,%%xmm0\n"
    "sha256rnds2 %%xmm0,%%xmm7,%%xmm6\n"
    "sha256msg1 %%xmm2,%%xmm1\n"
    "movdqu 0x20(%2),%%xmm0\n"
    "pshufb %%xmm5,%%xmm0\n"
    "movdqa %%xmm0,%%xmm3\n"
    "paddd  0x20(%0),%%xmm0\n"
    "sha256rnds2 %%xmm0,%%xmm6,%%xmm7\n"
    "pshufd $0xe,%%xmm0,%%xmm0\n"
    "sha256rnds2 %%xmm0,%%xmm7,%%xmm6\n"
    "sha256msg1 %%xmm3,%%xmm2\n"
    "movdqu 0x30(%2),%%xmm0\n"
    "pshufb %%xmm5,%%xmm0\n"
    "movdqa %%xmm0,%%xmm4\n"
    "paddd  0x30(%0),%%xmm0\n"
    "sha256rnds2 %%xmm0,%%xmm6,%%xmm7\n"
    "movdqa %%xmm4,%%xmm5\n"
    "palignr $0x4,%%xmm3,%%xmm5\n"
    "paddd  %%xmm5,%%xmm1\n"
    "sha256msg2 %%xmm4,%%xmm1\n"
    "pshufd $0xe,%%xmm0,%%xmm0\n"
    "sha256rnds2 %%xmm0,%%xmm7,%%xmm6\n"
    "sha256msg1 %%xmm4,%%xmm3\n"
    "movdqa %%xmm1,%%xmm0\n"
    "paddd  0x40(%0),%%xmm0\n"
    "sha256rnds2 %%xmm0,%%xmm6,%%xmm7\n"
    "movdqa %%xmm1,%%xmm5\n"
    "palignr $0x4,%%xmm4,%%xmm5\n"
    "paddd  %%xmm5,%%xmm2\n"
    "sha256msg2 %%xmm1,%%xmm2\n"
    "pshufd $0xe,%%xmm0,%%xmm0\n"
    "sha256rnds2 %%xmm0,%%xmm7,%%xmm6\n"
    "sha256msg1 %%xmm1,%%xmm4\n"
    "movdqa %%xmm2,%%xmm0\n"
    "paddd  0x50(%0),%%xmm0\n"
    "sha256rnds2 %%xmm0,%%xmm6,%%xmm7\n"
    "movdqa %%xmm2,%%xmm5\n"
    "palignr $0x4,%%xmm1,%%xmm5\n"
    "paddd  %%xmm5,%%xmm3\n"
    "sha256msg2 %%xmm2,%%xmm3\n"
    "pshufd $0xe,%%xmm0,%%xmm0\n"
    "sha256rnds2 %%xmm0,%%xmm7,%%xmm6\n"
    "sha256msg1 %%xmm2,%%xmm1\n"
    "movdqa %%xmm3,%%xmm0\n"
    "paddd  0x60(%0),%%xmm0\n"
    "sha256rnds2 %%xmm0,%%xmm6,%%xmm7\n"
    "movdqa %%xmm3,%%xmm5\n"
    "palignr $0x4,%%xmm2,%%xmm5\n"
    "paddd  %%xmm5,%%xmm4\n"
    "sha256msg2 %%xmm3,%%xmm4\n"
    "pshufd $0xe,%%xmm0,%%xmm0\n"
    "sha256rnds2 %%xmm0,%%xmm7,%%xmm6\n"
    "sha256msg1 %%xmm3,%%xmm2\n"
    "movdqa %%xmm4,%%xmm0\n"
    "paddd  0x70(%0),%%xmm0\n"
    "sha256rnds2 %%xmm0,%%xmm6,%%xmm7\n"
    "movdqa %%xmm4,%%xmm5\n"
    "palignr $0x4,%%xmm3,%%xmm5\n"
    "paddd  %%xmm5,%%xmm1\n"
    "sha256msg2 %%xmm4,%%xmm1\n"
    "pshufd $0xe,%%xmm0,%%xmm0\n"
    "sha256rnds2 %%xmm0,%%xmm7,%%xmm6\n"
    "sha256msg1 %%xmm4,%%xmm3\n"
    "movdqa %%xmm1,%%xmm0\n"
    "paddd  0x80(%0),%%xmm0\n"
    "sha256rnds2 %%xmm0,%%xmm6,%%xmm7\n"
    "movdqa %%xmm1,%%xmm5\n"
    "palignr $0x4,%%xmm4,%%xmm5\n"
    "paddd  %%xmm5,%%xmm2\n"
    "sha256msg2 %%xmm1,%%xmm2\n"
    "pshufd $0xe,%%xmm0,%%xmm0\n"
    "sha256rnds2 %%xmm0,%%xmm7,%%xmm6\n"
    "sha256msg1 %%xmm1,%%xmm4\n"
    "movdqa %%xmm2,%%xmm0\n"
    "paddd  0x90(%0),%%xmm0\n"
    "sha256rnds2 %%xmm0,%%xmm6,%%xmm7\n"
    "movdqa %%xmm2,%%xmm5\n"
    "palignr $0x4,%%xmm1,%%xmm5\n"
    "paddd  %%xmm5,%%xmm3\n"
    "sha256msg2 %%xmm2,%%xmm3\n"
    "pshufd $0xe,%%xmm0,%%xmm0\n"
    "sha256rnds2 %%xmm0,%%xmm7,%%xmm6\n"
    "sha256msg1 %%xmm2,%%xmm1\n"
    "movdqa %%xmm3,%%xmm0\n"
    "paddd  0xa0(%0),%%xmm0\n"
    "sha256rnds2 %%xmm0,%%xmm6,%%xmm7\n"
    "movdqa %%xmm3,%%xmm5\n"
    "palignr $0x4,%%xmm2,%%xmm5\n"
    "paddd  %%xmm5,%%xmm4\n"
    "sha256msg2 %%xmm3,%%xmm4\n"
    "pshufd $0xe,%%xmm0,%%xmm0\n"
    "sha256rnds2 %%xmm0,%%xmm7,%%xmm6\n"
    "sha256msg1 %%xmm3,%%xmm2\n"
    "movdqa %%xmm4,%%xmm0\n"
    "paddd  0xb0(%0),%%xmm0\n"
    "sha256rnds2 %%xmm0,%%xmm6,%%xmm7\n"
    "movdqa %%xmm4,%%xmm5\n"
    "palignr $0x4,%%xmm3,%%xmm5\n"
    "paddd  %%xmm5,%%xmm1\n"
    "sha256msg2 %%xmm4,%%xmm1\n"
    "pshufd $0xe,%%xmm0,%%xmm0\n"
    "sha256rnds2 %%xmm0,%%xmm7,%%xmm6\n"
    "sha256msg1 %%xmm4,%%xmm3\n"
    "movdqa %%xmm1,%%xmm0\n"
    "paddd  0xc0(%0),%%xmm0\n"
    "sha256rnds2 %%xmm0,%%xmm6,%%xmm7\n"
    "movdqa %%xmm1,%%xmm5\n"
    "palignr $0x4,%%xmm4,%%xmm5\n"
    "paddd  %%xmm5,%%xmm2\n"
    "sha256msg2 %%xmm1,%%xmm2\n"
    "pshufd $0xe,%%xmm0,%%xmm0\n"
    "sha256rnds2 %%xmm0,%%xmm7,%%xmm6\n"
    "sha256msg1 %%xmm1,%%xmm4\n"
    "movdqa %%xmm2,%%xmm0\n"
    "paddd  0xd0(%0),%%xmm0\n"
    "sha256rnds2 %%xmm0,%%xmm6,%%xmm7\n"
    "movdqa %%xmm2,%%xmm5\n"
    "palignr $0x4,%%xmm1,%%xmm5\n"
    "paddd  %%xmm5,%%xmm3\n"
    "sha256msg2 %%xmm2,%%xmm3\n"
    "pshufd $0xe,%%xmm0,%%xmm0\n"
    "sha256rnds2 %%xmm0,%%xmm7,%%xmm6\n"
    "movdqa %%xmm3,%%xmm0\n"
    "paddd  0xe0(%0),%%xmm0\n"
    "sha256rnds2 %%xmm0,%%xmm6,%%xmm7\n"
    "movdqa %%xmm3,%%xmm5\n"
    "palignr $0x4,%%xmm2,%%xmm5\n"
    "paddd  %%xmm5,%%xmm4\n"
    "sha256msg2 %%xmm3,%%xmm4\n"
    "pshufd $0xe,%%xmm0,%%xmm0\n"
    "sha256rnds2 %%xmm0,%%xmm7,%%xmm6\n"
    "movdqa %%xmm4,%%xmm0\n"
    "paddd  0xf0(%0),%%xmm0\n"
    "sha256rnds2 %%xmm0,%%xmm6,%%xmm7\n"
    "pshufd $0xe,%%xmm0,%%xmm0\n"
    "sha256rnds2 %%xmm0,%%xmm7,%%xmm6\n"
    "pshufd $0xb1,%%xmm7,%%xmm0\n"
    "pshufd $0x1b,%%xmm6,%%xmm6\n"
    "movdqa %%xmm0,%%xmm7\n"
    "pblendw $0xf0,%%xmm6,%%xmm7\n"
    "pblendw $0xf0,%%xmm0,%%xmm6\n"
    "pshufd $0x4e,%%xmm7,%%xmm7\n"
    "movdqu (%1),%%xmm0\n"
    "paddd  %%xmm6,%%xmm0\n"
    "movdqu %%xmm0,(%1)\n"
    "movdqu 0x10(%1),%%xmm0\n"
    "paddd  %%xmm7,%%xmm0\n"
    "movdqu %%xmm0,0x10(%1)\n"

    : "=&r" (tmp)
    : "r" (sha), "r" (buffer), "m" (shuffle_be), "m" (sha256_k)
    : "memory"
  );
}
#endif

static const uint32_t sha256_round_constants[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define K(I) sha256_round_constants[I]

#define F2(A, B, C) ((A & B) | (C & (A | B)))
#define F1(E, F, G) (G ^ (E & (F ^ G)))

#define ROTL(x, n) (((x) << (n)) + ((x) >> (32 - (n))))

#define SS0(x) (ROTL(x, 30) ^ ROTL(x, 19) ^ ROTL(x, 10))
#define SS1(x) (ROTL(x, 26) ^ ROTL(x, 21) ^ ROTL(x,  7))
#define  S0(x) (ROTL(x, 25) ^ ROTL(x, 14) ^ (x >>  3))
#define  S1(x) (ROTL(x, 15) ^ ROTL(x, 13) ^ (x >> 10))

void sha_process_block_slow(sha_t *sha, uint8_t *buffer)
{
  uint32_t x[16];
  uint32_t a = sha->state.data[0];
  uint32_t b = sha->state.data[1];
  uint32_t c = sha->state.data[2];
  uint32_t d = sha->state.data[3];
  uint32_t e = sha->state.data[4];
  uint32_t f = sha->state.data[5];
  uint32_t g = sha->state.data[6];
  uint32_t h = sha->state.data[7];

  for(unsigned u = 0; u < 16; u++) {
    x[u] = get_uint32_be(buffer);
    buffer += 4;
  }

  for(unsigned t = 0; t < 64; t++) {
    uint32_t w;

    if(t < 16) {
      w = x[t];
    }
    else {
      w = S1(x[(t - 2) & 15]) + x[(t - 7) & 15] + S0(x[(t - 15) & 15]) + x[t & 15];
      x[t & 15] = w;
    }

    uint32_t t1 = h + SS1(e) + F1(e, f, g) + K(t) + w;
    uint32_t t2 = SS0(a) + F2(a, b, c);

    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  sha->state.data[0] += a;
  sha->state.data[1] += b;
  sha->state.data[2] += c;
  sha->state.data[3] += d;
  sha->state.data[4] += e;
  sha->state.data[5] += f;
  sha->state.data[6] += g;
  sha->state.data[7] += h;
}
