#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <nettle/yarrow.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

#define YARROW_RESEED_ITERATIONS 1500

static inline void WRITE_UINT32(uint8_t *p, uint32_t i) {
    p[0] = (i >> 24) & 0xff;
    p[1] = (i >> 16) & 0xff;
    p[2] = (i >> 8) & 0xff;
    p[3] = i & 0xff;
}


//TODO: fast version still crashing
#if USE_OPENSSL

#include <openssl/sha.h>
#include <openssl/aes.h>


/* Yarrow-256, based on SHA-256 and AES-256 */
struct yarrow256_fast_ctx
{
  /* Indexed by yarrow_pool_id */
   SHA256_CTX pools[2];

  int seeded;

  /* The current key and counter block */
   AES_KEY key;
  uint8_t counter[AES_BLOCK_SIZE];

  /* The entropy sources */
  unsigned nsources;
  struct yarrow_source *sources;
};




void
yarrow256_fast_init(struct yarrow256_fast_ctx *ctx,
	       unsigned n,
	       struct yarrow_source *s)
{
  unsigned i;
  memset(ctx, 0, sizeof(*ctx));

  SHA256_Init(&ctx->pools[0]);
  SHA256_Init(&ctx->pools[1]);
  
  ctx->seeded = 0;

  /* Not strictly necessary, but it makes it easier to see if the
   * values are sane. */
  memset(ctx->counter, 0, sizeof(ctx->counter));
  
  ctx->nsources = n;
  ctx->sources = s;

  for (i = 0; i<n; i++)
    {
      ctx->sources[i].estimate[YARROW_FAST] = 0;
      ctx->sources[i].estimate[YARROW_SLOW] = 0;
      ctx->sources[i].next = YARROW_FAST;
    }
    //initialize AES key

}

void yarrow256_fast_seed(struct yarrow256_fast_ctx *ctx, size_t length, const uint8_t *seed_file)
{
    uint8_t digest[SHA256_DIGEST_SIZE];
    uint8_t v0[SHA256_DIGEST_SIZE];
    uint8_t count[4];
    uint32_t i;

    assert(length > 0);

    /* Update the FAST pool with seed data */
    SHA256_Update(&ctx->pools[YARROW_FAST], seed_file, length);
    SHA256_Final(digest, &ctx->pools[YARROW_FAST]);

    memcpy(v0, digest, SHA256_DIGEST_SIZE);

    /* Reseed iterations: hash (digest || v0 || count) repeatedly */
    for (i = 1; i < YARROW_RESEED_ITERATIONS; i++) {
        SHA256_CTX hash;
        SHA256_Init(&hash);
        SHA256_Update(&hash, digest, SHA256_DIGEST_SIZE);
        SHA256_Update(&hash, v0, SHA256_DIGEST_SIZE);
        WRITE_UINT32(count, i);
        SHA256_Update(&hash, count, sizeof(count));
        SHA256_Final(digest, &hash);
    }

    /* Set the 256-bit AES key using the final digest */
    AES_set_encrypt_key(digest, 256, &ctx->key);
    ctx->seeded = 1;

    /* Derive a new counter value by encrypting a zero block */
    memset(ctx->counter, 0, sizeof(ctx->counter));
    AES_encrypt(ctx->counter, ctx->counter, &ctx->key);

    /* Reset the entropy estimates for all sources in the FAST pool */
    for (i = 0; i < ctx->nsources; i++) {
        ctx->sources[i].estimate[YARROW_FAST] = 0;
    }
}

void fast_gen_key()
{
    time_t t = time(0);

    struct yarrow256_fast_ctx ctx;
    yarrow256_fast_init(&ctx, 0, NULL);
    char seed[32];
    snprintf(seed, sizeof(seed), "%lld", t);

    yarrow256_fast_seed(&ctx, strlen(seed), seed);
    //char buffer[32];
    //yarrow256_random(&ctx, 32, buffer);   
    // for (int i =0; i < sizeof(buffer); i++) {
    //     printf("%02x", (unsigned char )(buffer[i]));
    // }
    // printf("\n");
}

#endif

static void
yarrow_iterate(uint8_t *digest)
{
  uint8_t v0[SHA256_DIGEST_SIZE];
  unsigned i;
  
  memcpy(v0, digest, SHA256_DIGEST_SIZE);
  
  /* When hashed inside the loop, i should run from 1 to
   * YARROW_RESEED_ITERATIONS */
  for (i = 0; ++i < YARROW_RESEED_ITERATIONS; )
    {
      uint8_t count[4];
      struct sha256_ctx hash;
  
      sha256_init(&hash);

      /* Hash v_i | v_0 | i */
      WRITE_UINT32(count, i);
      sha256_update(&hash, SHA256_DIGEST_SIZE, digest);
      sha256_update(&hash, sizeof(v0), v0);
      sha256_update(&hash, sizeof(count), count);

      sha256_digest(&hash, SHA256_DIGEST_SIZE, digest);
    }
}

/* FIXME: Generalize so that it generates a few more blocks at a
 * time. */
static void
yarrow_generate_block(struct yarrow256_ctx *ctx,
		      uint8_t *block)
{
  unsigned i;

  aes256_encrypt(&ctx->key, sizeof(ctx->counter), block, ctx->counter);

  /* Increment counter, treating it as a big-endian number. This is
   * machine independent, and follows appendix B of the NIST
   * specification of cipher modes of operation.
   *
   * We could keep a representation of the counter as 4 32-bit values,
   * and write entire words (in big-endian byteorder) into the counter
   * block, whenever they change. */
  for (i = sizeof(ctx->counter); i--; )
    {
      if (++ctx->counter[i])
	break;
    }
}

void
yarrow256_fast_reseed_debug(struct yarrow256_ctx *ctx)
{
  uint8_t digest[SHA256_DIGEST_SIZE];
  unsigned i;
  
#if YARROW_DEBUG
  fprintf(stderr, "yarrow256_fast_reseed\n");
#endif
  
  /* We feed two block of output using the current key into the pool
   * before emptying it. */
  if (ctx->seeded)
    {
      uint8_t blocks[AES_BLOCK_SIZE * 2];
      
      yarrow_generate_block(ctx, blocks);
      yarrow_generate_block(ctx, blocks + AES_BLOCK_SIZE);
      sha256_update(&ctx->pools[YARROW_FAST], sizeof(blocks), blocks);
    }
  
  sha256_digest(&ctx->pools[YARROW_FAST], sizeof(digest), digest);

  /* Iterate */
  yarrow_iterate(digest);

  //debug print the digest
    // for (int i = 0; i < sizeof(digest); i++) {
    //     printf("%02x", (unsigned char)(digest[i]));
    // }
    // printf("\n");

  aes256_set_encrypt_key(&ctx->key, digest);
  ctx->seeded = 1;

  /* Derive new counter value */
  memset(ctx->counter, 0, sizeof(ctx->counter));
  aes256_encrypt(&ctx->key, sizeof(ctx->counter), ctx->counter, ctx->counter);
  
  /* Reset estimates. */
  for (i = 0; i<ctx->nsources; i++)
    ctx->sources[i].estimate[YARROW_FAST] = 0;
}




void
yarrow256_seed_debug(struct yarrow256_ctx *ctx,
	       size_t length,
	       const uint8_t *seed_file)
{
  assert(length > 0);

  sha256_update(&ctx->pools[YARROW_FAST], length, seed_file);
  yarrow256_fast_reseed_debug(ctx);
}



void gen_key(uint64_t t)
{

    struct yarrow256_ctx ctx;
    yarrow256_init(&ctx, 0, NULL);
    char seed[32];
    snprintf(seed, sizeof(seed), "%lld", t);

    yarrow256_seed(&ctx, strlen(seed), seed);
    char buffer[32];
    yarrow256_random(&ctx, 32, buffer);   
    for (int i =0; i < sizeof(buffer); i++) {
        printf("%02x", (unsigned char )(buffer[i]));
    }
    printf("\n");
}


int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Usage: %s <logfile>\n", argv[0]);
        return 1;
    }
    //read log file
    FILE *fp = fopen(argv[1], "rb");
    if (fp == NULL) {
        printf("Error: Unable to open file %s\n", argv[1]);
        return 1;
    }
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *buffer = malloc(fsize + 1);
    if (buffer == NULL) {
        printf("Error: Unable to allocate memory\n");
        return 1;
    }
    fread(buffer, fsize, 1, fp);
    fclose(fp);
    uint64_t *t = (uint64_t *)buffer;
    for (int i = 0; i < fsize/sizeof(uint64_t); i++) {

        if (t[i] < 1700000000000000000) {
            break;
        }
        if (t[i] > 1800000000000000000) {
            break;
        }
        printf("t = %lld: ", t[i]);
        gen_key(t[i]);
    }



}