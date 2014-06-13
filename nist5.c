#include "cpuminer-config.h"
#include "miner.h"

#include <string.h>
#include <stdint.h>

#include "sha3/sph_blake.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"

inline void nist5_hash(void *output, const void *input)
{
    sph_blake512_context     ctx_blake;
    sph_groestl512_context   ctx_groestl;
    sph_skein512_context     ctx_skein;
    sph_jh512_context        ctx_jh;
    sph_keccak512_context    ctx_keccak;
    
    uint32_t hash[16];
    
    sph_blake512_init(&ctx_blake);
    sph_blake512 (&ctx_blake, input, 80);
    sph_blake512_close (&ctx_blake, hash);

    sph_groestl512_init(&ctx_groestl);
    sph_groestl512 (&ctx_groestl, hash, 64);
    sph_groestl512_close(&ctx_groestl, hash);

    sph_jh512_init(&ctx_jh);
    sph_jh512 (&ctx_jh, hash, 64);
    sph_jh512_close(&ctx_jh, hash);

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, hash, 64);
    sph_keccak512_close(&ctx_keccak, hash);
    
    sph_skein512_init(&ctx_skein);
    sph_skein512 (&ctx_skein, hash, 64);
    sph_skein512_close (&ctx_skein, hash);

    memcpy(output, hash, 32);
}

#define SCOND(x) ((hash64[7] & (x))==0)

#define _SCAN_LOOP(x) do { \
        pdata[19] = ++n; \
        be32enc(&endiandata[19], n); \
        nist5_hash(hash64, &endiandata); \
        if ((x) && \
            fulltest(hash64, ptarget)) { \
            *hashes_done = n - first_nonce + 1; \
            return true; \
        } \
    } while (n < max_nonce && !work_restart[thr_id].restart);

#define SCAN_LOOP(x) _SCAN_LOOP(SCOND(x))
#define SCAN_LOOP_NC() _SCAN_LOOP(1)
    
int scanhash_nist5(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
    uint32_t max_nonce, unsigned long *hashes_done)
{
    uint32_t n = pdata[19] - 1;
    const uint32_t first_nonce = pdata[19];
    const uint32_t Htarg = ptarget[7];

    uint32_t hash64[8] __attribute__((aligned(32)));
    uint32_t endiandata[32];

    int kk=0;
    for (; kk < 32; kk++)
    {
        be32enc(&endiandata[kk], ((uint32_t*)pdata)[kk]);
    };

    if (ptarget[7]==0) {
        SCAN_LOOP(0xFFFFFFFF)       
    } 
    else if (ptarget[7]<=0xF) 
    {
        SCAN_LOOP(0xFFFFFFF0)  
    } 
    else if (ptarget[7]<=0xFF) 
    {
        SCAN_LOOP(0xFFFFFF00)
    } 
    else if (ptarget[7]<=0xFFF) 
    {
        SCAN_LOOP(0xFFFFF000)
    } 
    else if (ptarget[7]<=0xFFFF) 
    {
        SCAN_LOOP(0xFFFF0000)       
    } 
    else 
    {
        SCAN_LOOP_NC()
    }

    *hashes_done = n - first_nonce + 1;
    pdata[19] = n;
    return 0;
}
