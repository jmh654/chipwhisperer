/*
    This file is part of the ChipWhisperer Example Targets
    Copyright (C) 2016-2017 NewAE Technology Inc.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "hal.h"
#include "simpleserial.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include <avr/pgmspace.h> //für memcpy_p

//was macht da?
#if (HAL_TYPE == HAL_xmega) || (HAL_TYPE == HAL_avr) 

//#include "mbedtls/bignum.h"
//#include "mbedtls/rsa.h"

#include "mbedtls/rsa.h"
#include "mbedtls/sha256.h"
#include "mbedtls/oid.h"
uint8_t sig_chunk_1(uint8_t *pt, uint8_t len);
uint8_t sig_chunk_2(uint8_t *pt, uint8_t len);
//nötig?
#define mbedtls_calloc calloc
#define mbedtls_free free


/**********************************************************************************************
   RSA KEY #2 (2Bytes)
**********************************************************************************************/
/* Primzahl 1 p (2 Bytes): 62549 */
const uint8_t p2[] PROGMEM = {
0xf4, 0x55
};

/* Primzahl 2 q (2 Bytes): 61543*/
const uint8_t q2[] PROGMEM = {
0xf0, 0x67
};

/* Exponent 1 dp: 11321*/
const uint8_t dp2[] PROGMEM = {
0x2c, 0x39
};

/* Exponent 2 dq:647 */
const uint8_t dq2[] PROGMEM = {
0x02, 0x87
};

/* qinv:34632 */
const uint8_t qinv2[] PROGMEM = {
0x87, 0x48
};

/* modulus n: 3849453107 */
const uint8_t modulus2[] PROGMEM = {
0xe5, 0x71, 0xfe, 0x33
};

/* pub exponent e: 65537 */
const uint8_t pub_exponent2[] PROGMEM = {
0x01, 0x00, 0x01
};

/* priv exponent d: 1128127049*/
const uint8_t priv_exponent2[] PROGMEM = {
0x43, 0x3d, 0xda, 0x49
};


// MWC random number implementation - https://en.wikipedia.org/wiki/Multiply-with-carry_pseudorandom_number_generator
//für add padding 
#define PHI 0x9e3779b9

static uint32_t Q[1024], c = 362436;

void init_rand(uint32_t x)
{
    int i;

    Q[0] = x;
    Q[1] = x + PHI;
    Q[2] = x + PHI + PHI;

    for (i = 3; i < 1024; i++)
            Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
}

uint32_t rand_cmwc(void)
{
    uint64_t t, a = 18782LL;
    static uint32_t i = 1023;
    uint32_t x, r = 0xfffffffe;
    i = (i + 1) & 1023;
    t = a * Q[i] + c;
    c = (t >> 32);
    x = t + c;
    if (x < c) {
            x++;
            c++;
    }
    return (Q[i] = r - x);
}

static int myrand( void *rng_state, unsigned char *output, size_t len )
{
     size_t i;

     if( rng_state != NULL )
          rng_state  = NULL;

     for( i = 0; i < len; ++i )
          output[i] = rand_cmwc();

     return( 0 );
}




/*
uint8_t keys_allocated = 0;
rsa_publickey_t pub_key;
rsa_privatekey_t priv_key;

#define MSG       message_x
#define SEED      seed_x
#define ENCRYPTED encrypted_x
#define MODULUS modulus
#define PUB_EXPONENT pub_exponent
#define PRIV_EXPONENT priv_exponent
#define P p
#define Q q
#define DP dp
#define DQ dq
#define QINV qinv
*/

/*
 * Example RSA-1024 keypair, for test purposes
 */
#define RSA_KEY_LEN 2

#define RSA_N   "e571fe33" 
#define RSA_E   "10001"
#define RSA_D   "433dda49" 
#define RSA_P   "f455"        
#define RSA_Q   "f067" 
#define RSA_DP  "2c39" 
#define RSA_DQ  "0287" 
#define RSA_QP  "8748" 

//was? für add padding
#define PT_LEN  24 
//was? für add padding
#define RSA_PT  "\xAA\xBB\xCC\x03\x02\x01\x00\xFF\xFF\xFF\xFF\xFF" \
                "\x11\x22\x33\x0A\x0B\x0C\xCC\xDD\xDD\xDD\xDD\xDD"

const char MESSAGE[] =  "Hello World!";

mbedtls_rsa_context rsa_ctx;

//für add padding 
unsigned char rsa_plaintext[PT_LEN];
unsigned char rsa_decrypted[PT_LEN];
unsigned char rsa_ciphertext[RSA_KEY_LEN];

//debugging
uint8_t debug_buffer[32];
size_t debug_buffer_len; 
//mbedtls_mpi_write_string( X, 10, debug_buffer, sizeof( debug_buffer ), &debug_buffer_len);
//simpleserial_put('r', (uint8_t) debug_buffer_len, debug_buffer );

/*
 * Do an RSA private key operation
 */
static int simpleserial_mbedtls_rsa_private( mbedtls_rsa_context *ctx,
                 int (*f_rng)(void *, unsigned char *, size_t),
                 void *p_rng,
                 const unsigned char *input,
                 unsigned char *output )
{
    int ret;
    size_t olen;
    mbedtls_mpi T, T1, T2;
    mbedtls_mpi P1, Q1, R;
    mbedtls_mpi *DP = &ctx->DP;
    mbedtls_mpi *DQ = &ctx->DQ;

    /* Make sure we have private key info, prevent possible misuse */
    if( ctx->P.p == NULL || ctx->Q.p == NULL || ctx->D.p == NULL )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    mbedtls_mpi_init( &T ); mbedtls_mpi_init( &T1 ); mbedtls_mpi_init( &T2 );
    mbedtls_mpi_init( &P1 ); mbedtls_mpi_init( &Q1 ); mbedtls_mpi_init( &R );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &T, input, ctx->len ) );
    if( mbedtls_mpi_cmp_mpi( &T, &ctx->N ) >= 0 )
    {
        ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        goto cleanup;
    }

    /*
     * Faster decryption using the CRT
     *
     * T1 = input ^ dP mod P
     * T2 = input ^ dQ mod Q
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod( &T1, &T, DP, &ctx->P, &ctx->RP ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod( &T2, &T, DQ, &ctx->Q, &ctx->RQ ) );

    /*
     * T = (T1 - T2) * (Q^-1 mod P) mod P
     */
    trigger_high();
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &T, &T1, &T2 ) );
    trigger_low();
    //trigger_high();


    //debug
    mbedtls_mpi_write_string( &T, 10, debug_buffer, sizeof( debug_buffer ), &debug_buffer_len);
    simpleserial_put('r', (uint8_t) debug_buffer_len, debug_buffer );

    
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &T1, &T, &ctx->QP ) );
    //trigger_low();
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &T, &T1, &ctx->P ) );
    
    mbedtls_mpi_write_string( &T, 10, debug_buffer, sizeof( debug_buffer ), &debug_buffer_len);
    simpleserial_put('r', (uint8_t) debug_buffer_len, debug_buffer );
    

    /*
     * T = T2 + T * Q
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &T1, &T, &ctx->Q ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &T, &T2, &T1 ) );
    
    mbedtls_mpi_write_string( &T, 10, debug_buffer, sizeof( debug_buffer ), &debug_buffer_len);
    simpleserial_put('r', (uint8_t) debug_buffer_len, debug_buffer );

    olen = ctx->len;
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &T, output, olen ) );

cleanup:
    mbedtls_mpi_free( &T ); mbedtls_mpi_free( &T1 ); mbedtls_mpi_free( &T2 );
    mbedtls_mpi_free( &P1 ); mbedtls_mpi_free( &Q1 ); mbedtls_mpi_free( &R );

    if( ret != 0 )
        return( MBEDTLS_ERR_RSA_PRIVATE_FAILED + ret );

    return( 0 );
}


void load_key_from_flash(mbedtls_mpi *X, PGM_VOID_P os) {
    uint16_t length = sizeof(os);
    
    //temp buffer to store key from flash
    uint8_t key_buf[length]; //Anzahl der Bytes : 4 oder lenght

    //copy data from flash to buffer
    //dest, src, len
    memcpy_P(key_buf, os, length);

    // convert into mbedtls datatype
    // result number:&rsa_ctx.N; buffer(bigend): RSA_N; bufferlen (buffergröße in bytes?)
    mbedtls_mpi_read_binary( X, key_buf, length);
    
}


void rsa_init(void)
{
    
//!!!!!!!
    init_rand(0);

    //initialisiert ctx 
    mbedtls_rsa_init( &rsa_ctx, MBEDTLS_RSA_PKCS_V15, 0 ); // ctx->padding = MBEDTLS_RSA_PKCS_V15 ersetzten?  
    
    //warum? warnung bei comipilieren mit ss_ver_2_1
    simpleserial_addcmd('1', 0, sig_chunk_1);
    simpleserial_addcmd('2', 0, sig_chunk_2);
    
    //load key variables into rsa context 
    rsa_ctx.len = RSA_KEY_LEN;

    //load key data into ctx
    
    //from progmem
    load_key_from_flash( &rsa_ctx.N, modulus2);
    
    //from string; dest*, radix, char*
    //mbedtls_mpi_read_string( &rsa_ctx.N , 16, RSA_N  ) ;
    mbedtls_mpi_read_string( &rsa_ctx.E , 16, RSA_E  ) ;
    mbedtls_mpi_read_string( &rsa_ctx.D , 16, RSA_D  ) ;
    mbedtls_mpi_read_string( &rsa_ctx.P , 16, RSA_P  ) ;
    mbedtls_mpi_read_string( &rsa_ctx.Q , 16, RSA_Q  ) ;
    mbedtls_mpi_read_string( &rsa_ctx.DP, 16, RSA_DP ) ;
    mbedtls_mpi_read_string( &rsa_ctx.DQ, 16, RSA_DQ ) ;
    mbedtls_mpi_read_string( &rsa_ctx.QP, 16, RSA_QP ) ;

    //mbedtls_mpi_write_string( &rsa_ctx.P, 10, debug_buffer, sizeof( debug_buffer ), &debug_buffer_len);
    //simpleserial_put('r', (uint8_t) debug_buffer_len, debug_buffer );
    
    //mbedtls_mpi_write_string( &rsa_ctx.N, 10, debug_buffer, sizeof( debug_buffer ), &debug_buffer_len);
    //simpleserial_put('r', (uint8_t) debug_buffer_len, debug_buffer );

    

    //Make valid data first, otherwise system barfs 
    //kein andrer output
    //kopiert rsa_pt an rsa_plaintext nötig für mbedtls_rsa_pkcs1_encrypt
    //memcpy( rsa_plaintext, RSA_PT, PT_LEN );
    
    //encrypts depending on padding either pkcs1_v15 or oaep; adds message padding, input plaintest, output ciphertest; nötig ??
    //mbedtls_rsa_pkcs1_encrypt( &rsa_ctx, myrand, NULL, MBEDTLS_RSA_PUBLIC, PT_LEN, rsa_plaintext, rsa_ciphertext );
} 



uint8_t buf[128];
uint8_t hash[32];
    
#if SS_VER == SS_VER_2_1
uint8_t real_dec(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *pt) //input wird ignoriert ? 
#else
uint8_t real_dec(uint8_t *pt, uint8_t len)
#endif
{
    int ret = 0;

    //first need to hash our message
    //nötig? MESSAGE aonders?
    //memset(buf, 0, 128);  //copyes the 128 mal 0 an den pointer buf
    //mbedtls_sha256(MESSAGE, 12, hash, 0); //hashed message und speichert an hash? 

    //ret = simpleserial_mbedtls_rsa_rsassa_pkcs1_v15_sign(&rsa_ctx, NULL, NULL, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256, 32, hash, buf);
    // const unsigned char *hash, unsigned char *sig

    //buf bzw hash verwenden -> output = buf, input = hash? größe anpassen?
    //const unsigned char *input,unsigned char *output 
    //ret = simpleserial_mbedtls_rsa_private( &rsa_ctx, NULL, NULL, hash, buf );
    


    //ODER: get data from buffer pt
    //pt in const unsigned char *input
    uint8_t temp[4];
    memcpy(temp, pt, len);

    //debug -> msg in temp
    simpleserial_put('r', 4, temp);
    
    //input, output
    ret = simpleserial_mbedtls_rsa_private( &rsa_ctx, NULL, NULL, temp, buf );
    
    //debug -> so net
    //temp[2] = (uint8_t)((ret >> 8) & 0xFF);
    //temp[3] = (uint8_t)(ret & 0xFF);         // LSB
    //simpleserial_put('r', 4, temp);

    uint8_t temp2[8];
    //num, buff, radix
    itoa(ret, temp2, 10);
    simpleserial_put('r', 4, temp2);

    simpleserial_put('r', 4, buf);
    
    //trigger_low();

    //send back first 48 bytes
#if SS_VER == SS_VER_2_1
    simpleserial_put('r', 128, buf);
#else
    simpleserial_put('r', 48, buf);
#endif
    return ret;
}

uint8_t sig_chunk_1(uint8_t *pt, uint8_t len)
{
     simpleserial_put('r', 48, buf + 48);
     return 0x00;
}

uint8_t sig_chunk_2(uint8_t *pt, uint8_t len)
{
     simpleserial_put('r', 128 - 48 * 2, buf + 48*2);
     return 0x00;
}

#endif
