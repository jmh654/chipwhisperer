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

/**********************************************************************************************
   RSA KEY #4 (8Bytes)
**********************************************************************************************/
/*
// Primzahl 1 p (8 Bytes):14091828191315287507 
const uint8_t p4[] PROGMEM = {
0xc3, 0x90, 0x3b, 0x14, 0x0b, 0x2e, 0xdd, 0xd3
};

// Primzahl 2 q (8 Bytes): 6353019252147394247
const uint8_t q4[] PROGMEM = {
0x58, 0x2a, 0x75, 0x59, 0x9f, 0x76, 0x96, 0xc7
};

// Exponent 1 dp: 5927267588107438781 
const uint8_t dp4[] PROGMEM = {
0x52, 0x41, 0xe2, 0x77, 0xa5, 0xd4, 0x8a, 0xbd
};

// Exponent 2 dq:2516023234043145363 
const uint8_t dq4[] PROGMEM = {
0x22, 0xea, 0xb5, 0xcd, 0x07, 0xc5, 0x6c, 0x93
};

// qinv: 907488296688955759
const uint8_t qinv4[] PROGMEM = {
0x0c, 0x98, 0x0b, 0xcc, 0x39, 0xf8, 0x31, 0x6f

};

// modulus n:89525655797379415138998373505682772229 
const uint8_t modulus4[] PROGMEM = {
0x43, 0x5a, 0x03, 0x9d, 0xf7, 0x17, 0xd1, 0x60, 0x71, 0x35, 0x7b, 0xdd, 0x73, 0xaa, 0x11, 0x05
};

// pub exponent e: 65537 
const uint8_t pub_exponent4[] PROGMEM = {
0x01, 0x00, 0x01
};

// priv exponent d: 78459428511806828001727883835233122001
const uint8_t priv_exponent4[] PROGMEM = {
0x3b, 0x06, 0xbc, 0x7c, 0xc8, 0x7c, 0xdb, 0x45, 0xcd, 0xc8, 0x5c, 0x5a, 0x8f, 0xb5, 0xb6, 0xd1
};

*/


/*
 * Example RSA-1024 keypair, for test purposes
 */
#define RSA_KEY_LEN 4
//wenn 2, dann in simpleserial_mbedtls_rsa_private in MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &T, input, ctx->len ) ); probleme
//-> immer 2*bytes(p), also #bytes von N

/*
#define RSA_N   "E571FE33" 
#define RSA_E   "10001"
#define RSA_D   "433DDA49" 
#define RSA_P   "F455"        
#define RSA_Q   "F067" 
#define RSA_DP  "2C39" 
#define RSA_DQ  "0287" 
#define RSA_QP  "8748" 
*/

mbedtls_rsa_context rsa_ctx;

//debugging
uint8_t debug_buffer[64]; //32=8*4, 64=8*8 ->ausgabe 4535373100000000 statt45353731XXXXXXXX
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
    int ret = 0;
    size_t olen;
    mbedtls_mpi T, T1, T2;
    mbedtls_mpi P1, Q1, R;
    mbedtls_mpi *DP = &ctx->DP;
    mbedtls_mpi *DQ = &ctx->DQ;

    //debug
    uint8_t temp2[RSA_KEY_LEN];

    /* Make sure we have private key info, prevent possible misuse */
    if( ctx->P.p == NULL || ctx->Q.p == NULL || ctx->D.p == NULL )
        //debug,liefert warning: Timeout in OpenADC capture(), no trigger seen! Trigger forced, data is invalid. Status: 0b; 08
        //mbedtls_mpi_write_string( DP, 10, debug_buffer, sizeof( debug_buffer ), &debug_buffer_len);
        //simpleserial_put('r', (uint8_t) debug_buffer_len, debug_buffer );
    
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    mbedtls_mpi_init( &T ); mbedtls_mpi_init( &T1 ); mbedtls_mpi_init( &T2 );
    mbedtls_mpi_init( &P1 ); mbedtls_mpi_init( &Q1 ); mbedtls_mpi_init( &R );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &T, input, ctx->len ) );
    //debug 
    //simpleserial_put('r', sizeof(input)*2, input ); // für 0xa433059b -> rA433, mit *2: A433059B
    
    //mbedtls_mpi_write_string( &T, 16, debug_buffer, 64, &debug_buffer_len);
    //simpleserial_put('r', (uint8_t) debug_buffer_len, debug_buffer ); // für 0xa433059b -> r41 34 33 33 00 = A433 -> change rsa_key_len von 2 auf 4 -> r41 34 33 33 30 35 39 42 00 = A433059B -> passt
    
    if( mbedtls_mpi_cmp_mpi( &T, &ctx->N ) >= 0 )
    {
        ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        //debug, wird nicht ausgegeben 
        //mbedtls_mpi_write_string( &T, 10, debug_buffer, sizeof( debug_buffer ), &debug_buffer_len);
        //simpleserial_put('r', (uint8_t) debug_buffer_len, debug_buffer );

        goto cleanup;
    }
/*
    //debug
    itoa(ret, temp2, 10); //num, buff, radix
    simpleserial_put('r', 8, temp2);
    */

    /*
     * Faster decryption using the CRT
     *
     * T1 = input ^ dP mod P
     * T2 = input ^ dQ mod Q
     */
    /*
    //debug 
    mbedtls_mpi_write_string( &T, 16, debug_buffer, sizeof( debug_buffer ), &debug_buffer_len);
    simpleserial_put('r', (uint8_t) debug_buffer_len, debug_buffer ); // for 0xa433059b -> r333600 (ASCII)-> 36(HEX) -> 54 (DEC)
    mbedtls_mpi_write_string( DP, 16, debug_buffer, sizeof( debug_buffer ), &debug_buffer_len);
    simpleserial_put('r', (uint8_t) debug_buffer_len, debug_buffer );
    mbedtls_mpi_write_string( &ctx->P, 16, debug_buffer, sizeof( debug_buffer ), &debug_buffer_len);
    simpleserial_put('r', (uint8_t) debug_buffer_len, debug_buffer );
    mbedtls_mpi_write_string( &ctx->RP, 16, debug_buffer, sizeof( debug_buffer ), &debug_buffer_len);
    simpleserial_put('r', (uint8_t) debug_buffer_len, debug_buffer );
    */

    // gibt nach der 4ten Ausführung einen fehler 
    MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod( &T1, &T, DP, &ctx->P, &ctx->RP ) );
    
    /*
    //debug
    itoa(ret, temp2, 10); //num, buff, radix
    simpleserial_put('r', 8, temp2);
    */
    
    //debug 
    mbedtls_mpi_write_string( &T1, 16, debug_buffer, sizeof( debug_buffer ), &debug_buffer_len);
    //simpleserial_put('r', (uint8_t) debug_buffer_len, debug_buffer ); // for 0xa433059b -> r333600 (ASCII)-> 36(HEX) -> 54 (DEC)
    //mbedtls_mpi_write_string( DP, 16, debug_buffer, sizeof( debug_buffer ), &debug_buffer_len);
    //simpleserial_put('r', (uint8_t) debug_buffer_len, debug_buffer );
    //mbedtls_mpi_write_string( &ctx->P, 16, debug_buffer, sizeof( debug_buffer ), &debug_buffer_len);
    //simpleserial_put('r', (uint8_t) debug_buffer_len, debug_buffer );
    
    
    MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod( &T2, &T, DQ, &ctx->Q, &ctx->RQ ) );
    /*
    //debug
    itoa(ret, temp2, 10); //num, buff, radix
    simpleserial_put('r', 8, temp2);
    */
    //debug
    mbedtls_mpi_write_string( &T2, 16, debug_buffer, sizeof( debug_buffer ), &debug_buffer_len);
    //simpleserial_put('r', (uint8_t) debug_buffer_len, debug_buffer );
    //mbedtls_mpi_write_string( DQ, 16, debug_buffer, sizeof( debug_buffer ), &debug_buffer_len);
    //simpleserial_put('r', (uint8_t) debug_buffer_len, debug_buffer );
    //mbedtls_mpi_write_string( &ctx->Q, 16, debug_buffer, sizeof( debug_buffer ), &debug_buffer_len);
    //simpleserial_put('r', (uint8_t) debug_buffer_len, debug_buffer );

    /*
    //debug
    itoa(ret, temp2, 10); //num, buff, radix
    simpleserial_put('r', 8, temp2);
    */

    /*
     * T = (T1 - T2) * (Q^-1 mod P) mod P
     */
    trigger_high();
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &T, &T1, &T2 ) );
    trigger_low();
    //trigger_high();


    //debug, wird ausgegben 
    /*
    mbedtls_mpi_write_string( &T, 16, debug_buffer, sizeof( debug_buffer ), &debug_buffer_len);
    simpleserial_put('r', (uint8_t) debug_buffer_len, debug_buffer );
    */
    
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &T1, &T, &ctx->QP ) );
    //trigger_low();
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &T, &T1, &ctx->P ) );
    
    //mbedtls_mpi_write_string( &T, 16, debug_buffer, sizeof( debug_buffer ), &debug_buffer_len);
    //simpleserial_put('r', (uint8_t) debug_buffer_len, debug_buffer );

    /*
    //debug
    itoa(ret, temp2, 10); //num, buff, radix
    simpleserial_put('r', 8, temp2);
    */
    

    /*
     * T = T2 + T * Q
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &T1, &T, &ctx->Q ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &T, &T2, &T1 ) );
    //debug
    //mbedtls_mpi_write_string( &T, 16, debug_buffer, sizeof( debug_buffer ), &debug_buffer_len);
    //simpleserial_put('r', (uint8_t) debug_buffer_len, debug_buffer );

    olen = ctx->len;
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &T, output, olen ) );
    //debug
    //simpleserial_put('r', RSA_KEY_LEN, output );

cleanup:
    mbedtls_mpi_free( &T ); mbedtls_mpi_free( &T1 ); mbedtls_mpi_free( &T2 );
    mbedtls_mpi_free( &P1 ); mbedtls_mpi_free( &Q1 ); mbedtls_mpi_free( &R );

    
    //debug
    itoa(ret, temp2, 10); //num, buff, radix
    simpleserial_put('r', sizeof(temp2), temp2);
    // beim 5ten mal: r2D31360000000000 = -16 
    
    
    if( ret != 0 )
        return( MBEDTLS_ERR_RSA_PRIVATE_FAILED + ret ); //  -0x4300 + ret // -17152 +-16 = -17168 -> wird ausgegebn 

    return( 0 );
}


void load_key_from_flash(mbedtls_mpi *X, PGM_VOID_P os, size_t length) {
    
    //debug
    //uint8_t temp1[8];
    /*
    //num, buff, radix
    itoa(length, temp2, 16);
    simpleserial_put('r', sizeof(temp2), temp2);
    */
    
    //temp buffer to store key from flash
    uint8_t key_buf[length]; //Anzahl der Bytes

    //copy data from flash to buffer
    //dest, src, len
    memcpy_P(key_buf, os, length);

    //debug
    //simpleserial_put('r', length, key_buf); // korrekter output bei 16 byte 

    // convert into mbedtls datatype
    // result number:&rsa_ctx.N; buffer(bigend): RSA_N; bufferlen (buffergröße in bytes?)
    int ret = mbedtls_mpi_read_binary( X, key_buf, length);

    //itoa(ret, temp1, 10); //num, buff, radix
    //simpleserial_put('r', sizeof(temp1), temp1); // liefert r2D31360000000000 -> -16 -> MBEDTLS_ERR_MPI_ALLOC_FAILED  
    
    //debug
    mbedtls_mpi_write_string( X, 16, debug_buffer, sizeof( debug_buffer ), &debug_buffer_len);
    
    
    //simpleserial_put('r', (uint8_t) debug_buffer_len, debug_buffer ); // 00 bei 16 byte prim 

    
    
}


void rsa_init(void)
{
    //initialisiert ctx 
    mbedtls_rsa_init( &rsa_ctx, MBEDTLS_RSA_PKCS_V15, 0 ); // ctx->padding = MBEDTLS_RSA_PKCS_V15 ersetzten?  
    
    //warum? warnung bei comipilieren mit ss_ver_2_1
    simpleserial_addcmd('1', 0, sig_chunk_1);
    //simpleserial_addcmd('2', 0, sig_chunk_2);
    
    //load key variables into rsa context 
    rsa_ctx.len = RSA_KEY_LEN;

    /*
    //debug
    uint8_t temp3[2];
    itoa(55, temp3, 10); //num, buff, radix
    simpleserial_put('r', sizeof(temp3), temp3);
    */

    //load key data into ctx
    
    //from progmem
    load_key_from_flash( &rsa_ctx.N, modulus2, sizeof(modulus2));
    load_key_from_flash( &rsa_ctx.E, pub_exponent2, sizeof(pub_exponent2));
    load_key_from_flash( &rsa_ctx.D, priv_exponent2, sizeof(priv_exponent2));
    load_key_from_flash( &rsa_ctx.P, p2, sizeof(p2));
    load_key_from_flash( &rsa_ctx.Q, q2, sizeof(q2));
    load_key_from_flash( &rsa_ctx.DP, dp2, sizeof(dp2));
    load_key_from_flash( &rsa_ctx.DQ, dq2, sizeof(dq2));
    load_key_from_flash( &rsa_ctx.QP, qinv2, sizeof(qinv2));

    /*
    //from string; dest*, radix, char*
    mbedtls_mpi_read_string( &rsa_ctx.N , 16, RSA_N  ) ;
    mbedtls_mpi_read_string( &rsa_ctx.E , 16, RSA_E  ) ;
    mbedtls_mpi_read_string( &rsa_ctx.D , 16, RSA_D  ) ;
    mbedtls_mpi_read_string( &rsa_ctx.P , 16, RSA_P  ) ;
    mbedtls_mpi_read_string( &rsa_ctx.Q , 16, RSA_Q  ) ;
    mbedtls_mpi_read_string( &rsa_ctx.DP, 16, RSA_DP ) ;
    mbedtls_mpi_read_string( &rsa_ctx.DQ, 16, RSA_DQ ) ;
    int ret = mbedtls_mpi_read_string( &rsa_ctx.QP, 16, RSA_QP ) ;
    uint8_t temp2[4];
    itoa(ret, temp2, 10); 
    simpleserial_put('r', sizeof(temp2), temp2); //2d3136 = -16 alloc failed 
    */

    
    //no output, why? -> rsa_init in real_dec aufrufen
    // output = r4535373100 -> zu kurz; r4634353500; r343333444441343900
    mbedtls_mpi_write_string( &rsa_ctx.N, 16, debug_buffer, sizeof( debug_buffer ), &debug_buffer_len);
    simpleserial_put('r', (uint8_t) debug_buffer_len, debug_buffer );
    //r4535373100 -> zu kurz -> debug load_key_from_flash -> new output: r453537314645333300
    
    mbedtls_mpi_write_string( &rsa_ctx.P, 16, debug_buffer, sizeof( debug_buffer ), &debug_buffer_len);
    simpleserial_put('r', (uint8_t) debug_buffer_len, debug_buffer );
    //r4634353500 -> passt

    mbedtls_mpi_write_string( &rsa_ctx.D, 16, debug_buffer, sizeof( debug_buffer ), &debug_buffer_len);
    simpleserial_put('r', (uint8_t) debug_buffer_len, debug_buffer );
    //r343333444441343900 -> passt
    
    /*
    mbedtls_mpi_write_string( &rsa_ctx.E, 16, debug_buffer, sizeof( debug_buffer ), &debug_buffer_len);
    simpleserial_put('r', (uint8_t) debug_buffer_len, debug_buffer );
    mbedtls_mpi_write_string( &rsa_ctx.Q, 16, debug_buffer, sizeof( debug_buffer ), &debug_buffer_len);
    simpleserial_put('r', (uint8_t) debug_buffer_len, debug_buffer );
    mbedtls_mpi_write_string( &rsa_ctx.DP, 16, debug_buffer, sizeof( debug_buffer ), &debug_buffer_len);
    simpleserial_put('r', (uint8_t) debug_buffer_len, debug_buffer );
    mbedtls_mpi_write_string( &rsa_ctx.DQ, 16, debug_buffer, sizeof( debug_buffer ), &debug_buffer_len);
    simpleserial_put('r', (uint8_t) debug_buffer_len, debug_buffer );
    mbedtls_mpi_write_string( &rsa_ctx.QP, 16, debug_buffer, sizeof( debug_buffer ), &debug_buffer_len);
    simpleserial_put('r', (uint8_t) debug_buffer_len, debug_buffer );
  
    */
} 



uint8_t buf[128];
uint8_t hash[32];
    
#if SS_VER == SS_VER_2_1
uint8_t real_dec(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *pt) //input wird ignoriert ? 
#else
uint8_t real_dec(uint8_t *pt, uint8_t len)
#endif
{
    //ss_put in init liefert werte, wenn init hier auferufen wird und nicht in ss_rsa.c 
    rsa_init();
    
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
    


    //get data from buffer pt
    //pt in const unsigned char *input
    uint8_t temp[RSA_KEY_LEN]; //
    memcpy(temp, pt, len);

    //debug -> msg in temp, returns correct value
    // für 0xa433059b -> rA433059B00000000
    simpleserial_put('r', sizeof(temp), temp);
    
    //input, output
    ret = simpleserial_mbedtls_rsa_private( &rsa_ctx, NULL, NULL, temp, buf );

        /*
    //ret values of rsa_private: 2D313731 -> change rsa_key_len 
    // now: r30000000
    uint8_t temp2[8];
    itoa(ret, temp2, 10); //num, buff, radix
    simpleserial_put('r', 8, temp2);
    */

    //output = buf is empty, liefert 00000000, why??
    //simpleserial_put('r', RSA_KEY_LEN, buf);
    
    //trigger_low();

    /*
    //send back first 48 bytes
#if SS_VER == SS_VER_2_1
    simpleserial_put('r', 128, buf);
#else
    simpleserial_put('r', 48, buf);
#endif */
    return ret;
}

uint8_t sig_chunk_1(uint8_t *pt, uint8_t len)
{
     simpleserial_put('r', 48, buf + 48);
     return 0x00;
}
/*
uint8_t sig_chunk_2(uint8_t *pt, uint8_t len)
{
     simpleserial_put('r', 128 - 48 * 2, buf + 48*2);
     return 0x00;
}
*/
#endif
