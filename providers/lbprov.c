/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include "prov/names.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "prov/provider_util.h"
#include "prov/implementations.h"
#include "internal/nelem.h"

/*
 * Forward declarations to ensure that interface functions are correctly
 * defined.
 */
static OSSL_FUNC_provider_teardown_fn lbprov_teardown;
static OSSL_FUNC_provider_gettable_params_fn lbprov_gettable_params;
static OSSL_FUNC_provider_get_params_fn lbprov_get_params;
static OSSL_FUNC_provider_query_operation_fn lbprov_query;

#define ALG(NAMES, FUNC) { NAMES, "provider=loadbalance", FUNC , "dummy implementation by lbprov" }

/* Parameters we provide to the core */
static const OSSL_PARAM lbprov_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *lbprov_gettable_params(void *provctx)
{
    return lbprov_param_types;
}

static int lbprov_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "a built-in loadbalance provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "0.1"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "rc0"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, ossl_prov_is_running()))
        return 0;
    return 1;
}

/* dummy functions
 * Actual computing should never happen in this provider itself. Actual
 * computing should be delegated to the child providers.
 *
 * Return: NULL or 0 on error
 */
static int dummy_int_ret_err(void)
{
    printf("Enter %s()\n", __func__);
    return 0;
}

static int dummy_int_ret_succ(void)
{
    printf("Enter %s()\n", __func__);
    return 1;
}

static void *dummy_ptr_ret(void)
{
    printf("Enter %s()\n", __func__);
    return NULL;
}

static void dummy_void_ret(void)
{
    printf("Enter %s()\n", __func__);
    return;
}

static const OSSL_DISPATCH lbprov_dummy_md5_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX,  (void (*)(void))dummy_ptr_ret },
    { OSSL_FUNC_DIGEST_UPDATE,  (void (*)(void))dummy_int_ret_err },
    { OSSL_FUNC_DIGEST_FINAL,   (void (*)(void))dummy_int_ret_err },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))dummy_void_ret },
    { OSSL_FUNC_DIGEST_DUPCTX,  (void (*)(void))dummy_ptr_ret },
    { OSSL_FUNC_DIGEST_INIT,    (void (*)(void))dummy_int_ret_err },
    /*
     * OSSL_FUNC_DIGEST_GET_PARAMS must return 1 success.
     * Otherwise ossl_method_construct() fails at evp_md_cache_constants()
     */
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))dummy_int_ret_succ },
    { 0, NULL }
};

static const OSSL_ALGORITHM lbprov_digests[] = {
    ALG(PROV_NAMES_MD5, lbprov_dummy_md5_functions),
    { NULL, NULL, NULL }
};

#include <stdio.h>
#include <execinfo.h>
#include <stdlib.h>
void print_call_stack() {
    void* callstack[128];
    int num_frames;
    char** symbols;

    // Get the call stack
    num_frames = backtrace(callstack, sizeof(callstack) / sizeof(void*));

    // Get the function names and addresses
    symbols = backtrace_symbols(callstack, num_frames);

    if (symbols) {
        // Print the call stack
        printf("Call Stack:\n");
        for (int i = 0; i < num_frames; i++) {
            printf("%s\n", symbols[i]);
        }

        // Free the memory allocated by backtrace_symbols
        free(symbols);
    } else {
        printf("Error: Unable to obtain backtrace symbols.\n");
    }
}

/* dummy function for cipher */
# define IMPLEMENT_lbprov_dummy_cipher_func(alg, UCALG, lcmode, UCMODE,        \
                                           flags, kbits, blkbits, ivbits, typ) \
const OSSL_DISPATCH lbprov_dummy_##alg##kbits##lcmode##_functions[] = {        \
    { OSSL_FUNC_CIPHER_NEWCTX,       (void (*)(void)) dummy_ptr_ret },         \
    { OSSL_FUNC_CIPHER_FREECTX,      (void (*)(void)) dummy_void_ret },        \
    { OSSL_FUNC_CIPHER_DUPCTX,       (void (*)(void)) dummy_ptr_ret },         \
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void)) dummy_int_ret_succ },    \
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void)) dummy_int_ret_succ },    \
    { OSSL_FUNC_CIPHER_UPDATE,       (void (*)(void)) dummy_int_ret_err },     \
    { OSSL_FUNC_CIPHER_FINAL,        (void (*)(void)) dummy_int_ret_err },     \
    { OSSL_FUNC_CIPHER_CIPHER,       (void (*)(void)) dummy_int_ret_err },     \
    { OSSL_FUNC_CIPHER_GET_PARAMS,          (void (*)(void))dummy_int_ret_succ },   \
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,      (void (*)(void))dummy_int_ret_succ },   \
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,      (void (*)(void))dummy_int_ret_succ },   \
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,     (void (*)(void))dummy_ptr_ret },   \
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))dummy_ptr_ret },   \
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))dummy_ptr_ret },   \
    OSSL_DISPATCH_END                                                          \
};

/*
 * AES dummy
 */
/* lbprov_dummy_aes256ctr_functions */
IMPLEMENT_lbprov_dummy_cipher_func(aes, AES, ctr, CTR, 0, 256, 8, 128, stream)
/* lbprov_dummy_aes192ctr_functions */
IMPLEMENT_lbprov_dummy_cipher_func(aes, AES, ctr, CTR, 0, 192, 8, 128, stream)
/* lbprov_dummy_aes128ctr_functions */
IMPLEMENT_lbprov_dummy_cipher_func(aes, AES, ctr, CTR, 0, 128, 8, 128, stream)
/* lbprov_dummy_aes256ecb_functions */
IMPLEMENT_lbprov_dummy_cipher_func(aes, AES, ecb, ECB, 0, 256, 128, 0, block)
/* lbprov_dummy_aes192ecb_functions */
IMPLEMENT_lbprov_dummy_cipher_func(aes, AES, ecb, ECB, 0, 192, 128, 0, block)
/* lbprov_dummy_aes128ecb_functions */
IMPLEMENT_lbprov_dummy_cipher_func(aes, AES, ecb, ECB, 0, 128, 128, 0, block)
/* lbprov_dummy_aes256cbc_functions */
IMPLEMENT_lbprov_dummy_cipher_func(aes, AES, cbc, CBC, 0, 256, 128, 128, block)
/* lbprov_dummy_aes192cbc_functions */
IMPLEMENT_lbprov_dummy_cipher_func(aes, AES, cbc, CBC, 0, 192, 128, 128, block)
/* lbprov_dummy_aes128cbc_functions */
IMPLEMENT_lbprov_dummy_cipher_func(aes, AES, cbc, CBC, 0, 128, 128, 128, block)
/* lbprov_dummy_aes256ofb_functions */
IMPLEMENT_lbprov_dummy_cipher_func(aes, AES, ofb, OFB, 0, 256, 8, 128, stream)
/* lbprov_dummy_aes192ofb_functions */
IMPLEMENT_lbprov_dummy_cipher_func(aes, AES, ofb, OFB, 0, 192, 8, 128, stream)
/* lbprov_dummy_aes128ofb_functions */
IMPLEMENT_lbprov_dummy_cipher_func(aes, AES, ofb, OFB, 0, 128, 8, 128, stream)
/* lbprov_dummy_aes256cfb_functions */
IMPLEMENT_lbprov_dummy_cipher_func(aes, AES, cfb,  CFB, 0, 256, 8, 128, stream)
/* lbprov_dummy_aes192cfb_functions */
IMPLEMENT_lbprov_dummy_cipher_func(aes, AES, cfb,  CFB, 0, 192, 8, 128, stream)
/* lbprov_dummy_aes128cfb_functions */
IMPLEMENT_lbprov_dummy_cipher_func(aes, AES, cfb,  CFB, 0, 128, 8, 128, stream)
/* lbprov_dummy_aes256cfb1_functions */
IMPLEMENT_lbprov_dummy_cipher_func(aes, AES, cfb1, CFB, 0, 256, 8, 128, stream)
/* lbprov_dummy_aes192cfb1_functions */
IMPLEMENT_lbprov_dummy_cipher_func(aes, AES, cfb1, CFB, 0, 192, 8, 128, stream)
/* lbprov_dummy_aes128cfb1_functions */
IMPLEMENT_lbprov_dummy_cipher_func(aes, AES, cfb1, CFB, 0, 128, 8, 128, stream)
/* lbprov_dummy_aes256cfb8_functions */
IMPLEMENT_lbprov_dummy_cipher_func(aes, AES, cfb8, CFB, 0, 256, 8, 128, stream)
/* lbprov_dummy_aes192cfb8_functions */
IMPLEMENT_lbprov_dummy_cipher_func(aes, AES, cfb8, CFB, 0, 192, 8, 128, stream)
/* lbprov_dummy_aes128cfb8_functions */
IMPLEMENT_lbprov_dummy_cipher_func(aes, AES, cfb8, CFB, 0, 128, 8, 128, stream)

#ifndef OPENSSL_NO_SM4
/*
 * SM4 dummy
 */
/* lbprov_dummy_sm4128ecb_functions */
IMPLEMENT_lbprov_dummy_cipher_func(sm4, SM4, ecb, ECB, 0, 128, 128, 0, block)
/* lbprov_dummy_sm4128cbc_functions */
IMPLEMENT_lbprov_dummy_cipher_func(sm4, SM4, cbc, CBC, 0, 128, 128, 128, block)
/* lbprov_dummy_sm4128ctr_functions */
IMPLEMENT_lbprov_dummy_cipher_func(sm4, SM4, ctr, CTR, 0, 128, 8, 128, stream)
/* lbprov_dummy_sm4128ofb128_functions */
IMPLEMENT_lbprov_dummy_cipher_func(sm4, SM4, ofb128, OFB, 0, 128, 8, 128, stream)
/* lbprov_dummy_sm4128cfb128_functions */
IMPLEMENT_lbprov_dummy_cipher_func(sm4, SM4, cfb128,  CFB, 0, 128, 8, 128, stream)
#endif

static const OSSL_ALGORITHM lbprov_ciphers[] = {
#if 0
    /* TODO: if enable the following line ALG(.., lbprov_dummy_aes256ctr_functions)
     * this runtime error will happen, even with default provider only.
     *
     * $ openssl speed -provider default -seconds 1 -bytes 100 -evp md5
     * $ openssl speed -provider loadbalance -provider default -seconds 1 -bytes 100 -evp md5
     *
     * Error message:
     *  203009B1FFFF0000:error:1C8000BC:Provider routines:ossl_prov_drbg_instantiate:error instantiating drbg:providers/implementations/rands/drbg.c:456:
     *  203009B1FFFF0000:error:1200006C:random number generator:rand_new_drbg:error instantiating drbg:crypto/rand/rand_lib.c:612:
     */
    ALG(PROV_NAMES_AES_256_CTR, lbprov_dummy_aes256ctr_functions),
#endif
    ALG(PROV_NAMES_AES_192_CTR, lbprov_dummy_aes192ctr_functions),
    ALG(PROV_NAMES_AES_128_CTR, lbprov_dummy_aes128ctr_functions),
    ALG(PROV_NAMES_AES_256_ECB, lbprov_dummy_aes256ecb_functions),
    ALG(PROV_NAMES_AES_192_ECB, lbprov_dummy_aes192ecb_functions),
    ALG(PROV_NAMES_AES_128_ECB, lbprov_dummy_aes128ecb_functions),
    ALG(PROV_NAMES_AES_256_CBC, lbprov_dummy_aes256cbc_functions),
    ALG(PROV_NAMES_AES_192_CBC, lbprov_dummy_aes192cbc_functions),
    ALG(PROV_NAMES_AES_128_CBC, lbprov_dummy_aes128cbc_functions),
    ALG(PROV_NAMES_AES_256_OFB, lbprov_dummy_aes256ofb_functions),
    ALG(PROV_NAMES_AES_192_OFB, lbprov_dummy_aes192ofb_functions),
    ALG(PROV_NAMES_AES_128_OFB, lbprov_dummy_aes128ofb_functions),
    ALG(PROV_NAMES_AES_256_CFB, lbprov_dummy_aes256cfb_functions),
    ALG(PROV_NAMES_AES_192_CFB, lbprov_dummy_aes192cfb_functions),
    ALG(PROV_NAMES_AES_128_CFB, lbprov_dummy_aes128cfb_functions),
    ALG(PROV_NAMES_AES_256_CFB1, lbprov_dummy_aes256cfb1_functions),
    ALG(PROV_NAMES_AES_192_CFB1, lbprov_dummy_aes192cfb1_functions),
    ALG(PROV_NAMES_AES_128_CFB1, lbprov_dummy_aes128cfb1_functions),
    ALG(PROV_NAMES_AES_256_CFB8, lbprov_dummy_aes256cfb8_functions),
    ALG(PROV_NAMES_AES_192_CFB8, lbprov_dummy_aes192cfb8_functions),
    ALG(PROV_NAMES_AES_128_CFB8, lbprov_dummy_aes128cfb8_functions),
#ifndef OPENSSL_NO_SM4
    ALG(PROV_NAMES_SM4_ECB, lbprov_dummy_sm4128ecb_functions),
    ALG(PROV_NAMES_SM4_CBC, lbprov_dummy_sm4128cbc_functions),
    ALG(PROV_NAMES_SM4_CTR, lbprov_dummy_sm4128ctr_functions),
    ALG(PROV_NAMES_SM4_OFB, lbprov_dummy_sm4128ofb128_functions),
    ALG(PROV_NAMES_SM4_CFB, lbprov_dummy_sm4128cfb128_functions),
#endif /* OPENSSL_NO_SM4 */
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM lbprov_kdfs[] = {
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *lbprov_query(void *provctx, int operation_id,
                                          int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_DIGEST:
        return lbprov_digests;
    case OSSL_OP_CIPHER:
        return lbprov_ciphers;
    case OSSL_OP_KDF:
        return lbprov_kdfs;
    }
    return NULL;
}

static void lbprov_teardown(void *provctx)
{
    OSSL_LIB_CTX_free(PROV_LIBCTX_OF(provctx));
    ossl_prov_ctx_free(provctx);
}

/* The base dispatch table */
static const OSSL_DISPATCH lbprov_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))lbprov_teardown },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))lbprov_query },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))lbprov_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))lbprov_get_params },
    { 0, NULL }
};

typedef struct lbprov_conf_st {
    int strategy;
} LBPROV_CONF;

static LBPROV_CONF lbprov_conf;

static int lbprov_get_params_from_core(OSSL_FUNC_core_get_params_fn *c_get_params,
                                       const OSSL_CORE_HANDLE *handle)
{
    /*
    * Parameters to retrieve from the configuration
    * NOTE: inside c_get_params() these will be loaded from config items
    * stored inside prov->parameters
    */

    OSSL_PARAM core_params[2], *p = core_params;
    const char *strategy_string = "\0";
    int conf_strategy = 0;

    /* NOTE: config parameter values are always treated as string
     * refer to ossl_provider_add_parameter()
     */
    *p++ = OSSL_PARAM_construct_utf8_ptr("lb-strategy",
                                         (char **)&strategy_string,
                                         sizeof(strategy_string));
    *p = OSSL_PARAM_construct_end();

    if (!c_get_params(handle, core_params)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return 0;
    }

    if (strategy_string[0] != '\0')
        conf_strategy = atoi(strategy_string);
    else                /* no strategy config from core */
        return 1;

    /* validate the returned value */
    if ((conf_strategy < LB_STRATEGY_ROUND_ROBIN) || (conf_strategy >= LB_STRATEGY_MAX))
        lbprov_conf.strategy = LB_STRATEGY_ROUND_ROBIN;
    else
        lbprov_conf.strategy = conf_strategy;

    return 1;
}

#ifdef STATIC_LBPROV
OSSL_provider_init_fn ossl_lb_provider_init;
# define OSSL_provider_init ossl_lb_provider_init
#endif

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    OSSL_LIB_CTX *libctx = NULL;
    const OSSL_DISPATCH *tmp = in;
    OSSL_FUNC_provider_set_load_balancer_fn *c_set_load_balancer = NULL;
    OSSL_FUNC_core_get_params_fn *c_get_params = NULL;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_PROVIDER_SET_LOAD_BALANCER:
            c_set_load_balancer = OSSL_FUNC_provider_set_load_balancer(in);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_FUNC_core_get_params(in);
            break;
        default:
            /* Just ignore anything we don't understand */
            break;
        }
    }

    /* initialize load balance configurations */
    lbprov_conf.strategy = LB_STRATEGY_ROUND_ROBIN;

    /* get configuration from core */
    if ((c_get_params == NULL)
            || (lbprov_get_params_from_core(c_get_params, handle) == 0))
        return 0;

    /* mark self as a loadbalancer provider */
    if ((c_set_load_balancer == NULL) || (c_set_load_balancer(handle) == 0))
        return 0;

    /* create load_balancer libctx */
    if ((*provctx = ossl_prov_ctx_new()) == NULL
        || (libctx = OSSL_LIB_CTX_new_load_balancer(handle, tmp,
                                                    lbprov_conf.strategy)) == NULL) {
        OSSL_LIB_CTX_free(libctx);
        goto err;
    }

    /* set up provctx */
    ossl_prov_ctx_set0_libctx(*provctx, libctx);
    ossl_prov_ctx_set0_handle(*provctx, handle);

    *out = lbprov_dispatch_table;
    return 1;

err:
    lbprov_teardown(*provctx);
    *provctx = NULL;
    return 0;
}
