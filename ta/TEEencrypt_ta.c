/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <stdio.h>
#include <string.h>

#include <TEEencrypt_ta.h>

#define MAX_FILE_SIZE 1000

unsigned int rootkey = 17;

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	IMSG("Hello World!\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	IMSG("Goodbye!\n");
}

static TEE_Result enc_value(uint32_t param_types,
	TEE_Param params[4])
{
	char * in = (char *)params[0].memref.buffer;
    char * out = (char *)params[2].memref.buffer;
    int in_len = strlen (params[0].memref.buffer);
	int key = params[1].value.a - rootkey;
    char encrypted [MAX_FILE_SIZE]={0,};

    DMSG("========================Encryption========================\n");
    DMSG("==========================Caesar==========================\n");
	DMSG ("Encryption key : %d", key);
    DMSG ("Plaintext :  %s", in);
    memcpy(encrypted, in, in_len);

    for(int i=0; i<in_len;i++){
        if(encrypted[i]>='a' && encrypted[i] <='z'){
            encrypted[i] -= 'a';
            encrypted[i] += key;
            encrypted[i] = encrypted[i] % 26;
            encrypted[i] += 'a';
        }
        else if (encrypted[i] >= 'A' && encrypted[i] <= 'Z') {
            encrypted[i] -= 'A';
            encrypted[i] += key;
            encrypted[i] = encrypted[i] % 26;
            encrypted[i] += 'A';
        }
    }
    DMSG ("Ciphertext :  %s", encrypted);
    memcpy(out, encrypted, in_len);

    return TEE_SUCCESS;

}

static TEE_Result dec_value(uint32_t param_types,
	TEE_Param params[4])
{
    char * in = (char *)params[0].memref.buffer;
    char * out = (char *)params[2].memref.buffer;
    int in_len = strlen (params[0].memref.buffer);
	int key = params[1].value.a - rootkey;
    char decrypted [MAX_FILE_SIZE]={0,};

    DMSG("========================Decryption========================\n");
	DMSG ("Key	  : %d", key);
    DMSG ("Ciphertext :  %s", in);
    memcpy(decrypted, in, in_len);

    for(int i=0; i<in_len;i++){
        if(decrypted[i]>='a' && decrypted[i] <='z'){
            decrypted[i] -= 'a';
            decrypted[i] -= key;
            decrypted[i] += 26;
            decrypted[i] = decrypted[i] % 26;
            decrypted[i] += 'a';
        }
        else if (decrypted[i] >= 'A' && decrypted[i] <= 'Z') {
            decrypted[i] -= 'A';
            decrypted[i] -= key;
            decrypted[i] += 26;
            decrypted[i] = decrypted[i] % 26;
            decrypted[i] += 'A';
        }
    }
    DMSG ("Plaintext :  %s", decrypted);

	params[1].value.a = key;

	DMSG("params[1] = %d", params[1].value.a);

    memcpy(out, decrypted, in_len);

	return TEE_SUCCESS;
}

static TEE_Result randomkey_get(uint32_t param_types,
	TEE_Param params[4])
{
	int key = 0;

	TEE_GenerateRandom(&key, sizeof(key));
	
	if (key < 0) key = -key;
	if (key < 0) key--;

    DMSG("=========================Make_key=========================\n");
	key = (key % 25) + 1;
	key += rootkey;

	params[1].value.a = key;

	DMSG("key = %d", key);
	DMSG("params[1] = %d", params[1].value.a);

	return TEE_SUCCESS;
}

static int pow_mod(int a, unsigned int n, unsigned int e) {
	int cnt = e - 1;
	int r = a % n;

	while (cnt--) {
		r = (r * a) % n;
	}

	return r;
}

static TEE_Result enc_rsa(uint32_t param_types,
	TEE_Param params[4])
{
	char * in = (char *)params[0].memref.buffer;
	char * out = (char *)params[2].memref.buffer;
    int in_len = strlen (params[0].memref.buffer);
	int encrypted_len;
	int j = 0;
    char plaintext[MAX_FILE_SIZE]={0,};
	char encrypted[MAX_FILE_SIZE]={0,};

	unsigned int n = 42480;
	unsigned int e = 8999;
	unsigned int d = 29129;

    DMSG("========================Encryption========================\n");
    DMSG("============================RSA===========================\n");
	DMSG ("Public key : %d, %d", n, e);
	DMSG ("Private key : %d, %d", n, d);
    DMSG ("Plaintext :  %s", in);
    memcpy(plaintext, in, in_len);

	for (int i = 0; i < in_len; i++) {
		j += snprintf (encrypted + j, 6, "%d", pow_mod(plaintext[i], n, e));
	}

	encrypted_len = strlen (encrypted);
	encrypted[encrypted_len] = '\n';
	DMSG("Ciphertext :  %s", encrypted);

	memcpy(out, encrypted, encrypted_len+1);
	params[1].value.a = n;
	params[3].value.a = d;

	return TEE_SUCCESS;
}

/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */

	switch (cmd_id) {
	case TA_TEEencrypt_CMD_ENC_VALUE:
		return enc_value(param_types, params);
	case TA_TEEencrypt_CMD_DEC_VALUE:
		return dec_value(param_types, params);
	case TA_TEEencrypt_CMD_RANDOMKEY_GET:
		return randomkey_get(param_types, params);
	case TA_TEEencrypt_CMD_ENC_RSA:
		return enc_rsa(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
