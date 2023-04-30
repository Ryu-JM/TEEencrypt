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

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

#define MAX_FILE_SIZE 1000
#define CAESAR 0
#define RSA 1

void usage(char* pname) {
	printf("%s usage :\n", pname);
	printf("\t%s [-e textfile Caesar|RSA]\n", pname);
	printf("\t%s [-d encrypted_file encryption_key]\n", pname);

	return;
}

bool checkchar(char* filename) {
	int len = (sizeof(filename) / sizeof(filename[0]));

	for (int i = 0; i < len; i++) {
		if (filename[i] == '/') {
			return false;
		}
	}

	return true;
}

int main(int argc, char* argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char plaintext[MAX_FILE_SIZE] = {0,};
	char ciphertext[MAX_FILE_SIZE] = {0,};
	char* encrypted_filename = "ciphertext.txt";
	char* encrypted_key = "encryptedkey.txt";
	char* decrypted_filename = "plaintext.txt";
	char* decrypted_key = "decryptedkey.txt";
	int key=0;
	FILE* fp;
	FILE* dec_key;
	FILE* mkfp1;
	FILE* mkfp2;
	size_t file_size;
	int encrypt_option = -1;

	if (argc != 4) {
		usage(argv[0]);
		return 0;
	}

	if (!checkchar(argv[2])) {
		printf("File name has unacceptable character!!!\n");
		return 0;
	}

	if ( (fp = fopen(argv[2], "r")) == NULL) {
		printf("Cannot open the file!!!\n");
		return 0;
	}

	fseek(fp, 0, SEEK_END);
	file_size = ftell(fp);

	if (file_size >= MAX_FILE_SIZE) {
		printf("This file's size is too big!!!\n");
		return 0;
	}

	res = TEEC_InitializeContext(NULL, &ctx);
    res = TEEC_OpenSession(&ctx, &sess, &uuid,
                            TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT,
                                     TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT);

	if (!strncmp(argv[1], "-e", 2)) {
		if (!strncmp(argv[3], "Caesar", 6))
			encrypt_option = CAESAR;
		else if (!strncmp(argv[3], "RSA", 3))
			encrypt_option = RSA;
		
		if (encrypt_option == -1) {
			printf("Invalid Crypt Algorithm!!!\n");

			fclose(fp);
			TEEC_CloseSession(&sess);
			TEEC_FinalizeContext(&ctx);

			return 0;
		}

		//Encryption
		memset(plaintext, 0, file_size+1);

		fseek(fp, 0, SEEK_SET);
		fread(plaintext, file_size, 1, fp);

		if (file_size >= MAX_FILE_SIZE) {
			printf("Input File Size is too big!!!\n");

			fclose(fp);
			TEEC_CloseSession(&sess);
			TEEC_FinalizeContext(&ctx);
			
			return 0;
		}

		op.params[0].tmpref.buffer = plaintext;
	    op.params[0].tmpref.size = file_size;
		op.params[1].value.a = 0;
		op.params[2].tmpref.buffer = ciphertext;
		op.params[2].tmpref.size = MAX_FILE_SIZE;
		op.params[3].value.a = 0;

	    printf("========================Encryption========================\n");
	    memcpy(op.params[0].tmpref.buffer, plaintext, file_size);

		if (encrypt_option == CAESAR) {
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_GET,
				       	         	 &op, &err_origin);
		    res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
        		                     &err_origin);
		}
		else if (encrypt_option == RSA) {
		    res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_RSA, &op,
        		                     &err_origin);
		}


		file_size = strlen(op.params[2].tmpref.buffer);
	    memcpy(ciphertext, op.params[2].tmpref.buffer, file_size);
		key = op.params[1].value.a;

		if ( (mkfp1 = fopen(encrypted_filename, "wt")) == NULL) {
			printf("Cannot Open a File!!!\n");
			fclose(fp);
			TEEC_CloseSession(&sess);
			TEEC_FinalizeContext(&ctx);

			return 0;
		}

		fwrite(ciphertext, sizeof(char), file_size, mkfp1);
		printf("Make a Ciphertext File Successfully!!!\n");

		fclose(mkfp1);

		if ( (mkfp2 = fopen(encrypted_key, "w")) == NULL) {
			printf("Cannot Open a File!!!\n");
			fclose(fp);
			TEEC_CloseSession(&sess);
			TEEC_FinalizeContext(&ctx);

			return 0;
		}

		if (encrypt_option == CAESAR) {
			fprintf(mkfp2, "%d\n", key);
		}
		else if (encrypt_option == RSA) {
			int key2 = op.params[3].value.a;
			fprintf(mkfp2, "Private key : %d, %d\n", key, key2);
		}

		printf("Make a Encrypted CipherKey File Successfully!!!\n");

		fclose(mkfp2);
	}
	else if (!strncmp(argv[1], "-d", 2)) {
		if ( (dec_key = fopen(argv[3], "r")) == NULL) {
			printf("Cannot Open a File!!!\n");
			fclose(fp);
			TEEC_CloseSession(&sess);
			TEEC_FinalizeContext(&ctx);

			return 0;
		}

		//Decryption
		memset(plaintext, 0, file_size+1);

		fseek(fp, 0, SEEK_SET);
		fread(ciphertext, file_size, 1, fp);

		fscanf(dec_key, "%d", &key);

		fclose(dec_key);

		op.params[0].tmpref.buffer = ciphertext;
	    op.params[0].tmpref.size = file_size;
		op.params[1].value.a = key;
		op.params[2].tmpref.buffer = plaintext;
		op.params[2].tmpref.size = MAX_FILE_SIZE;

	    printf("========================Decryption========================\n");

	    memcpy(op.params[0].tmpref.buffer, ciphertext, file_size);
	    res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
                                 &err_origin);

	    memcpy(plaintext, op.params[2].tmpref.buffer, file_size);
		key = op.params[1].value.a;

		if ( (mkfp1 = fopen(decrypted_filename, "wt")) == NULL) {
			printf("Cannot Open a File!!!\n");
			fclose(fp);
			TEEC_CloseSession(&sess);
			TEEC_FinalizeContext(&ctx);

			return 0;
		}

		fwrite(plaintext, sizeof(char), file_size, mkfp1);
		printf("Make a Plaintext File Successfully!!!\n");

		fclose(mkfp1);

		if ( (mkfp2 = fopen(decrypted_key, "w")) == NULL) {
			printf("Cannot Open a File!!!\n");
			fclose(fp);
			TEEC_CloseSession(&sess);
			TEEC_FinalizeContext(&ctx);

			return 0;
		}

		fprintf(mkfp2, "%d\n", key);
		printf("Make a Decrypted CipherKey File Successfully!!!\n");

		fclose(mkfp2);
	}
	else {
		printf("Invalid Option!!!\n");
	}

	fclose(fp);

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
