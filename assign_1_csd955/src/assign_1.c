#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/cmac.h>

#define BLOCK_SIZE 16


/* function prototypes */
void print_hex(unsigned char *, size_t);
void print_string(unsigned char *, size_t); 
void usage(void);
void check_args(char *, char *, unsigned char *, int, int);
unsigned char * keygen(unsigned char *, unsigned char *, unsigned char *, int);
void encrypt(unsigned char *, int, unsigned char *, unsigned char *, 
    unsigned char *, int );
int decrypt(unsigned char *, int, unsigned char *, unsigned char *, 
    unsigned char *, int);
void gen_cmac(unsigned char *, size_t, unsigned char *, unsigned char *, int);
int verify_cmac(unsigned char *, unsigned char *);


const EVP_MD * getDigestSHA1();
const EVP_CIPHER * getCipher(int);
EVP_CIPHER_CTX * createContext();
void initializeEncryptionOperation(EVP_CIPHER_CTX *, unsigned char *, int);
void initializeDecryptionOperation(EVP_CIPHER_CTX *, unsigned char *, int);
FILE * openFile(char *, char *);

/*
 * Prints the hex value of the input
 * 16 values per line
 */
void
print_hex(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("\n");
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}


/*
 * Prints the input as string
 */
void
print_string(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++)
			printf("%c", data[i]);
		printf("\n");
	}
}


/*
 * Prints the usage message
 * Describe the usage of the new arguments you introduce
 */
void
usage(void)
{
	printf(
	    "\n"
	    "Usage:\n"
	    "    assign_1 -i in_file -o out_file -p passwd -b bits" 
	        " [-d | -e | -s | -v]\n"
	    "    assign_1 -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    " -i    path    Path to input file\n"
	    " -o    path    Path to output file\n"
	    " -p    psswd   Password for key generation\n"
	    " -b    bits    Bit mode (128 or 256 only)\n"
	    " -d            Decrypt input and store results to output\n"
	    " -e            Encrypt input and store results to output\n"
	    " -s            Encrypt+sign input and store results to output\n"
	    " -v            Decrypt+verify input and store results to output\n"
	    " -h            This help message\n"
	);
	exit(EXIT_FAILURE);
}


/*
 * Checks the validity of the arguments
 * Check the new arguments you introduce
 */
void
check_args(char *input_file, char *output_file, unsigned char *password, 
    int bit_mode, int op_mode)
{
	if (!input_file) {
		printf("Error: No input file!\n");
		usage();
	}

	if (!output_file) {
		printf("Error: No output file!\n");
		usage();
	}

	if (!password) {
		printf("Error: No user key!\n");
		usage();
	}

	if ((bit_mode != 128) && (bit_mode != 256)) {
		printf("Error: Bit Mode <%d> is invalid!\n", bit_mode);
		usage();
	}

	if (op_mode == -1) {
		printf("Error: No mode\n");
		usage();
	}
}




/*
 * Generates a key using a password
 */
unsigned char *
keygen(unsigned char *password, unsigned char *key, unsigned char *iv,
    int bit_mode)
{
    const EVP_CIPHER *cipher = NULL;
    const EVP_MD *dgst = NULL;
    unsigned char *salt = NULL;
    
    
    cipher = getCipher(bit_mode);
    if(!cipher) return NULL;
    
    dgst = getDigestSHA1();
    if(!dgst) return NULL;
        
    key = malloc (cipher->key_len * sizeof(char));
    iv = malloc (EVP_MAX_IV_LENGTH * sizeof(char));
    
    if(!EVP_BytesToKey(cipher, dgst, salt, password, strlen((const char *)password), 1, key, iv)){
        fprintf(stderr, "EVP_BytesToKey failed\n");
        exit(EXIT_FAILURE);
    }

    print_hex(key, cipher->key_len);
    
    return key;
}



/*
 * Encrypts the data
 */


void
encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
    unsigned char *iv, unsigned char *ciphertext, int bit_mode)
{
        EVP_CIPHER_CTX *context;
        int len, ciphertext_len;
      
        context = createContext();
        
        initializeEncryptionOperation(context, key, bit_mode);
  
        /*Provide the message to be encrypted and obtain the encrypted output*/
        if(EVP_EncryptUpdate(context, ciphertext, &len, plaintext, plaintext_len) != 1){
            fprintf(stderr, "EVP_EncryptUpdate failed\n");
            exit(EXIT_FAILURE);
            
        }
        ciphertext_len = len;
        
        /* Finalize the encryption. Further ciphertext bytes may be written at this stage.*/
        if(EVP_EncryptFinal(context, ciphertext + len, &len) != 1) {
            fprintf(stderr, "EVP_EncryptUpdate failed\n");
            exit(EXIT_FAILURE);
        }
        ciphertext_len += len;
        
       /* Print message as hex*/
        print_hex(ciphertext, ciphertext_len);
        
        /* Clean up*/
        EVP_CIPHER_CTX_free(context);

}



/*
 * Decrypts the data and returns the plaintext size
 */
int
decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
    unsigned char *iv, unsigned char *plaintext, int bit_mode)
{
	int plaintext_len, len;
        EVP_CIPHER_CTX *context;

	plaintext_len = 0;

        
        context = createContext();
        
        initializeDecryptionOperation(context, key, bit_mode);
        
        /* Provide a message to be decrypted, and obtain the plaintext*/
        
         if(EVP_DecryptUpdate(context, plaintext, &len, ciphertext, ciphertext_len) != 1){
            fprintf(stderr, "EVP_DecryptUpdate failed\n");
            exit(EXIT_FAILURE);
            
        }
        plaintext_len = len;
        
        /*Finalize the decryption. Further plaintext bytes may be written at this stage*/
        if(EVP_DecryptFinal(context, plaintext + len, &len) != 1){
            fprintf(stderr, "EVP_DecryptFinal failed\n");
            exit(EXIT_FAILURE);
            
        }
        
        plaintext_len += len;
        
        print_string(plaintext, plaintext_len);
        EVP_CIPHER_CTX_free(context);
        
	return plaintext_len;
}


/*
 * Generates a CMAC
 */
void
gen_cmac(unsigned char *data, size_t data_len, unsigned char *key, 
    unsigned char *cmac, int bit_mode)
{
        CMAC_CTX *ctx = NULL;
        size_t cmacLen;
        
        if(!(ctx = CMAC_CTX_new())){
            fprintf(stderr, "CMAC_CTX_new() failed\n");
            exit(EXIT_FAILURE);
        }
        
       /* CMAC_Init configures ctx to use the given key and cipher. The CMAC RFC only specifies the use of AES-128 thus key_len should be 16 and cipher should be EVP_aes_128_cbc(). However, this implementation also supports AES-256 by setting key_len to 32 and cipher to EVP_aes_256_cbc(). */
    
        switch (bit_mode){
            case 128:
                if(CMAC_Init(ctx, key, 16, EVP_aes_128_ecb(), NULL) != 1){
                    fprintf(stderr, "CMAC_Init failed\n");
                    return;
                }
                break;
            case 256:
                if(CMAC_Init(ctx, key, 32, EVP_aes_256_ecb(), NULL) != 1){
                    fprintf(stderr, "CMAC_Init failed\n");
                    return;
                }
                break;
            default:
                printf ("bit_mode should be 128 or 256!\n");
                return;
        }
        /*CMAC_Update processes data_len bytes of data from input.*/
        if(CMAC_Update(ctx, data, data_len) != 1){
            fprintf(stderr, "CMAC_Update failed\n");
            exit(EXIT_FAILURE);
            
        }
        
        if(CMAC_Final(ctx, cmac, &cmacLen) != 1){
            fprintf(stderr, "CMAC_Final failed\n");
            exit(EXIT_FAILURE);
            
        }
        
        CMAC_CTX_free(ctx);
}



/*
 * Verifies a CMAC
 */
int
verify_cmac(unsigned char *cmac1, unsigned char *cmac2)
{
	int verify;

	verify = 0;

	if(memcmp((const char *)cmac1, (const char *)cmac2, 16) == 0){
            verify = 1;
        }else{
            verify = 0;
        }

	return verify;
}

const EVP_MD * getDigestSHA1(){
    const EVP_MD *dgst = NULL;
    const  char *hash_type = "sha1";
    
    dgst =  EVP_get_digestbyname(hash_type);
    if(!dgst) { 
        fprintf(stderr, "EVP_get_digestbyname failed.\n"); 
        exit(EXIT_FAILURE);
    }
    return dgst;
}

const EVP_CIPHER * getCipher(int bit_mode){
    const EVP_CIPHER *cipher = NULL;
    
    switch (bit_mode){
        case 128:
            printf ("Creating a %d bit key...\n", bit_mode);
            cipher = EVP_get_cipherbyname("aes-128-ecb");
            if(!cipher) { 
                fprintf(stderr, "EVP_get_cipherbyname(\"aes-128-ecb\") failed \n"); 
                exit(EXIT_FAILURE); 
            }
            break;
        case 256:
            printf ("Creating a %d bit key...\n", bit_mode);
            cipher = EVP_get_cipherbyname("aes-256-ecb");
            if(!cipher) { 
                fprintf(stderr, "EVP_get_cipherbyname(\"aes-256-ecb\") failed \n"); 
                exit(EXIT_FAILURE);
            }
            break;
        default:
            printf ("bit_mode should be 128 or 256!\n");
            exit(EXIT_FAILURE);
    }
    
    return cipher;
}



EVP_CIPHER_CTX * createContext(){
    EVP_CIPHER_CTX *ctx;
    /* Create and Initialize the context */
    if(!(ctx = EVP_CIPHER_CTX_new())){
            fprintf(stderr, "EVP_CIPHER_CTX_new() failed\n");
            exit(EXIT_FAILURE);
        
    }
    
    return ctx;
}

void initializeEncryptionOperation(EVP_CIPHER_CTX * ctx, unsigned char *key, int bit_mode){
    
    switch (bit_mode){
            case 128:
                if(EVP_EncryptInit(ctx, EVP_aes_128_ecb(), key, NULL) != 1){
                    fprintf(stderr, "EVP_EncryptInit for 128 bit_mode failed\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case 256:
                if(EVP_EncryptInit(ctx, EVP_aes_256_ecb(), key, NULL) != 1){
                    fprintf(stderr, "EVP_EncryptInit for 256 bit_mode failed\n");
                    exit(EXIT_FAILURE);
                }
                break;
            default:
                printf ("bit_mode should be 128 or 256!\n");
                exit(EXIT_FAILURE);
        }
        
}

FILE * openFile(char *input_file, char *mode){
    FILE *myfp = fopen(input_file, mode);
    if (myfp == NULL){
        fprintf(stderr, "File error");
        exit(EXIT_FAILURE);
        
    }
    return myfp;
}

void initializeDecryptionOperation(EVP_CIPHER_CTX * ctx, unsigned char *key, int bit_mode){
    
    switch (bit_mode){
            case 128:
                if(EVP_DecryptInit(ctx, EVP_aes_128_ecb(), key, NULL) != 1){
                    fprintf(stderr, "EVP_DecryptInit for 128 bit_mode failed\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case 256:
                if(EVP_DecryptInit(ctx, EVP_aes_256_ecb(), key, NULL) != 1){
                    fprintf(stderr, "EVP_DecryptInit for 256 bit_mode failed\n");
                    exit(EXIT_FAILURE);
                }
                break;
            default:
                printf ("bit_mode should be 128 or 256!\n");
                exit(EXIT_FAILURE);
        }
        
}




/*
 * Encrypts the input file and stores the ciphertext to the output file
 *
 * Decrypts the input file and stores the plaintext to the output file
 *
 * Encrypts and signs the input file and stores the ciphertext concatenated with 
 * the CMAC to the output file
 *
 * Decrypts and verifies the input file and stores the plaintext to the output
 * file
 */

int
main(int argc, char **argv)
{
	int opt;			/* used for command line arguments */
	int bit_mode;			/* defines the key-size 128 or 256 */
	int op_mode;			/* operation mode */
	char *input_file;		/* path to the input file */
	char *output_file;		/* path to the output file */
	unsigned char *password;	/* the user defined password */
	unsigned char *myKey = NULL,*myIV = NULL;
        FILE * fp, *outfp;
        unsigned char * plaintext, *ciphertxt = NULL, *cmac, *cipher_with_cmac = NULL, *ciphers_mac;
        long lSize;
        size_t result, ciphertext_length, plaintext_length, res;

	/* Init arguments */
	input_file = NULL;
	output_file = NULL;
	password = NULL;
	bit_mode = -1;
	op_mode = -1;


	/**
	 * Get arguments
	 */
	while ((opt = getopt(argc, argv, "b:i:m:o:p:desvh:")) != -1) {
		switch (opt) {
		case 'b':
			bit_mode = atoi(optarg);
                        fprintf(stdout, "bit_mode: %d\n", bit_mode);
			break;
		case 'i':
			input_file = strdup(optarg);
			break;
		case 'o':
			output_file = strdup(optarg);
			break;
		case 'p':
			password = (unsigned char *)strdup(optarg);
                        fprintf(stdout, "password: %s\n", password);
			break;
		case 'd':
			/* if op_mode == 1 the tool decrypts */
			op_mode = 1;
			break;
		case 'e':
			/* if op_mode == 1 the tool encrypts */
			op_mode = 0;
			break;
		case 's':
			/* if op_mode == 1 the tool signs */
			op_mode = 2;
			break;
		case 'v':
			/* if op_mode == 1 the tool verifies */
			op_mode = 3;
			break;
		case 'h':
		default:
			usage();
		}
	}


	/* check arguments */
	check_args(input_file, output_file, password, bit_mode, op_mode);
        
        
	/* Initialize the library */
        ERR_load_crypto_strings();
        OpenSSL_add_all_algorithms();
        OPENSSL_config(NULL);

	/* Keygen from password */
        myKey = keygen(password, myKey, myIV , bit_mode);
    
	
         /* Operate on the data according to the mode */
        switch (op_mode){
            case 0:
                printf("-- Mode: ENCRYPT\n");
                /* encrypt */
                fp = openFile(input_file, "rb");
                
                /*Calculate the size of the plaintext*/
                fseek(fp, 0L, SEEK_END);
                lSize = ftell(fp);
                fseek(fp, 0L, SEEK_SET);
                
                /* allocate memory for plaintext storing*/
                plaintext = malloc (sizeof(char) * lSize);
                if (plaintext == NULL){
                    fprintf(stderr, "Memory error");
                    exit(2);
                }
                /*read plaintext*/
                result = fread(plaintext, sizeof(char), lSize, fp);
                if (result != lSize){
                    fprintf(stderr, "Reading error");
                    exit(3);   
                }
                /*calculate the length of ciphertext. We calculate how many blocks is the plaintext. We multiply with BLOCK_SIZE to calculate the size we need along with padding */
                ciphertext_length = ((lSize / BLOCK_SIZE)+1) * BLOCK_SIZE;
                ciphertxt = malloc (ciphertext_length * sizeof(char));
                
                encrypt(plaintext, lSize , myKey, myIV, ciphertxt, bit_mode);
                
            
                outfp = openFile(output_file, "wb");
                
                fwrite(ciphertxt, sizeof(char), ciphertext_length, outfp);
                
                
                fclose(outfp);
                fclose(fp);
                break;
            case 1:
                /* decrypt */
                printf("-- Mode: DECRYPT\n");
                fp = openFile(input_file, "rb");
                
                fseek(fp, 0L, SEEK_END);
                lSize = ftell(fp);
                fseek(fp, 0L, SEEK_SET);
                
                
                ciphertxt = malloc (sizeof(char) * lSize);
                if (ciphertxt == NULL){
                    fprintf(stderr, "Memory error");
                    exit(2);
                }
                
                result = fread(ciphertxt, sizeof(char), lSize, fp);
                if (result != lSize){
                    fprintf(stderr, "Reading error");
                    exit(3);   
                }
                
            
                ciphertext_length = ((int)(lSize / BLOCK_SIZE) + 1) * BLOCK_SIZE;
                
                plaintext = malloc (ciphertext_length);
                plaintext_length = decrypt(ciphertxt, lSize, myKey, myIV, plaintext, bit_mode);
                
                
                outfp = openFile(output_file, "wb");
                
                
                fwrite(plaintext, sizeof(char), plaintext_length, outfp);
                
                
                fclose(outfp);
                fclose(fp);
                
                break;
                
            case 2:
                /* sign */
                printf("-- Mode: SIGN\n");
                fp = openFile(input_file, "rb");
                
                fseek(fp, 0L, SEEK_END);
                lSize = ftell(fp);
                fseek(fp, 0L, SEEK_SET);
                
                plaintext = malloc (sizeof(char) * lSize);
                if (plaintext == NULL){
                    fprintf(stderr, "Memory error");
                    exit(2);
                }
                result = fread(plaintext, sizeof(char), lSize, fp);
                if (result != lSize){
                    fprintf(stderr, "Reading error");
                    exit(3);   
                }
                /*ENCRYPT plaintext*/
                
                ciphertext_length = ((int)(lSize / BLOCK_SIZE) + 1) * BLOCK_SIZE;
                ciphertxt = malloc (ciphertext_length * sizeof(char));
                
                encrypt(plaintext, lSize , myKey, myIV, ciphertxt, bit_mode);
                
                /* Generate cmac for plaintext*/
                cmac = malloc (BLOCK_SIZE * sizeof(char));
                gen_cmac(plaintext, lSize, myKey, cmac, bit_mode);
                printf("cmac: \n");
                print_hex(cmac, 16);
                
                outfp = openFile(output_file, "wb");
                
                /*write encrypted message and cmac*/
                fwrite(ciphertxt, sizeof(char), ciphertext_length, outfp);
                fwrite(cmac, sizeof(char), 16, outfp);
                
                fclose(outfp);
                fclose(fp);
                
                break;
                
            case 3:
                /* verify */
                printf("-- Mode: VERIFY\n");
	
                fp = fopen(input_file, "rb");
        
                if (fp == NULL){
                    fprintf(stderr, "File error");
                    exit(1);
                }
                fseek(fp, 0L, SEEK_END);
                lSize = ftell(fp);
                fseek(fp, 0L, SEEK_SET);
                
                
                cipher_with_cmac = malloc (sizeof(char) * lSize);
                if (cipher_with_cmac == NULL){
                    fprintf(stderr, "Memory error");
                    exit(2);
                }
                
                result = fread(cipher_with_cmac, sizeof(char), lSize, fp);
                if (result != lSize){
                    fprintf(stderr, "Reading error");
                    exit(3);   
                }
                
                ciphertext_length = ((int)((lSize) / BLOCK_SIZE) + 1) * BLOCK_SIZE;
                
                plaintext = malloc (ciphertext_length);
                /*decrypt text without cmac*/
                plaintext_length = decrypt(cipher_with_cmac, lSize - BLOCK_SIZE, myKey, myIV, plaintext, bit_mode);
                
                /*cipher text cmac*/
                ciphers_mac = malloc (BLOCK_SIZE * sizeof(char));
                fseek(fp, -16L, SEEK_END);
                res = fread(ciphers_mac, sizeof(char), BLOCK_SIZE, fp);
                if (res != BLOCK_SIZE){
                    fprintf(stderr, "Reading error");
                    exit(3);   
                }
                
                printf("Ciphertext CMAC: \n");
                print_hex(ciphers_mac, BLOCK_SIZE);
                
                /* Generate cmac for plaintext */
                cmac = malloc (BLOCK_SIZE * sizeof(char));
                gen_cmac(plaintext, plaintext_length, myKey, cmac, bit_mode);
                
                printf("gen_cmac: \n");
                print_hex(cmac, BLOCK_SIZE);
                
                if(verify_cmac(ciphers_mac, cmac) == 1){
                    printf("Verified\n");
                    outfp = openFile(output_file, "wb");
                
                    /*write decrypted message if varified*/
                    fwrite(plaintext, sizeof(char), plaintext_length, outfp);
                    
                    fclose(outfp);
                }
                else{
                    printf("Not verified\n");
                }
                
                
                fclose(fp);
                        
                break;
            default:
                printf("error");

            
        }
        
        
	
	

		

	/* Clean up */
        EVP_cleanup();
        ERR_free_strings();
        
	free(input_file);
	free(output_file);
	free(password);


	/* END */
	return 0;
}
