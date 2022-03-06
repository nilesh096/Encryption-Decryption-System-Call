#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <openssl/md5.h>
#include <sys/syscall.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#ifndef __NR_cryptocopy
#error cryptocopy system call not defined
#endif

typedef struct argument
{
    char* outfile;
    char* infile;
    unsigned char flag;
    void* keybuf;
    int keylen;
}arguments;

void help()
{
	printf("Usage: ./test_cryptocopy {-e|-d|-c} -p <password> inputfile outputfile\n");
	printf("-c: Copy the input file to output file\n\
	-e: Encrypt the input file to output file\n\
	-d: Decrypt the input file to output file\n\
	-p: Password to encrypt/decrypt ONLY; Should be greater than 6 characters\n\
	inputfile: file to encrypt/decrypt/copy\n\
	outputfile: file to have the contents after encrypt/decrypt/copy\n\
	Please specify only of the options of -e|-d|-c\n");
}

void generate_md5_hash(char* str, unsigned char* digest)
{
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, str, strlen(str));
    MD5_Final(digest, &ctx);
}

int checkpassword(char *pass, arguments *args)
{
	unsigned char digest[16];
	if (strlen(pass) < 6)
	{	
		printf("Please provide a password greater than 6 characters\n\
		Try 'test_cryptocopy -h'\n");
		return -1;
	}
	generate_md5_hash(pass, digest);
	args->keybuf = malloc(16);
	memcpy(args->keybuf, (void *)digest, 16);
	return 0;
}

int main(int argc, char *argv[])
{
	int opt, rc = 0, ret = 0;
	arguments *args = (arguments *)malloc(sizeof(arguments));
	int edc = 0;

	args->flag = 0;

	if (args == NULL)
	{
		printf("ERROR: Unable to allocate memory to structure\n");
		rc = -1;
		goto out;
	}

	while((opt = getopt(argc, argv, "dechp:?")) != -1)
	{
		switch(opt)
		{
			case 'd':
				args->flag = (unsigned char)0x02;
				edc += 1;
				break;

			case 'e':
				args->flag = (unsigned char)0x01;
				edc += 1;
				break;

			case 'c':
				args->flag = (unsigned char)0x04;
				edc += 1;
				break;
				
			case 'h':
				help();
				goto out;
			
			case 'p':
				if (optarg == NULL)
				{
					printf("Password can't be empty\n\
					Try 'test_cryptocopy -h'\n");
					rc = -1;
					goto out;
				}
				args->keybuf = NULL;
				ret = checkpassword(optarg, args);
				if (ret == -1)
				{
					rc = -1;
					goto out;
				}
				args->keylen = 16;
				break;
			
			case '?':
				printf("Unknown option %s provided\n\
				Try 'test_cryptocopy -h'\n",argv[optind-1]);
				rc = -1;
				goto out;
		}
	}

	args->infile = NULL;
	args->outfile = NULL;

	if (edc == 0)
	{
		printf("Please provide one of the options of encrypt/decrypt/copy\n\
		Try 'test_cryptocopy -h'\n");
		rc = -1;
		goto out;
	}

	if (args->keybuf != NULL)
	{
		if (args->flag == 0x04)
		{
			printf("Password can't be provided with copy option\n\
			Try 'test_cryptocopy -h'\n");
			rc = -1;
			goto out;
		}
	}

	if (args->keybuf == NULL)
	{
		if (!((args->flag != 0x01) && (args->flag != 0x02)))
		{
			printf("Password can't be empty with encrypt/decrypt options\n\
			Try 'test_cryptocopy -h'\n");
			rc = -1;
			goto out;
		}
	}


	if (optind >= argc)
	{
		printf("Input file not specified\n\
		Try 'test_cryptocopy -h'\n");
		rc = -1;
		goto out;
	}
	else
	{
		if (argv[optind][0] == '\0') 
		{
			printf("Input file name is empty or null\n\
			Please provide a valid name\n\
			Try 'test_cryptocopy -h'\n");
			rc = -1;
			goto out;
		}
		args->infile = argv[optind];
	}

	if(optind + 1 >= argc)
	{
		printf("Output file not provided\n\
		Try 'test_cryptocopy -h'\n");
		rc = -1;
		goto out;
	}
	else
	{
		if (argv[optind + 1][0] == '\0') 
		{
			printf("Output file name is empty or null\n\
			Please provide a valid name\n\
			Try 'test_cryptocopy -h'\n");
			rc = -1;
			goto out;
		}
		args->outfile = argv[optind + 1];
	}

	if (edc > 1)
	{
		printf("More than one option of encrypt/decrypt/copy provided\n\
		Try 'test_cryptocopy -h'\n");
		rc = -1;
		goto out;
	}

	rc = syscall(__NR_cryptocopy, args);
	if (rc == 0)
		printf("syscall returned %d\n", rc);
	else
		printf("syscall returned %d (errno=%d)\n", rc, errno);

out:
	if (args->keybuf)
		free(args->keybuf);
	if (args)
		free(args);
	exit(rc);
}
