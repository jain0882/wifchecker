#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <ctype.h>
#include "openssl/sha.h"
#include "wif_checker.h"
#include "threadpool.h"
#include "queue.h"

const char* pSuffix = "5bCRZhiS5sEGMpmcRZdpAhmWLRfMmutGmPHtjVob";
const char *base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

#define uint32_t_bits (sizeof(uint32_t) * 8)
static const uint64_t uint32_t_mask = ((((uint64_t)1) << uint32_t_bits) - 1);

static const int8_t b58digits_map[] = {
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
	-1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
	22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
	-1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
	47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
};

typedef struct ThreadArgs_ {
	FILE* pFile1;
	FILE* pFile2;
	FILE* pFile3;
	FILE* pFileOutput;
	pthread_mutex_t* pMutexFile1;
	pthread_mutex_t* pMutexOutputFile;
} ThreadArgs;

char* getBinRep(char ch) {
	switch(ch) {
		case '0':
			return "0000";
		case '1':
			return "0001";
		case '2':
			return "0010";
		case '3':
			return "0011";
		case '4':
			return "0100";
		case '5':
			return "0101";
		case '6':
			return "0110";
		case '7':
			return "0111";
		case '8':
			return "1000";
		case '9':
			return "1001";
		case 'A':
			return "1010";
		case 'B':
			return "1011";
		case 'C':
			return "1100";
		case 'D':
			return "1101";
		case 'E':
			return "1110";
		case 'F':
			return "1111";
	}
}

char getHexChar(char* pStr) {
	if(!strncmp(pStr, "0000", 4)) {
		return '0';
	} else if(!strncmp(pStr, "0001", 4)) {
		return '1';
	} else if(!strncmp(pStr, "0010", 4)) {
		return '2';
	} else if(!strncmp(pStr, "0011", 4)) {
                return '3';
        } else if(!strncmp(pStr, "0100", 4)) {
                return '4';
        } else if(!strncmp(pStr, "0101", 4)) {
                return '5';
        } else if(!strncmp(pStr, "0110", 4)) {
                return '6';
        } else if(!strncmp(pStr, "0111", 4)) {
                return '7';
        } else if(!strncmp(pStr, "1000", 4)) {
                return '8';
        } else if(!strncmp(pStr, "1001", 4)) {
                return '9';
        } else if(!strncmp(pStr, "1010", 4)) {
                return 'A';
        } else if(!strncmp(pStr, "1011", 4)) {
                return 'B';
        } else if(!strncmp(pStr, "1100", 4)) {
                return 'C';
        } else if(!strncmp(pStr, "1101", 4)) {
                return 'D';
        } else if(!strncmp(pStr, "1110", 4)) {
                return 'E';
        } else if(!strncmp(pStr, "1111", 4)) {
                return 'F';
        }
}

char* hexToBinStr(char* pStr) {
	char* pBinStr = (char *)malloc(strlen(pStr)*4) + 1;
	int j = 0;
	for(int i = 0; i < strlen(pStr); ++i) {
		char* pBinRep = getBinRep(toupper(pStr[i]));
		pBinStr[j++] = pBinRep[0];
		pBinStr[j++] = pBinRep[1];
		pBinStr[j++] = pBinRep[2];
		pBinStr[j++] = pBinRep[3];
	}

	pBinStr[j] = '\0';
}

char* decToHexStr(int* pStr, int size) {
	char* pHexStr = (char *)malloc(sizeof(char) * (2 *size + 1));
	int j = 0;
	for(int i = 0; i < size; i++) {
		sprintf((pHexStr + 2 * i), "%X", pStr[i]);;
	}
	pHexStr[2*size] = '\0';
	return pHexStr;
}

int indexOfBlockSize(int size) {
	static const int sizeArray[] = {0, 2, 3, 5, 6, 7, 9, 10, 11};
	for(int i = 0; i < 9; ++i) {
		if(size == sizeArray[i])
			return i;
	}
	return -1;
}

int* uint64_to_8_be(int num, int size) {
	int* pOutput = (int *)malloc(sizeof(int) * size);
	memset(pOutput, 0, sizeof(int) * size);
	for(int i = size -1; i >= 0; i--) {
		pOutput[i] = num % 256;
		num = num/256;
	}

	return pOutput;
}

bool base58_decode(const char *str, unsigned char *bytes) {
    int i, j, len = strlen(str), carry;
    unsigned char index;
    int num_bytes = 73;

    memset(bytes, 0, 74);

    for(i = 0; i < len; i++) {
	    const char* p = strchr(base58_chars, str[i]);
	    if(!p) {
		    return false;
	    }
	    carry = p - base58_chars;
	    
	    for(j = num_bytes; j >= 0; j--) {
		carry += 58 * bytes[j];
		bytes[j] = carry % 256;
		carry /= 256;
	    }
    }

    if(carry) 
    {
    	return false;
    }

    return true;
}

void convertToHex(unsigned char* pBytes, size_t size, char* pHexChars) {
	int j = 0;
	for(int i = 0; i < size; ++i) {
		int val = (int)pBytes[i];
        	int quotient = val / 16;
		int remainder = val % 16;

        	if (quotient < 10)
            		pHexChars[j++] = 48 + quotient;
        	else
            		pHexChars[j++] = 55 + quotient;

        	if (remainder < 10)
            		pHexChars[j++] = 48 + remainder;
        	else
            		pHexChars[j++] = 55 + remainder;
        	
	}
}

char* trimZeroFromLeft(char* pStr) {
	for(int i = 0; i < 128; ++i) {
		if(pStr[i] != '0') {
			return (pStr + i);
		}
	}

	return NULL;
}

bool verifyWIF(char* pStr) {
	unsigned char bytes[74];
	if(!base58_decode(pStr, bytes)) {
		return false;
	}

	char hexChars[148];
	convertToHex(bytes, 74, hexChars);
	printf("base58 decoded: %s\n", hexChars);
	char* pTrimStr = trimZeroFromLeft(hexChars);
	printf("converted hex: %s\n", pTrimStr);

	if((pTrimStr - hexChars) < 74) {
		return false;
	}

	char checksum[8];
	memcpy(checksum, pTrimStr + 66, 8);

	char privateKey[66];
	memcpy(privateKey, pTrimStr, 66);

	unsigned char hash[SHA256_DIGEST_LENGTH];
    	SHA256_CTX sha256;
    	SHA256_Init(&sha256);
    	SHA256_Update(&sha256, pTrimStr, 66);
    	SHA256_Final(hash, &sha256);
	char firstHash[64];

	int i = 0;
    	for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    	{
        	sprintf(firstHash + (i * 2), "%02x", hash[i]);
    	}

	printf("First Hash: %s\n", firstHash);
	unsigned char hash_1[SHA256_DIGEST_LENGTH];
    	SHA256_CTX sha256_1;
    	SHA256_Init(&sha256_1);
    	SHA256_Update(&sha256_1, firstHash, 64);
    	SHA256_Final(hash_1, &sha256_1);

	char secondHash[64];

    	for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    	{
        	sprintf(secondHash + (i * 2), "%02x", hash_1[i]);
    	}

	printf("Second Hash: %s\n", secondHash);

	if(!memcmp(checksum, secondHash, 8)) {
		return true;
	}

	return false;
}

void threadTask(void* pArgs)
{
	ThreadArgs* pThreadArgs = (ThreadArgs *)pArgs;
	while(1)
	{
		pthread_mutex_lock(pThreadArgs->pMutexFile1);
		if(feof(pThreadArgs->pFile1))
		{
			pthread_mutex_unlock(pThreadArgs->pMutexFile1);
			break;
		}
		char part1[6];
		fscanf(pThreadArgs->pFile1, "%s", part1);
		printf("part1: %s\n", part1);
		pthread_mutex_unlock(pThreadArgs->pMutexFile1);
		
		
		fseek(pThreadArgs->pFile2, 0, SEEK_SET);

		while(1) {
			if(feof(pThreadArgs->pFile2))
			{
				break;
			}

			char part2[5];
			fscanf(pThreadArgs->pFile2, "%s", part2);
			printf("part2: %s\n", part2);

			fseek(pThreadArgs->pFile3, 0, SEEK_SET);

			while(1) {
				if(feof(pThreadArgs->pFile3))
				{
					break;
				}
				char part3[4];
				fscanf(pThreadArgs->pFile3, "%s", part3);
				printf("part3: %s\n", part3);

				char str[53];
				memcpy(str, part1, 5);
				memcpy(str + 5, part2, 4);
				memcpy(str + 9, part3, 3);
				memcpy(str + 12, pSuffix, 40);
				str[52] = '\0';
				printf("Complete String: %s\n", str);
				if(verifyWIF(str)) {
					pthread_mutex_lock(pThreadArgs->pMutexOutputFile);
					fprintf(pThreadArgs->pFileOutput, "%s\n", str);
					pthread_mutex_unlock(pThreadArgs->pMutexOutputFile);
				}
			}
		}
	}

	fclose(pThreadArgs->pFile2);
	fclose(pThreadArgs->pFile3);
}

void showUsage() {
	printf("\nNeed inpute file names.\n");
	printf("wif_checker 1.txt 2.txt 3.txt\n");
}

int main(int argc, char** argv) {
	if(argc < 4 || argc > 4) {
		showUsage();
		return 0;
	}
	FILE* pFile1 = fopen(argv[1], "r");
	FILE* pFileOutput = fopen("output.txt", "w+");
	pthread_mutex_t mutexFile1;
	pthread_mutex_t mutexOutputFile;

	pthread_mutex_init(&mutexFile1, NULL);
	pthread_mutex_init(&mutexOutputFile, NULL);
	
	ThreadPool* pThreadPool = initThreadPool(true /*bAsPerCore */);
	for(int i = 0; i < pThreadPool->nThreadCount; ++i)
	{
		ThreadArgs* pArgs = (ThreadArgs *)malloc(sizeof(ThreadArgs));
		pArgs->pFile1 = pFile1;
		pArgs->pFile2 = fopen(argv[2], "r");
		pArgs->pFile3 = fopen(argv[3], "r");
		pArgs->pFileOutput = pFileOutput;
		pArgs->pMutexFile1 = &mutexFile1;
		pArgs->pMutexOutputFile = &mutexOutputFile;

		QueueNode* pNode = createWorkNode(threadTask, pArgs);

		pushNode(pNode, &(pThreadPool->pHead), &(pThreadPool->pTail), &(pThreadPool->queueMutex), &(pThreadPool->workCond));
	}

	destroyThreadPool(pThreadPool);

	fclose(pFile1);
	fclose(pFileOutput);

	pthread_mutex_destroy(&mutexFile1);
	pthread_mutex_destroy(&mutexOutputFile);
}
