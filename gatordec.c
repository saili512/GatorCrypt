/*
 * gatordec.c
 *
 *  Created on: Sep 15, 2014
 *      Author: saili
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/stat.h>
#include <gcrypt.h>
#include <errno.h>

void printError(const char *msg) {
	perror(msg);
	exit(0);
}

void gcryptError(gcry_error_t errorCode, const char *msg) {
	printf("%s Operation failed : %s/%s\n", msg, gcry_strsource(errorCode),
			gcry_strerror(errorCode));
	exit(0);
}

int main(int argc, char *argv[]) {

	char *filename;
	char *fileContents;
	unsigned char *rcvdHash, *calcdHash;
	struct stat st;
	int sizeOfFile;
	FILE *fptr;
	char *tempfileName = "encFile";

	char password[20];
	char *keybuffer;
	unsigned long iterations = 4096;
	int iv[4] = { 5, 8, 4, 4 };
	gcry_error_t errorCode;
	gcry_cipher_hd_t hd;
	gcry_md_hd_t hd2;

	int socketFd, newSocketFd;

	if (argc < 3) {
		fprintf(stderr, "usage %s <file-name> [-d <port>] [-l]\n", argv[0]);
		exit(0);
	}

	filename = argv[1];

	// if -d option is given the receive the file contents and save them locally and later decrypt them
	if (!strcmp(argv[2], "-d")) {
		int portNo, n, n1;
		socklen_t clientLen;
		char buffer[256];
		struct sockaddr_in serverAddr, clientAddr;

		fptr = fopen(tempfileName, "w");
		if (fptr == NULL) {
			printError("Cannot open file \n");
		}

		socketFd = socket(AF_INET, SOCK_STREAM, 0);
		if (socketFd < 0)
			printError("ERROR opening socket");
		bzero((char *) &serverAddr, sizeof(serverAddr));
		portNo = atoi(argv[3]);
		serverAddr.sin_family = AF_INET;
		serverAddr.sin_addr.s_addr = INADDR_ANY;
		serverAddr.sin_port = htons(portNo);
		printf("Waiting for connections..\n");
		if (bind(socketFd, (struct sockaddr *) &serverAddr, sizeof(serverAddr))
				< 0)
			printError("ERROR on binding");
		listen(socketFd, 5);
		clientLen = sizeof(clientAddr);
		newSocketFd = accept(socketFd, (struct sockaddr *) &clientAddr,
				&clientLen);
		printf("Inbound file..\n");
		if (newSocketFd < 0)
			printError("ERROR on accept");
		while (1) {
			bzero(buffer, 256);
			n = read(newSocketFd, buffer, 255);
			if (n < 0)
				printError("ERROR reading from socket");
			if (n == 0)
				break;
			n1 = fwrite(buffer, sizeof(char), n, fptr);
		}
		fclose(fptr);
	}

	//Read password from user

	printf("%s", "Password:");
	scanf("%s", password);

	//Read from file (at this point a file will exist either locally or via network transfer)
	if (!strcmp(argv[2], "-l")) {
		fptr = fopen(filename, "r");
		if (fptr == NULL) {
			printError("Cannot open file \n");
		}
		stat(filename, &st);
		sizeOfFile = st.st_size;
	} else if (!strcmp(argv[2], "-d")) {
		fptr = fopen(tempfileName, "r");
		if (fptr == NULL) {
			printError("Cannot open file \n");
		}
		stat(tempfileName, &st);
		sizeOfFile = st.st_size;
	}

	int newSize = sizeOfFile - 64;
	fileContents = (char *) malloc(newSize * sizeof(char)); //initialize buffer to file size
	fread(fileContents, sizeof(char), newSize, fptr); //read data from file into buffer
	rcvdHash = (unsigned char *) malloc(64 * sizeof(unsigned char));
	fread(rcvdHash, sizeof(unsigned char), 64, fptr); //read hash from file into buffer
	fclose(fptr);

	//initialize libgcrypt and decrypt contents from buffer

	if (!gcry_check_version(GCRYPT_VERSION)) {
		fputs("libgcrypt version mismatch\n", stderr);
		exit(2);
	}

	//Disable secure memory.
	errorCode = gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
	if (errorCode) {
		gcryptError(errorCode, "disable secure mem");
	}
	//... If required, other initialization goes here.

	//Tell Libgcrypt that initialization has completed.
	errorCode = gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
	if (errorCode) {
		gcryptError(errorCode, "initialization");
	}

	keybuffer = (char *) malloc(16 * sizeof(char));
	errorCode = gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2,
			GCRY_MD_SHA512, "NaCl", strlen("NaCl"), iterations, 16, keybuffer);
	if (errorCode) {
		gcryptError(errorCode, "key derivation");
	}
	// print key in hexadecimal format
	int i;
	printf("Key : ");
	for (i = 0; i < 16; i++) {
		printf("%02X ", (unsigned char) keybuffer[i]);
	}
	printf("\n");

	//HMAC the encrypted contents

	errorCode = gcry_md_open(&hd2, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC);
	if (errorCode) {
		gcryptError(errorCode, "open context handle for HMAC");
	}
	errorCode = gcry_md_setkey(hd2, keybuffer, 16);
	if (errorCode) {
		gcryptError(errorCode, "set key for HMAC");
	}
	gcry_md_write(hd2, fileContents, newSize);
	if (errorCode) {
		gcryptError(errorCode, "Update digest");
	}
	int dlen = gcry_md_get_algo_dlen(GCRY_MD_SHA512);
	calcdHash = (unsigned char*) malloc(dlen * sizeof(unsigned char));
	calcdHash = gcry_md_read(hd2, 0);
	if (errorCode) {
		gcryptError(errorCode, "read digest");
	}

	//compare calculated and received hash for the encrypted data for authentication
	for (i = 0; i < 64; i++) {
		if (*(rcvdHash + i) != *(calcdHash + i)) {
			printf("HMAC authentication failed!!\n");
			exit(62);
		}
	}

	errorCode = gcry_cipher_open(&hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC,
			GCRY_CIPHER_CBC_CTS); // aes128 in CBC mode with ciphertext stealing
	if (errorCode) {
		gcryptError(errorCode, "open context handle");
	}
	errorCode = gcry_cipher_setkey(hd, keybuffer, 16);
	if (errorCode) {
		gcryptError(errorCode, "set key");
	}
	errorCode = gcry_cipher_setiv(hd, iv, sizeof(iv));
	if (errorCode) {
		gcryptError(errorCode, "set IV");
	}
	errorCode = gcry_cipher_decrypt(hd, fileContents, newSize,
	NULL, 0);
	if (errorCode) {
		gcryptError(errorCode, "decryption");
	}

	//write contents to a file without .uf extension

	if (!strcmp(argv[2], "-l")) {
		for (i = strlen(filename) - 3; i < strlen(filename); i++) {
			filename[i] = '\0';
		}
	}
	fptr = fopen(filename, "wx"); //file named without .uf extension
	if (fptr == NULL && errno == EEXIST) {
		printError("File already exists");
		return 33;
	}

	fwrite(fileContents, sizeof(char), newSize, fptr);
	fclose(fptr);

	free(fileContents);
	free(keybuffer);
	close(socketFd);
	close(newSocketFd);
	if (!strcmp(argv[2], "-d")) {
		remove(tempfileName);
	}
	printf("Succesfully decrypted %s (%i bytes written)\n", filename, newSize);
	return 0;
}
