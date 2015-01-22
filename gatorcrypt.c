/*
 * gatorcrypt.c
 *
 *  Created on: Sep 13, 2014
 *      Author: saili
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h> // for string manipulations
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/stat.h> // to get the filesize using stat function
#include <gcrypt.h> //required to use libgcrypt api
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
	struct stat st;
	int sizeOfFile;
	FILE *fptr;

	char password[20];
	char *keybuffer;
	unsigned char *hash;
	unsigned long iterations = 4096;
	int iv[4] = { 5, 8, 4, 4 };
	gcry_error_t errorCode;
	size_t keylen = gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES128);
	gcry_cipher_hd_t hd;
	gcry_md_hd_t hd2;

	int i;

	if (argc < 3) {
		fprintf(stderr, "usage %s <input-file> [-d <IP-addr:port>] [-l]\n",
				argv[0]);
		exit(0);
	}

	//Read user password

	printf("%s", "Password: ");
	scanf("%s", password);

	//Read input file into buffer fileContents
	filename = argv[1];
	fptr = fopen(filename, "r");
	if (fptr == NULL) {
		printError("Cannot open file \n");
	}

	stat(filename, &st); //this function returns the attributes of the file such as file size in the structure st
	sizeOfFile = st.st_size;
	fileContents = (char *) malloc(sizeOfFile * sizeof(char)); //initialize buffer to file size
	fread(fileContents, sizeof(char), sizeOfFile, fptr); //read from file into buffer
	fclose(fptr);

	//Initialize libgcrypt library,generate key,encryption context handle and encrypt the buffer

	if (!gcry_check_version(GCRYPT_VERSION)) {
		fputs("libgcrypt version mismatch\n", stderr);
		exit(2);
	}

	// Disable secure memory.
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

	keybuffer = (char *) malloc(16);
	errorCode = gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2,
			GCRY_MD_SHA512, "NaCl", strlen("NaCl"), iterations, 16, keybuffer);
	if (errorCode) {
		gcryptError(errorCode, "key derivation");
	}
	// print key in hexadecimal format
	printf("Key : ");
	for (i = 0; i < 16; i++) {
		printf("%02X ", (unsigned char) keybuffer[i]);
	}
	printf("\n");
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
	errorCode = gcry_cipher_encrypt(hd, fileContents, sizeOfFile,
	NULL, 0);
	if (errorCode) {
		gcryptError(errorCode, "encryption");
	}

	//HMAC the encrypted data
	errorCode = gcry_md_open(&hd2, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC);
	if (errorCode) {
		gcryptError(errorCode, "open context handle for HMAC");
	}
	errorCode = gcry_md_setkey(hd2, keybuffer, 16);
	if (errorCode) {
		gcryptError(errorCode, "set key for HMAC");
	}
	gcry_md_write(hd2, fileContents, sizeOfFile);
	if (errorCode) {
		gcryptError(errorCode, "Update digest");
	}
	int dlen = gcry_md_get_algo_dlen(GCRY_MD_SHA512);
	hash = (unsigned char*) malloc(dlen * sizeof(unsigned char));
	hash = gcry_md_read(hd2, 0);
	if (errorCode) {
		gcryptError(errorCode, "read digest");
	}

	//if argument is -l then write the encrypted contents and generated hash to a local file with additional .uf extension
	if (!strcmp(argv[2], "-l")) {
		strcat(filename, ".uf");
		fptr = fopen(filename, "wx");
		if (fptr == NULL && errno == EEXIST) {
			printf("File already exists\n");
			return 33;
		}
		int no = fwrite(fileContents, sizeof(char), sizeOfFile, fptr);
		no = fwrite(hash, sizeof(unsigned char), dlen, fptr);
		fclose(fptr);
		printf("Successfully encrypted input file to %s (%i bytes written)\n",
				filename, sizeOfFile + dlen);
	}
	//if argument is -d then send the encrypted contents and generated hash to the server
	else if (!strcmp(argv[2], "-d")) {

		int socketFd, portno, n;
		struct sockaddr_in serverAddress;
		struct hostent *server;
		struct in_addr ipv4addr;
		char *ipAddr;
		char *portNo;

		ipAddr = strtok(argv[3], ":"); //separate the ipAddr and portNo
		portNo = strtok(NULL, ":");

		portno = atoi(portNo);
		socketFd = socket(AF_INET, SOCK_STREAM, 0); //Create and open a socket
		if (socketFd < 0)
			printError("ERROR opening socket");
		inet_pton(AF_INET, ipAddr, &ipv4addr);
		server = gethostbyaddr(&ipv4addr, sizeof &ipv4addr, AF_INET); //get server details from IP address
		if (server == NULL) {
			printError("No such host exists\n");
		}
		bzero((char *) &serverAddress, sizeof(serverAddress));
		// Populate the serverAddress structure
		serverAddress.sin_family = AF_INET;
		bcopy((char *) server->h_addr,
		(char *)&serverAddress.sin_addr.s_addr,
		server->h_length);
		serverAddress.sin_port = htons(portno);
		if (connect(socketFd, (struct sockaddr *) &serverAddress, //establish a connection to the server
				sizeof(serverAddress)) < 0)
			printError("ERROR connecting");
		n = write(socketFd, fileContents, sizeOfFile);
		if (n < 0)
			printError("ERROR writing to socket");
		n = write(socketFd, hash, dlen);
		close(socketFd);
		printf(
				"Successfully encrypted %s and sent to server at %s (%i bytes transmitted)\n",
				filename, ipAddr, sizeOfFile + dlen);
	}

	free(fileContents);
	free(keybuffer);
	return 0;
}
