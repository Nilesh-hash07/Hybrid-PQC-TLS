/**
 * hybrid_tls_client.c - Hybrid TLS Client
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/obj_mac.h>

#define SERVER "127.0.0.1"
#define PORT 4433
#define BUFFER_SIZE 4096

/* Load default provider and OQS provider */
int load_providers(void) {
    OSSL_PROVIDER *default_prov;
    OSSL_PROVIDER *oqs_prov;
    
    /* Load default provider first */
    default_prov = OSSL_PROVIDER_load(NULL, "default");
    if (!default_prov) {
        fprintf(stderr, "Failed to load default provider\n");
        return 0;
    }
    
    /* Try to load OQS provider */
    oqs_prov = OSSL_PROVIDER_load(NULL, "oqsprovider");
    if (!oqs_prov) {
        oqs_prov = OSSL_PROVIDER_load(NULL, "/opt/openssl-3.5/lib64/ossl-modules/oqsprovider.so");
    }
    
    return 1;
}

/* Get curve name from ID */
const char* get_curve_name(int nid) {
    /* Try to get the name from OpenSSL's built-in database */
    const char *name = OBJ_nid2sn(nid);
    if (name) return name;
    
    /* Common NIDs for hybrid groups */
    switch(nid) {
        case 29: return "X25519";
        case 412: return "X25519MLKEM768";
        case 413: return "P256MLKEM768";
        case 0x100016C: return "X25519MLKEM768";
        case 0x100016D: return "X448MLKEM1024";
        case 0x100016E: return "SecP256r1MLKEM768";
        case 0x100016F: return "SecP384r1MLKEM1024";
        default: {
            static char buf[50];
            snprintf(buf, sizeof(buf), "HYBRID(0x%X)", nid);
            return buf;
        }
    }
}

int main() {
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int sockfd = -1;
    struct sockaddr_in addr;
    char buffer[BUFFER_SIZE];
    
    printf("\n========================================\n");
    printf("  Hybrid TLS Client\n");
    printf("========================================\n\n");
    
    /* Initialize OpenSSL */
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    
    /* Load providers */
    printf("[1/5] Loading providers... ");
    fflush(stdout);
    if (load_providers()) {
        printf("OK\n");
    } else {
        printf("FAILED\n");
        goto cleanup;
    }
    
    /* Create SSL context */
    printf("[2/5] Creating SSL context... ");
    fflush(stdout);
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        printf("FAILED\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    printf("OK\n");
    
    /* Force TLS 1.3 */
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    
    /* Set cipher list */
    SSL_CTX_set_cipher_list(ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");
    
    /* Offer hybrid groups */
    printf("[3/5] Offering X25519+ML-KEM-768... ");
    fflush(stdout);
    
    const char *groups = "X25519MLKEM768:X25519:P-256";
    if (SSL_CTX_set1_groups_list(ctx, groups) == 1) {
        printf("OK\n");
    } else {
        printf("FAILED\n");
    }
    
    /* Skip cert verification for demo */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    
    /* Create socket and connect */
    printf("[4/5] Connecting to %s:%d... ", SERVER, PORT);
    fflush(stdout);
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        printf("FAILED\n");
        perror("socket");
        goto cleanup;
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = inet_addr(SERVER);
    
    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        printf("FAILED\n");
        perror("connect");
        goto cleanup;
    }
    printf("OK\n");
    
    /* Create SSL */
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    
    /* Handshake */
    printf("[5/5] Performing TLS handshake... ");
    fflush(stdout);
    
    if (SSL_connect(ssl) == 1) {
        printf("SUCCESS\n\n");
        
        const char *cipher = SSL_get_cipher_name(ssl);
        const char *version = SSL_get_version(ssl);
        int curve_nid = SSL_get_negotiated_group(ssl);
        const char *curve = get_curve_name(curve_nid);
        
        printf("=== Connection Established ===\n");
        printf("Protocol: %s\n", version);
        printf("Cipher: %s\n", cipher);
        printf("Key exchange: %s (NID: %d/0x%X)\n", curve, curve_nid, curve_nid);
        
        if (curve_nid == 412 || curve_nid == 0x100016C) {
            printf("→ HYBRID ACTIVE (X25519 + ML-KEM-768)\n");
        }
        
        /* Send request */
        char request[] = "GET / HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "Connection: close\r\n"
                         "\r\n";
        
        SSL_write(ssl, request, strlen(request));
        
        /* Read response */
        printf("\n--- Server Response ---\n");
        int bytes;
        while ((bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0) {
            buffer[bytes] = '\0';
            printf("%s", buffer);
        }
        printf("\n----------------------\n");
        
    } else {
        printf("FAILED\n");
        ERR_print_errors_fp(stderr);
    }
    
cleanup:
    if (ssl) SSL_free(ssl);
    if (sockfd >= 0) close(sockfd);
    if (ctx) SSL_CTX_free(ctx);
    
    return 0;
}
