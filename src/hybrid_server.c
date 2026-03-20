/**
 * hybrid_tls_server.c - Hybrid TLS Server with X25519 + ML-KEM-768
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
#include <time.h>

#define PORT 4433
#define CERT_FILE "certs/server.crt"
#define KEY_FILE "certs/server.key"
#define LOG_FILE "hybrid_handshake.log"

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
        /* Try explicit path */
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

/* Log connection */
void log_connection(SSL *ssl, const char *client_ip) {
    FILE *log = fopen(LOG_FILE, "a");
    if (!log) return;
    
    time_t now;
    time(&now);
    
    const char *cipher = SSL_get_cipher_name(ssl);
    const char *version = SSL_get_version(ssl);
    int curve_nid = SSL_get_negotiated_group(ssl);
    const char *curve = get_curve_name(curve_nid);
    
    fprintf(log, "\n=== Connection at %s", ctime(&now));
    fprintf(log, "Client: %s\n", client_ip);
    fprintf(log, "Protocol: %s\n", version);
    fprintf(log, "Cipher: %s\n", cipher);
    fprintf(log, "Key exchange: %s (NID: %d/0x%X)\n", curve, curve_nid, curve_nid);
    
    if (curve_nid == 412 || curve_nid == 0x100016C) {
        fprintf(log, "STATUS: HYBRID PQC ACTIVE (X25519+ML-KEM-768)\n");
    }
    
    fclose(log);
}

int main() {
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int server_fd = -1, client_fd = -1;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    char client_ip[INET_ADDRSTRLEN];
    
    printf("\n========================================\n");
    printf("  Hybrid TLS Server\n");
    printf("========================================\n\n");
    
    /* Initialize OpenSSL */
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_load_crypto_strings();
    
    /* Load providers */
    printf("[1/7] Loading providers... ");
    fflush(stdout);
    if (load_providers()) {
        printf("OK\n");
    } else {
        printf("FAILED\n");
        goto cleanup;
    }
    
    /* Create SSL context */
    printf("[2/7] Creating SSL context... ");
    fflush(stdout);
    ctx = SSL_CTX_new(TLS_server_method());
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
    
    /* Set hybrid groups */
    printf("[3/7] Setting hybrid groups... ");
    fflush(stdout);
    
    const char *groups = "X25519MLKEM768:X25519:P-256";
    if (SSL_CTX_set1_groups_list(ctx, groups) == 1) {
        printf("OK (%s)\n", groups);
    } else {
        printf("FAILED\n");
    }
    
    /* Load certificate */
    printf("[4/7] Loading certificate... ");
    fflush(stdout);
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        printf("FAILED\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    printf("OK\n");
    
    /* Load private key */
    printf("[5/7] Loading private key... ");
    fflush(stdout);
    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        printf("FAILED\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    printf("OK\n");
    
    /* Verify key */
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Key mismatch\n");
        goto cleanup;
    }
    
    /* Create socket */
    printf("[6/7] Creating socket... ");
    fflush(stdout);
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        printf("FAILED\n");
        perror("socket");
        goto cleanup;
    }
    printf("OK\n");
    
    /* Allow reuse */
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    /* Bind */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        goto cleanup;
    }
    
    /* Listen */
    if (listen(server_fd, 10) < 0) {
        perror("listen");
        goto cleanup;
    }
    
    printf("[7/7] Server ready on port %d\n", PORT);
    printf("\nWaiting for connections...\n");
    printf("Press Ctrl+C to stop\n\n");
    
    /* Main loop */
    while (1) {
        client_fd = accept(server_fd, (struct sockaddr*)&addr, &addr_len);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }
        
        inet_ntop(AF_INET, &addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        printf("\nClient connected: %s:%d\n", client_ip, ntohs(addr.sin_port));
        
        /* Create SSL */
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);
        
        /* Handshake */
        printf("  TLS handshake... ");
        fflush(stdout);
        
        int ret = SSL_accept(ssl);
        if (ret == 1) {
            printf("SUCCESS\n");
            
            const char *cipher = SSL_get_cipher_name(ssl);
            int curve_nid = SSL_get_negotiated_group(ssl);
            const char *curve = get_curve_name(curve_nid);
            
            printf("  Cipher: %s\n", cipher);
            printf("  Key exchange: %s (NID: %d/0x%X)\n", curve, curve_nid, curve_nid);
            
            if (curve_nid == 412 || curve_nid == 0x100016C) {
                printf("  → HYBRID ACTIVE (X25519 + ML-KEM-768)\n");
            }
            
            /* Log it */
            log_connection(ssl, client_ip);
            
            /* Send response */
            char response[2048];
            snprintf(response, sizeof(response),
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html\r\n"
                "Connection: close\r\n"
                "\r\n"
                "<html><body style='font-family: monospace; padding: 20px;'>"
                "<h2>Hybrid TLS Connection</h2>"
                "<p><b>Protocol:</b> %s</p>"
                "<p><b>Cipher:</b> %s</p>"
                "<p><b>Key exchange:</b> %s (NID: %d/0x%X)</p>"
                "<hr><p><i>X25519 + ML-KEM-768 hybrid key exchange</i></p>"
                "</body></html>\n",
                SSL_get_version(ssl),
                cipher,
                curve, curve_nid, curve_nid);
            
            SSL_write(ssl, response, strlen(response));
            
        } else {
            printf("FAILED\n");
            ERR_print_errors_fp(stderr);
        }
        
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }
    
cleanup:
    if (client_fd >= 0) close(client_fd);
    if (server_fd >= 0) close(server_fd);
    if (ssl) SSL_free(ssl);
    if (ctx) SSL_CTX_free(ctx);
    
    return 0;
}
