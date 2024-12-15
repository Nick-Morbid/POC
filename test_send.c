#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

void test_send(const char *ip, int port) {
    int sock;
    struct sockaddr_in server;
    char message[1024] = "Hello from client!";
    char buffer[1024] = {0};

    // 创建套接字
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("Socket creation failed");
        return;
    }
    printf("Socket created successfully.\n");

    // 设置服务器地址
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &server.sin_addr) <= 0) {
        perror("Invalid IP address or address not supported");
        close(sock);
        return;
    }

    // 连接到服务器
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("Connection failed");
        close(sock);
        return;
    }
    printf("Connected to %s:%d\n", ip, port);

    // 发送测试消息
    if (send(sock, message, strlen(message), 0) < 0) {
        perror("Send failed");
        close(sock);
        return;
    }
    printf("Message sent: %s\n", message);

    // 接收服务器响应（如果有）
    ssize_t received = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (received > 0) {
        buffer[received] = '\0';
        printf("Server response: %s\n", buffer);
    } else if (received == 0) {
        printf("Connection closed by server.\n");
    } else {
        perror("Receive failed");
    }

    // 关闭套接字
    close(sock);
    printf("Connection closed.\n");
}

int main() {
    const char *ip = "192.168.1.7"; // 目标 IP
    int port = 22;                 // 目标端口 (SSH 默认端口)

    printf("Testing connection to %s:%d...\n", ip, port);
    test_send(ip, port);

    return 0;
}
