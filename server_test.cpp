// server_c++.cpp
#include "test.h"
#include <iostream>
#include <string>
#include <sstream>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define PORT 8080
#define BACKLOG 5

std::string readHtmlFile(const std::string& filename) {
    std::ifstream file(filename);
    std::stringstream buffer;
    
    if (file.is_open()) {
        buffer << file.rdbuf();
        file.close();
        return buffer.str();
    } else {
        std::cerr << "Error: Unable to open file " << filename << std::endl;
        return "<!DOCTYPE html><html><body><h1>Error loading page</h1></body></html>";
    }
}

void handle_request(int client_socket) {
    static PropertyManagementSystem pms;
    char buffer[1024] = {0};
    string response;

    read(client_socket, buffer, sizeof(buffer) - 1);
    string request(buffer);

    if (strstr(buffer, "GET / HTTP/1.1")) {
        string html_content = readHtmlFile("test_frontend.html");
        response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Type: text/html\r\n";
        response += "Connection: close\r\n\r\n";
        response += html_content;
    }
    else if (strstr(buffer, "POST /login")) {
        std::cout << "Received login request" << std::endl;
        
        const int BUFFER_SIZE = 4096;
        char request_buffer[BUFFER_SIZE] = {0};
        int total_bytes = 0;
        int bytes_received = 0;
        std::string complete_request;

        complete_request = std::string(buffer);
        
        std::string content_length_header = "Content-Length: ";
        size_t content_length_pos = complete_request.find(content_length_header);
        int content_length = 0;
        
        if (content_length_pos != std::string::npos) {
            size_t content_length_end = complete_request.find("\r\n", content_length_pos);
            std::string content_length_str = complete_request.substr(
                content_length_pos + content_length_header.length(),
                content_length_end - (content_length_pos + content_length_header.length())
            );
            content_length = std::stoi(content_length_str);
        }

        size_t header_end = complete_request.find("\r\n\r\n");
        if (header_end == std::string::npos) {
            std::cerr << "Could not find end of headers" << std::endl;
            response = "HTTP/1.1 400 Bad Request\r\n\r\n";
            send(client_socket, response.c_str(), response.size(), 0);
            return;
        }

        std::string post_data = complete_request.substr(header_end + 4);
        
        while (post_data.length() < content_length) {
            bytes_received = recv(client_socket, request_buffer, BUFFER_SIZE - 1, 0);
            if (bytes_received <= 0) break;
            post_data += std::string(request_buffer, bytes_received);
            memset(request_buffer, 0, BUFFER_SIZE);
        }

        std::string username, password;
        try {
            size_t username_pos = post_data.find("username=");
            size_t password_pos = post_data.find("password=");

            if (username_pos != std::string::npos && password_pos != std::string::npos) {
                username_pos += 9;
                password_pos += 9;

                size_t username_end = post_data.find("&", username_pos);
                size_t password_end = post_data.find("&", password_pos);
                if (password_end == std::string::npos) {
                    password_end = post_data.length();
                }

                username = post_data.substr(username_pos, username_end - username_pos);
                password = post_data.substr(password_pos, password_end - password_pos);

                std::cout << "Login attempt for username: " << username << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "Error parsing login data: " << e.what() << std::endl;
            response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n";
            response += "{\"status\":\"error\",\"message\":\"Invalid login data format\"}";
            send(client_socket, response.c_str(), response.size(), 0);
            return;
        }

        bool success = pms.userLogin(username, password);
        
        if (success) {
            response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n";
            response += "{\"status\":\"success\",\"message\":\"Login successful\"}";
        } else {
            response = "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\r\n";
            response += "{\"status\":\"error\",\"message\":\"Invalid username or password\"}";
        }
    }
    else if (strstr(buffer, "POST /signup")) {
        std::cout << "Received signup request" << std::endl;
        
        const int BUFFER_SIZE = 4096;
        char request_buffer[BUFFER_SIZE] = {0};
        int total_bytes = 0;
        int bytes_received = 0;
        std::string complete_request;

        complete_request = std::string(buffer);
        
        std::string content_length_header = "Content-Length: ";
        size_t content_length_pos = complete_request.find(content_length_header);
        int content_length = 0;
        
        if (content_length_pos != std::string::npos) {
            size_t content_length_end = complete_request.find("\r\n", content_length_pos);
            std::string content_length_str = complete_request.substr(
                content_length_pos + content_length_header.length(),
                content_length_end - (content_length_pos + content_length_header.length())
            );
            content_length = std::stoi(content_length_str);
        }

        size_t header_end = complete_request.find("\r\n\r\n");
        if (header_end == std::string::npos) {
            std::cerr << "Could not find end of headers" << std::endl;
            response = "HTTP/1.1 400 Bad Request\r\n\r\n";
            send(client_socket, response.c_str(), response.size(), 0);
            return;
        }

        std::string post_data = complete_request.substr(header_end + 4);
        
        while (post_data.length() < content_length) {
            bytes_received = recv(client_socket, request_buffer, BUFFER_SIZE - 1, 0);
            if (bytes_received <= 0) break;
            post_data += std::string(request_buffer, bytes_received);
            memset(request_buffer, 0, BUFFER_SIZE);
        }

        std::cout << "Complete POST data: " << post_data << std::endl;

        std::string username, password, role;
        try {
            size_t username_pos = post_data.find("username=");
            size_t password_pos = post_data.find("password=");
            size_t role_pos = post_data.find("userType=");

            if (username_pos != std::string::npos && password_pos != std::string::npos && role_pos != std::string::npos) {
                username_pos += 9;
                password_pos += 9;
                role_pos += 9;

                size_t username_end = post_data.find("&", username_pos);
                size_t password_end = post_data.find("&", password_pos);

                username = post_data.substr(username_pos, username_end - username_pos);
                password = post_data.substr(password_pos, password_end - password_pos);
                role = post_data.substr(role_pos);

                std::cout << "Parsed username: " << username << std::endl;
                std::cout << "Parsed role: " << role << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "Error parsing POST data: " << e.what() << std::endl;
            response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n";
            response += "{\"status\":\"error\",\"message\":\"Invalid data format\"}";
            send(client_socket, response.c_str(), response.size(), 0);
            return;
        }

        if (username.empty() || password.empty() || role.empty()) {
            std::cerr << "Missing required fields" << std::endl;
            response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n";
            response += "{\"status\":\"error\",\"message\":\"Missing required fields\"}";
            send(client_socket, response.c_str(), response.size(), 0);
            return;
        }

        bool success = pms.createAccount(username, password, role);
        
        if (success) {
            response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n";
            response += "{\"status\":\"success\",\"message\":\"Account created successfully\"}";
        } else {
            response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n";
            response += "{\"status\":\"error\",\"message\":\"Failed to create account\"}";
        }
    }
    else if (strstr(buffer, "POST /maintenance")) {
        string postData = request.substr(request.find("\r\n\r\n") + 4);
        size_t idPos = postData.find("tenant_id=") + 10;
        size_t descPos = postData.find("description=") + 12;
        size_t idEnd = postData.find("&", idPos);
        
        int tenantId = stoi(postData.substr(idPos, idEnd - idPos));
        string description = postData.substr(descPos);

        pms.submitMaintenanceRequest(tenantId, description);

        response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Type: text/html\r\n";
        response += "Connection: close\r\n\r\n";
        response += "<html><body>";
        response += "<h1>Maintenance Request Submitted!</h1>";
        response += "<a href='/'>Back to Home</a>";
        response += "</body></html>";
    }
    else {
        response = "HTTP/1.1 404 Not Found\r\n";
        response += "Content-Type: text/html\r\n";
        response += "Connection: close\r\n\r\n";
        response += "<html><body><h1>404 Not Found</h1></body></html>";
    }

    send(client_socket, response.c_str(), response.size(), 0);
    close(client_socket);
}

int main() {
    int server_socket, client_socket;
    struct sockaddr_in server_addr;
    socklen_t client_len;
    struct sockaddr_in client_addr;

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        std::cerr << "Failed to create socket." << std::endl;
        return 1;
    }

    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::cerr << "Failed to set socket options." << std::endl;
        close(server_socket);
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (::bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Failed to bind to port." << std::endl;
        close(server_socket);
        return 1;
    }

    if (listen(server_socket, BACKLOG) < 0) {
        std::cerr << "Listen failed." << std::endl;
        close(server_socket);
        return 1;
    }

    std::cout << "Server running on port " << PORT << "..." << std::endl;

    client_len = sizeof(client_addr);
    while (true) {
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket < 0) {
            std::cerr << "Failed to accept connection." << std::endl;
            continue;
        }

        handle_request(client_socket);
    }

    close(server_socket);
    return 0;
}