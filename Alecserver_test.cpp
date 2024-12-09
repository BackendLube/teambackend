// server_c++.cpp
// Server implementation for Property Management System
// Handles HTTP requests and client-server communication
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

// Server configuration constants
#define PORT 8080
#define BACKLOG 5  // Maximum length of pending connections queue

/**
 * Security Functions and Features
 */

// Reads HTML file content
// Security considerations:
// - Basic error handling for file operations
// - Returns fallback HTML on error
// - Could be enhanced with path validation to prevent directory traversal
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

// Security: Ensure buffer isn't overflowed during read
// Security: Parse and validate Content-Length
// Security: Validate request format
// Security: Clear buffer after use
void validateAndParseRequest(const std::string& request, std::string& post_data, int& content_length) {
    std::string content_length_header = "Content-Length: ";
    size_t content_length_pos = request.find(content_length_header);
    if (content_length_pos != std::string::npos) {
        size_t content_length_end = request.find("\r\n", content_length_pos);
        std::string content_length_str = request.substr(
            content_length_pos + content_length_header.length(),
            content_length_end - (content_length_pos + content_length_header.length())
        );
        content_length = std::stoi(content_length_str);
    }

    size_t header_end = request.find("\r\n\r\n");
    if (header_end == std::string::npos) {
        throw std::runtime_error("Could not find end of headers");
    }

    post_data = request.substr(header_end + 4);
}

// Validate presence of required fields
void validateRequiredFields(const std::string& post_data, const std::vector<std::string>& fields) {
    for (const auto& field : fields) {
        if (post_data.find(field + "=") == std::string::npos) {
            throw std::runtime_error("Missing required field: " + field);
        }
    }
}

/**
 * Main request handler function
 */
void handle_request(int client_socket) {
    static PropertyManagementSystem pms;
    char buffer[1024] = {0}; // prevents buffer overflow
    std::string response;

    read(client_socket, buffer, sizeof(buffer) - 1);
    std::string request(buffer);

    // Handle GET request for main page
    if (strstr(buffer, "GET / HTTP/1.1")) {
        std::string html_content = readHtmlFile("test_frontend.html");
        response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Type: text/html\r\n";
        response += "Connection: close\r\n\r\n";
        response += html_content;
    }
    // Handle login POST request
    else if (strstr(buffer, "POST /login")) {
        try {
            std::cout << "Received login request" << std::endl;
            std::string post_data;
            int content_length = 0;
            validateAndParseRequest(request, post_data, content_length);

            validateRequiredFields(post_data, {"username", "password"});

            std::string username = post_data.substr(post_data.find("username=") + 9, post_data.find("&password=") - (post_data.find("username=") + 9));
            std::string password = post_data.substr(post_data.find("password=") + 9);

            bool success = pms.userLogin(username, password);

            if (success) {
                std::string user_role = pms.getUserRole(username);
                response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n";
                response += "{\"status\":\"success\",\"message\":\"Login successful\",\"user\":{\"username\":\"" +
                            username + "\",\"role\":\"" + user_role + "\"}}";
            } else {
                response = "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\r\n";
                response += "{\"status\":\"error\",\"message\":\"Invalid username or password\"}";
            }
        } catch (const std::exception& e) {
            std::cerr << "Error processing login request: " << e.what() << std::endl;
            response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n";
            response += "{\"status\":\"error\",\"message\":\"Invalid login request\"}";
        }
    }
    // Handle signup POST request
    else if (strstr(buffer, "POST /signup")) {
        try {
            std::cout << "Received signup request" << std::endl;
            std::string post_data;
            int content_length = 0;
            validateAndParseRequest(request, post_data, content_length);

            validateRequiredFields(post_data, {"username", "password", "userType"});

            std::string username = post_data.substr(post_data.find("username=") + 9, post_data.find("&password=") - (post_data.find("username=") + 9));
            std::string password = post_data.substr(post_data.find("password=") + 9, post_data.find("&userType=") - (post_data.find("password=") + 9));
            std::string role = post_data.substr(post_data.find("userType=") + 9);

            bool success = pms.createAccount(username, password, role);

            response = success
                ? "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"success\",\"message\":\"Account created successfully\"}"
                : "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"status\":\"error\",\"message\":\"Failed to create account\"}";
        } catch (const std::exception& e) {
            std::cerr << "Error processing signup request: " << e.what() << std::endl;
            response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n";
            response += "{\"status\":\"error\",\"message\":\"Invalid signup request\"}";
        }
    }

    else if (strstr(buffer, "GET /financial-overview/")) {
        std::string username = request.substr(request.find("username=") + 9);
        username = username.substr(0, username.find(" HTTP"));

    // Retrieve financial overview for the user
        std::map<std::string, double> financials = pms.getFinancialOverview(username);

    // Create a JSON response
        response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Type: application/json\r\n";
        response += "Connection: close\r\n\r\n";
        response += "{";
        response += "\"Gross Operating Income (GOI)\":" + std::to_string(financials["Gross Operating Income (GOI)"]) + ",";
        response += "\"Operating Expenses\":" + std::to_string(financials["Operating Expenses"]) + ",";
        response += "\"Net Operating Income (NOI)\":" + std::to_string(financials["Net Operating Income (NOI)"]) + ",";
        response += "\"Capitalization Rate (%)\":" + std::to_string(financials["Capitalization Rate (%)"]);
        response += "}";
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

/**
 * Main server function
 */
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
