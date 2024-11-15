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
// funtion to read HTML File

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
// Function to handle all incoming HTTP requests
void handle_request(int client_socket) {
    // Create a single instance of PropertyManagementSystem
    static PropertyManagementSystem pms;
    char buffer[1024] = {0};
    string response;

    // Read the HTTP request from the client
    read(client_socket, buffer, sizeof(buffer) - 1);
    string request(buffer);

    // Handle different types of requests
    if (strstr(buffer, "GET / HTTP/1.1")) {
        // Serve the main HTML page
       
       string html_content = readHtmlFile("test_frontend.html");
       
        response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Type: text/html\r\n";
        response += "Connection: close\r\n\r\n";
        response += html_content;
        // Here would go your HTML content

       
    }
  else if (strstr(buffer, "POST /signup")) {
    std::cout << "Received signup request" << std::endl;
    
    // Read the entire request content
    const int BUFFER_SIZE = 4096;
    char request_buffer[BUFFER_SIZE] = {0};
    int total_bytes = 0;
    int bytes_received = 0;
    std::string complete_request;

    // First, read what we already have
    complete_request = std::string(buffer);
    
    // Look for Content-Length in headers
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

    // Find the start of POST data
    size_t header_end = complete_request.find("\r\n\r\n");
    if (header_end == std::string::npos) {
        std::cerr << "Could not find end of headers" << std::endl;
        response = "HTTP/1.1 400 Bad Request\r\n\r\n";
        send(client_socket, response.c_str(), response.size(), 0);
        return;
    }

    std::string post_data = complete_request.substr(header_end + 4);
    
    // If we haven't received all the data, keep reading
    while (post_data.length() < content_length) {
        bytes_received = recv(client_socket, request_buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received <= 0) break;
        post_data += std::string(request_buffer, bytes_received);
        memset(request_buffer, 0, BUFFER_SIZE);
    }

    std::cout << "Complete POST data: " << post_data << std::endl;

    // Parse the POST data
    std::string username, password, role;
    try {
        size_t username_pos = post_data.find("username=");
        size_t password_pos = post_data.find("password=");
        size_t role_pos = post_data.find("userType=");

        if (username_pos != std::string::npos && password_pos != std::string::npos && role_pos != std::string::npos) {
            username_pos += 9; // length of "username="
            password_pos += 9; // length of "password="
            role_pos += 9; // length of "userType="

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

    // Verify we got all required fields
    if (username.empty() || password.empty() || role.empty()) {
        std::cerr << "Missing required fields" << std::endl;
        response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n";
        response += "{\"status\":\"error\",\"message\":\"Missing required fields\"}";
        send(client_socket, response.c_str(), response.size(), 0);
        return;
    }

    // Try to create the account
    bool success = pms.createAccount(username, password, role);
    
    // Send response
    if (success) {
        response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n";
        response += "{\"status\":\"success\",\"message\":\"Account created successfully\"}";
    } else {
        response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n";
        response += "{\"status\":\"error\",\"message\":\"Failed to create account\"}";
    }
}
else if (strstr(buffer, "POST /change-password")) {
        std::cout << "Received password change request" << std::endl;
        
        const int BUFFER_SIZE = 4096;
        char request_buffer[BUFFER_SIZE] = {0};
        std::string complete_request;

        complete_request = std::string(buffer);
        
        // Look for Content-Length in headers
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

        // Find the start of POST data
        size_t header_end = complete_request.find("\r\n\r\n");
        if (header_end == std::string::npos) {
            std::cerr << "Could not find end of headers" << std::endl;
            response = "HTTP/1.1 400 Bad Request\r\n\r\n";
            send(client_socket, response.c_str(), response.size(), 0);
            return;
        }

        std::string post_data = complete_request.substr(header_end + 4);
        
        // If we haven't received all the data, keep reading
        while (post_data.length() < content_length) {
            int bytes_received = recv(client_socket, request_buffer, BUFFER_SIZE - 1, 0);
            if (bytes_received <= 0) break;
            post_data += std::string(request_buffer, bytes_received);
            memset(request_buffer, 0, BUFFER_SIZE);
        }

        std::cout << "Complete POST data: " << post_data << std::endl;

        // Parse the POST data
        std::string username, oldPassword, newPassword;
        try {
            size_t username_pos = post_data.find("username=");
            size_t old_password_pos = post_data.find("oldPassword=");
            size_t new_password_pos = post_data.find("newPassword=");

            if (username_pos != std::string::npos && 
                old_password_pos != std::string::npos && 
                new_password_pos != std::string::npos) {
                
                username_pos += 9; // length of "username="
                old_password_pos += 11; // length of "oldPassword="
                new_password_pos += 11; // length of "newPassword="

                size_t username_end = post_data.find("&", username_pos);
                size_t old_password_end = post_data.find("&", old_password_pos);

                username = post_data.substr(username_pos, username_end - username_pos);
                oldPassword = post_data.substr(old_password_pos, old_password_end - old_password_pos);
                newPassword = post_data.substr(new_password_pos);

                std::cout << "Processing password change for user: " << username << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "Error parsing POST data: " << e.what() << std::endl;
            response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n";
            response += "{\"status\":\"error\",\"message\":\"Invalid data format\"}";
            send(client_socket, response.c_str(), response.size(), 0);
            return;
        }

        // Verify we got all required fields
        if (username.empty() || oldPassword.empty() || newPassword.empty()) {
            std::cerr << "Missing required fields" << std::endl;
            response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n";
            response += "{\"status\":\"error\",\"message\":\"Missing required fields\"}";
            send(client_socket, response.c_str(), response.size(), 0);
            return;
        }

        // Try to change the password
        bool success = pms.changePassword(username, oldPassword, newPassword);
        
        // Send response
        if (success) {
            response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n";
            response += "{\"status\":\"success\",\"message\":\"Password changed successfully\"}";
        } else {
            response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n";
            response += "{\"status\":\"error\",\"message\":\"Failed to change password\"}";
        }
    }
    else if (strstr(buffer, "POST /maintenance")) {
        // Handle maintenance requests
        
        // Extract maintenance request data
        string postData = request.substr(request.find("\r\n\r\n") + 4);
        size_t idPos = postData.find("tenant_id=") + 10;
        size_t descPos = postData.find("description=") + 12;
        size_t idEnd = postData.find("&", idPos);
        
        // Parse the maintenance request details
        int tenantId = stoi(postData.substr(idPos, idEnd - idPos));
        string description = postData.substr(descPos);

        // Submit the maintenance request
        pms.submitMaintenanceRequest(tenantId, description);

        // Prepare response
        response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Type: text/html\r\n";
        response += "Connection: close\r\n\r\n";
        response += "<html><body>";
        response += "<h1>Maintenance Request Submitted!</h1>";
        response += "<a href='/'>Back to Home</a>";
        response += "</body></html>";
    }
    else {
        // Handle unknown requests with 404
        response = "HTTP/1.1 404 Not Found\r\n";
        response += "Content-Type: text/html\r\n";
        response += "Connection: close\r\n\r\n";
        response += "<html><body><h1>404 Not Found</h1></body></html>";
    }

    // Send response back to client
    send(client_socket, response.c_str(), response.size(), 0);
    close(client_socket);
}

// Main function to run the server
int main() {
    // Initialize socket variables
    int server_socket, client_socket;
    struct sockaddr_in server_addr;
    socklen_t client_len;
    struct sockaddr_in client_addr;

    // Create server socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        std::cerr << "Failed to create socket." << std::endl;
        return 1;
    }

    // Set socket options
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::cerr << "Failed to set socket options." << std::endl;
        close(server_socket);
        return 1;
    }

    // Configure server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind socket to port
    if (::bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Failed to bind to port." << std::endl;
        close(server_socket);
        return 1;
    }

    // Start listening for connections
    if (listen(server_socket, BACKLOG) < 0) {
        std::cerr << "Listen failed." << std::endl;
        close(server_socket);
        return 1;
    }

    std::cout << "Server running on port " << PORT << "..." << std::endl;

    // Main server loop
    client_len = sizeof(client_addr);
    while (true) {
        // Accept incoming connections
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket < 0) {
            std::cerr << "Failed to accept connection." << std::endl;
            continue;
        }

        // Handle the request
        handle_request(client_socket);
    }

    // Close server socket (this will never be reached in this implementation)
    close(server_socket);
    return 0;
}
