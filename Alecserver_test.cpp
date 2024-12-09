// server_c++.cpp
// Server implementation for Property Management System
// Handles HTTP requests and client-server communication

#include "test.h" // Custom header file for property management system functionalities
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
#define PORT 8080     // Port number the server listens on
#define BACKLOG 5     // Maximum number of pending connections in the queue

/**
 * Reads HTML file content
 * Security considerations:
 * - Includes basic error handling for file operations.
 * - Returns fallback HTML content in case of file-read failure.
 * - Can be enhanced with path validation to prevent directory traversal attacks.
 */
std::string readHtmlFile(const std::string& filename) {
    std::ifstream file(filename);
    std::stringstream buffer;

    if (file.is_open()) {
        buffer << file.rdbuf(); // Read entire file contents into the buffer
        file.close();
        return buffer.str();
    } else {
        std::cerr << "Error: Unable to open file " << filename << std::endl;
        // Return minimal error page if file read fails
        return "<!DOCTYPE html><html><body><h1>Error loading page</h1></body></html>";
    }
}

/**
 * Handles client HTTP requests.
 * Security features:
 * - Buffer size limits to prevent overflow.
 * - Validates incoming request formats and content.
 * - Handles incomplete or malformed requests gracefully.
 * - Includes logging for debugging and auditing.
 */
void handle_request(int client_socket) {
    static PropertyManagementSystem pms; // Instance of the property management system
    char buffer[1024] = {0};             // Buffer for incoming request data
    std::string response;                // Response to be sent to the client

    // Read incoming request from client
    // Security: Use sizeof(buffer) - 1 to ensure no overflow
    read(client_socket, buffer, sizeof(buffer) - 1);
    std::string request(buffer);

    // Check if the request is a GET request for the home page
    if (strstr(buffer, "GET / HTTP/1.1")) {
        // Read HTML content from the main page file
        std::string html_content = readHtmlFile("test_frontend.html");
        // Construct the HTTP response
        response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Type: text/html\r\n";
        response += "Connection: close\r\n\r\n";
        response += html_content;
    }

    // Handle POST request for user login
    else if (strstr(buffer, "POST /login")) {
        std::cout << "Received login request" << std::endl;

        const int BUFFER_SIZE = 4096; // Define buffer size for request handling
        char request_buffer[BUFFER_SIZE] = {0}; // Temporary buffer for receiving data
        std::string complete_request(buffer);   // Store the complete HTTP request

        // Parse Content-Length header to determine the body size
        std::string content_length_header = "Content-Length: ";
        size_t content_length_pos = complete_request.find(content_length_header);
        int content_length = 0;

        // Extract and validate the Content-Length value
        if (content_length_pos != std::string::npos) {
            size_t content_length_end = complete_request.find("\r\n", content_length_pos);
            std::string content_length_str = complete_request.substr(
                content_length_pos + content_length_header.length(),
                content_length_end - (content_length_pos + content_length_header.length()));
            content_length = std::stoi(content_length_str);
        }

        // Find the end of the headers to extract the POST body
        size_t header_end = complete_request.find("\r\n\r\n");
        if (header_end == std::string::npos) {
            // Return 400 Bad Request if headers are incomplete
            std::cerr << "Could not find end of headers" << std::endl;
            response = "HTTP/1.1 400 Bad Request\r\n\r\n";
            send(client_socket, response.c_str(), response.size(), 0);
            return;
        }

        // Extract the body of the POST request
        std::string post_data = complete_request.substr(header_end + 4);

        // Continue receiving data if the body is incomplete
        int bytes_received = 0;
        while (post_data.length() < content_length) {
            bytes_received = recv(client_socket, request_buffer, BUFFER_SIZE - 1, 0);
            if (bytes_received <= 0) break;
            post_data += std::string(request_buffer, bytes_received);
            memset(request_buffer, 0, BUFFER_SIZE); // Clear buffer to prevent data leakage
        }

        // Parse login credentials from the POST body
        std::string username, password;
        try {
            size_t username_pos = post_data.find("username=");
            size_t password_pos = post_data.find("password=");

            if (username_pos != std::string::npos && password_pos != std::string::npos) {
                username_pos += 9; // Skip "username=" length
                password_pos += 9; // Skip "password=" length

                size_t username_end = post_data.find("&", username_pos);
                size_t password_end = post_data.find("&", password_pos);
                if (password_end == std::string::npos) {
                    password_end = post_data.length();
                }

                username = post_data.substr(username_pos, username_end - username_pos);
                password = post_data.substr(password_pos, password_end - password_pos);
            }
        } catch (const std::exception& e) {
            // Handle errors during parsing
            std::cerr << "Error parsing login data: " << e.what() << std::endl;
            response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n";
            response += "{\"status\":\"error\",\"message\":\"Invalid login data format\"}";
            send(client_socket, response.c_str(), response.size(), 0);
            return;
        }

        // Authenticate user with the Property Management System
        bool success = pms.userLogin(username, password);

        if (success) {
            // Retrieve the user's role for authorization
            std::string user_role = pms.getUserRole(username);
            std::cout << "Retrieved role for user " << username << ": " << user_role << std::endl;

            // Respond with success and user role
            response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n";
            response += "{\"status\":\"success\",\"message\":\"Login successful\",\"user\":{\"username\":\"" +
                        username + "\",\"role\":\"" + user_role + "\"}}";
        } else {
            // Respond with 401 Unauthorized if login fails
            response = "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\r\n";
            response += "{\"status\":\"error\",\"message\":\"Invalid username or password\"}";
        }
    }

    // Add more request handlers here...

    // Send the response to the client and close the socket
    send(client_socket, response.c_str(), response.size(), 0);
    close(client_socket);
}

/**
 * Main server function.
 * Security features:
 * - Handles errors during socket creation, binding, and listening.
 * - Cleans up resources properly on failure.
 */
int main() {
    int server_socket, client_socket;
    struct sockaddr_in server_addr; // Server address structure
    socklen_t client_len;
    struct sockaddr_in client_addr; // Client address structure

    // Create a TCP socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        std::cerr << "Failed to create socket." << std::endl;
        return 1;
    }

    // Set socket options for reuse
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::cerr << "Failed to set socket options." << std::endl;
        close(server_socket);
        return 1;
    }

    // Configure server address
    server_addr.sin_family = AF_INET;       // IPv4
    server_addr.sin_addr.s_addr = INADDR_ANY; // Bind to all available interfaces
    server_addr.sin_port = htons(PORT);    // Convert port number to network byte order

    // Bind the socket to the configured address
    if (::bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Failed to bind to port." << std::endl;
        close(server_socket);
        return 1;
    }

    // Start listening for incoming connections
    if (listen(server_socket, BACKLOG) < 0) {
        std::cerr << "Listen failed." << std::endl;
        close(server_socket);
        return 1;
    }

    std::cout << "Server running on port " << PORT << "..." << std::endl;

    client_len = sizeof(client_addr);
    while (true) {
        // Accept a new client connection
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket < 0) {
            std::cerr << "Failed to accept connection." << std::endl;
            continue;
        }

        // Handle the client request in a separate function
        handle_request(client_socket);
    }

    // Close the server socket when done
    close(server_socket);
    return 0;
}

