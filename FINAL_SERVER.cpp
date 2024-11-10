
// server_c++.cpp
#include "propertymanagementsystem_front.h"
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
       
       string html_content = readHtmlFile("frontend.html");
       
        response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Type: text/html\r\n";
        response += "Connection: close\r\n\r\n";
        response += html_content;
        // Here would go your HTML content

       
    }
    else if (strstr(buffer, "POST /login")) {
        // Handle login requests
        
        // Extract username and password from POST data
        string postData = request.substr(request.find("\r\n\r\n") + 4);
        size_t userPos = postData.find("username=") + 9;
        size_t passPos = postData.find("password=") + 9;
        size_t userEnd = postData.find("&", userPos);
        
        // Parse the credentials
        string username = postData.substr(userPos, userEnd - userPos);
        string password = postData.substr(passPos);

        // Attempt to login
        bool success = pms.userLogin(username, password);

        // Prepare response
        response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Type: text/html\r\n";
        response += "Connection: close\r\n\r\n";
        response += "<html><body>";
        response += success ? "<h1>Login Successful!</h1>" : "<h1>Login Failed!</h1>";
        response += "<a href='/'>Back to Home</a>";
        response += "</body></html>";
    }
    else if (strstr(buffer, "POST /signup")) {
        // Handle signup requests
        
        // Extract signup data from POST request
        string postData = request.substr(request.find("\r\n\r\n") + 4);
        
        // Parse form data to get username, password, and role
        size_t userPos = postData.find("username=") + 9;
        size_t passPos = postData.find("password=") + 9;
        size_t rolePos = postData.find("userType=") + 9;
        
        size_t userEnd = postData.find("&", userPos);
        size_t passEnd = postData.find("&", passPos);
        
        // Extract the individual fields
        string username = postData.substr(userPos, userEnd - userPos);
        string password = postData.substr(passPos, passEnd - passPos);
        string role = postData.substr(rolePos);
        
        // Attempt to create the account
        bool success = pms.createAccount(username, password, role);
        
        // Prepare JSON response
        response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Type: application/json\r\n";
        response += "Connection: close\r\n\r\n";
        
        if (success) {
            response += "{\"status\": \"success\", \"message\": \"Account created successfully\"}";
        } else {
            response += "{\"status\": \"error\", \"message\": \"Username already exists\"}";
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
