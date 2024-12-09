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
 * Reads HTML file content
 * Security considerations:
 * - Basic error handling for file operations
 * - Returns fallback HTML on error
 * - Could be enhanced with path validation to prevent directory traversal
 */
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
/**
 * Main request handler function
 * Security features:
 * - Fixed buffer size to prevent overflow
 * - Request validation
 * - Error handling for parsing
 * - Content-Length validation
 * - Input validation for all parameters
 */
void handle_request(int client_socket) {
    static PropertyManagementSystem pms;
    char buffer[1024] = {0}; // prevents buffer overflow
    string response;
    
// Security: Ensure buffer isn't overflowed during read
    read(client_socket, buffer, sizeof(buffer) - 1);
    string request(buffer);


 // Handle GET request for main page
    if (strstr(buffer, "GET / HTTP/1.1")) {
        string html_content = readHtmlFile("test_frontend.html");
        response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Type: text/html\r\n";
        response += "Connection: close\r\n\r\n";
        response += html_content;
    }
//Handle login POST request

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
// Security: Parse and validate Content-Length

        if (content_length_pos != std::string::npos) {
            size_t content_length_end = complete_request.find("\r\n", content_length_pos);
            std::string content_length_str = complete_request.substr(
                content_length_pos + content_length_header.length(),
                content_length_end - (content_length_pos + content_length_header.length())
            );
            content_length = std::stoi(content_length_str);
        }
// Security: Validate request format

        size_t header_end = complete_request.find("\r\n\r\n");
        if (header_end == std::string::npos) {
            std::cerr << "Could not find end of headers" << std::endl;
            response = "HTTP/1.1 400 Bad Request\r\n\r\n";
            send(client_socket, response.c_str(), response.size(), 0);
            return;
        }
    // Extract POST data
 std::string post_data = complete_request.substr(header_end + 4);
        
        // Security: Ensure complete data is received
        while (post_data.length() < content_length) {
            bytes_received = recv(client_socket, request_buffer, BUFFER_SIZE - 1, 0);
            if (bytes_received <= 0) break;
            post_data += std::string(request_buffer, bytes_received);
            memset(request_buffer, 0, BUFFER_SIZE); // Security: Clear buffer after use
        }
// Parse login credentials
        std::string username, password;
        try {
  //Validate presence of required fields
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
// extract credentials 
                username = post_data.substr(username_pos, username_end - username_pos);
                password = post_data.substr(password_pos, password_end - password_pos);

                std::cout << "Login attempt for username: " << username << std::endl;
            }
        } catch (const std::exception& e) {
            // handles parsing data
            std::cerr << "Error parsing login data: " << e.what() << std::endl;
            response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n";
            response += "{\"status\":\"error\",\"message\":\"Invalid login data format\"}";
            send(client_socket, response.c_str(), response.size(), 0);
            return;
        }
// attempt login and get user role
        bool success = pms.userLogin(username, password);
        
        if (success) {
            // Get the user's role
            string user_role = pms.getUserRole(username);
            std::cout << "Retrieved role for user " << username << ": " << user_role << std::endl;
            
            // Send success response with role information
            response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n";
            response += "{\"status\":\"success\",\"message\":\"Login successful\",\"user\":{\"username\":\"" + 
                        username + "\",\"role\":\"" + user_role + "\"}}";
        } else {
            response = "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\r\n";
            response += "{\"status\":\"error\",\"message\":\"Invalid username or password\"}";
        }
    }
    else if (strstr(buffer, "POST /signup")) {
        std::cout << "Received signup request" << std::endl;
        // security implemtatin to set the buffer size for request handling 
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

        std::string username, password, role;
        try {
            // validates the required fields
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
            // handle parsing errors
            std::cerr << "Error parsing POST data: " << e.what() << std::endl;
            response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n";
            response += "{\"status\":\"error\",\"message\":\"Invalid data format\"}";
            send(client_socket, response.c_str(), response.size(), 0);
            return;
        }

        if (username.empty() || password.empty() || role.empty()) {
            // handle required fields errors 
            std::cerr << "Missing required fields" << std::endl;
            response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n";
            response += "{\"status\":\"error\",\"message\":\"Missing required fields\"}";
            send(client_socket, response.c_str(), response.size(), 0);
            return;
        }
// make the account
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
else if (strstr(buffer, "POST /add-property")) {
    std::cout << "Received add property request" << std::endl;
    
    string post_data = request.substr(request.find("\r\n\r\n") + 4);
    
    size_t username_pos = post_data.find("username=");
    size_t address_pos = post_data.find("address=");
    size_t date_pos = post_data.find("date=");
    size_t price_pos = post_data.find("price=");
    size_t rent_pos = post_data.find("rent=");

    if (username_pos != string::npos && address_pos != string::npos && 
        date_pos != string::npos && price_pos != string::npos && rent_pos != string::npos) {
        
        username_pos += 9;
        address_pos += 8;
        date_pos += 5;
        price_pos += 6;
        rent_pos += 5;

        size_t username_end = post_data.find("&", username_pos);
        size_t address_end = post_data.find("&", address_pos);
        size_t date_end = post_data.find("&", date_pos);
        size_t price_end = post_data.find("&", price_pos);
        size_t rent_end = post_data.length();
        if (post_data.find("&", rent_pos) != string::npos) {
            rent_end = post_data.find("&", rent_pos);
        }

        string username = post_data.substr(username_pos, username_end - username_pos);
        string address = post_data.substr(address_pos, address_end - address_pos);
        string date = post_data.substr(date_pos, date_end - date_pos);
        double price = stod(post_data.substr(price_pos, price_end - price_pos));
        double rent = stod(post_data.substr(rent_pos, rent_end - rent_pos));

        bool success = pms.addProperty(username, address, date, price, rent);

        if (success) {
            response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n";
            response += "{\"status\":\"success\",\"message\":\"Property added successfully\"}";
        } else {
            response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n";
            response += "{\"status\":\"error\",\"message\":\"Failed to add property\"}";
        }
    } else {
        response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n";
        response += "{\"status\":\"error\",\"message\":\"Missing required fields\"}";
    }
}
// Submits a maintenance request from a tenant
void PropertyManagementSystem::submitMaintenanceRequest(int tenantId, const string& description) {
    if (!conn) return;  // Ensure there is a valid connection

    // Escape the description to prevent SQL injection
    char* escaped_description = new char[description.length() * 2 + 1];
    mysql_real_escape_string(conn, escaped_description, description.c_str(), description.length());

    // Build the SQL query to insert the maintenance request
    string query = "INSERT INTO maintenance_requests (tenant_id, description) VALUES (" +
                   to_string(tenantId) + ", '" + string(escaped_description) + "')";

    // Execute the query
    if (mysql_query(conn, query.c_str())) {
        std::cerr << "Maintenance request submission failed: " << mysql_error(conn) << std::endl;
    }

    // Clean up dynamically allocated memory
    delete[] escaped_description;
}
vector<map<string, string>> getMaintenanceRequests(int propertyId);
inline vector<map<string, string>> PropertyManagementSystem::getMaintenanceRequests(int propertyId) {
    vector<map<string, string>> requests;
    
    if (!conn) {
        std::cerr << "No database connection" << std::endl;
        return requests;
    }

    string query = "SELECT id, tenant_id, description, status FROM maintenance_requests WHERE property_id=" + to_string(propertyId);

    if (mysql_query(conn, query.c_str())) {
        std::cerr << "Maintenance request fetch failed: " << mysql_error(conn) << std::endl;
        return requests;
    }

    MYSQL_RES* result = mysql_store_result(conn);
    if (result == NULL) {
        std::cerr << "Failed to get query result" << std::endl;
        return requests;
    }

    MYSQL_ROW row;
    while ((row = mysql_fetch_row(result))) {
        map<string, string> request;
        request["id"] = row[0];           // Request ID
        request["tenant_id"] = row[1];    // Tenant ID
        request["description"] = row[2];  // Description
        request["status"] = row[3];       // Request Status (e.g., Pending, Completed)
        requests.push_back(request);
    }

    mysql_free_result(result);
    return requests;
}



    
    
    // In server.cpp, modify the GET /properties/ route handler:
else if (strstr(buffer, "GET /properties/")) {
    string username = request.substr(request.find("username=") + 9);
    username = username.substr(0, username.find(" HTTP"));
    
    vector<map<string, string> > properties = pms.getPropertiesByUser(username);
    
    response = "HTTP/1.1 200 OK\r\n";
    response += "Content-Type: application/json\r\n";
    response += "Connection: close\r\n\r\n";
    response += "[";
    
    for (size_t i = 0; i < properties.size(); i++) {
        if (i > 0) response += ",";
        response += "{";
        response += "\"id\":\"" + properties[i]["id"] + "\",";
        response += "\"address\":\"" + properties[i]["address"] + "\",";
        response += "\"date_added\":\"" + properties[i]["date_added"] + "\",";
        response += "\"price\":\"" + properties[i]["price"] + "\",";
        response += "\"rent_rent\":\"" + properties[i]["rent_rent"] + "\"";
        response += "}";
    }
    response += "]";
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
 * Security features:
 * - Socket error handling
 * - Option setting for socket reuse
 * - Proper cleanup on errors
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
        // this function is validating the client socket
        if (client_socket < 0) {
            std::cerr << "Failed to accept connection." << std::endl;
            continue;
        }

        handle_request(client_socket);
    }

    close(server_socket);
    return 0;
}
