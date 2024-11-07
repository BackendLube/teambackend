#include <iostream>
#include <string>
#include <sstream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <vector>
#include <map>

// Need to link with Ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")

#define PORT 8080
#define BACKLOG 5

// Simple Property Management System class
class PropertyManagementSystem {
private:
    struct User {
        std::string username;
        std::string password;
        std::string role;
    };

    std::vector<User> users;

public:
    PropertyManagementSystem() {
        // Initialize some default users
        users.push_back({"admin", "admin123", "admin"});
        users.push_back({"tenant1", "tenant123", "tenant"});
        users.push_back({"owner", "owner123", "property_owner"});
    }

    bool userLogin(const std::string& username, const std::string& password) {
        for (const auto& user : users) {
            if (user.username == username && user.password == password) {
                return true;
            }
        }
        return false;
    }

    void submitMaintenanceRequest(int tenantId, const std::string& description) {
        // In a real system, this would store the maintenance request
        std::cout << "Maintenance request submitted for tenant " << tenantId 
                  << ": " << description << std::endl;
    }
};

// Function to handle incoming requests
void handle_request(SOCKET client_socket) {
    static PropertyManagementSystem pms;  // Create a single instance
    char buffer[1024] = {0};
    std::string response;

    // Read the HTTP request from the client
    recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    std::string request(buffer);

    if (strstr(buffer, "GET / HTTP/1.1")) {
        response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Type: text/html\r\n";
        response += "Connection: close\r\n\r\n";
        response += "<!DOCTYPE html>\n"
            "<html>\n"
            "<head>\n"
            "    <title>Property Management System</title>\n"
            "    <style>\n"
            "        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: white; }\n"
            "        .nav { background-color: black; padding: 1rem; color: white; }\n"
            "        .nav button { background: none; border: none; color: white; padding: 0.5rem 1rem; margin-right: 1rem; cursor: pointer; }\n"
            "        .nav button:hover { background-color: grey; border-radius: 4px; }\n"
            "        .content { padding: 2rem; }\n"
            "        .card { background: white; border-radius: 8px; padding: 1rem; margin-bottom: 1rem; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }\n"
            "        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1rem; margin-top: 1rem; }\n"
            "        .login-container { max-width: 400px; margin: 100px auto; padding: 2rem; background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }\n"
            "        input, select { width: 100%; padding: 0.5rem; margin-bottom: 1rem; border: 1px solid #ddd; border-radius: 4px; }\n"
            "        button { background-color: blue; color: white; border: none; padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer; margin-bottom: 0.5rem; }\n"
            "        button:hover { background-color: darkblue; }\n"
            "        .error { color: red; margin-bottom: 1rem; }\n"
            "        .secondary-button { background-color: #666; width: 100%; }\n"
            "    </style>\n"
            "</head>\n"
            "<body>\n"
            "    <div id=\"app\"></div>\n"
            "    <script>\n"
            "        const data = {\n"
            "            properties: [\n"
            "                { id: 1, address: \"123 Main St\", description: \"Modern Apartment\", value: 1200000, performance: 85.5 },\n"
            "                { id: 2, address: \"456 Meridian Rd\", description: \"Commercial Space\", value: 2500000, performance: 92.0 },\n"
            "                { id: 3, address: \"789 Normal Ave\", description: \"Residential Home\", value: 450000, performance: 78.3 }\n"
            "            ],\n"
            "            tenants: [\n"
            "                { id: 1, name: \"Evan Lubinsky\", property_id: 1, lease_start: \"2024-01-01\", lease_end: \"2024-12-31\", rent: 1500 },\n"
            "                { id: 2, name: \"Aden Llewellyn\", property_id: 1, lease_start: \"2024-02-01\", lease_end: \"2024-12-31\", rent: 1600 },\n"
            "                { id: 3, name: \"Jake Dobson\", property_id: 2, lease_start: \"2024-01-15\", lease_end: \"2024-12-31\", rent: 2500 }\n"
            "            ],\n"
            "            maintenance: [\n"
            "                { id: 1, property_id: 1, description: \"Leaking faucet\", status: \"Open\", created_at: \"2024-03-15\" },\n"
            "                { id: 2, property_id: 2, description: \"HVAC repair\", status: \"In Progress\", created_at: \"2024-03-10\" },\n"
            "                { id: 3, property_id: 1, description: \"Broken window\", status: \"Resolved\", created_at: \"2024-03-01\" }\n"
            "            ],\n"
            "            users: [\n"
            "                { id: 1, username: \"admin\", password: \"admin123\", role: \"admin\" },\n"
            "                { id: 2, username: \"tenant1\", password: \"tenant123\", role: \"tenant\" },\n"
            "                { id: 3, username: \"owner\", password: \"owner123\", role: \"property_owner\" }\n"
            "            ]\n"
            "        };\n"
            "\n"
            "        let currentUser = null;\n"
            "        let currentPage = 'login';\n"
            "\n"
            "        function renderLogin() {\n"
            "            return `\n"
            "                <div class=\"login-container\">\n"
            "                    <h2>Property Management Login</h2>\n"
            "                    <div id=\"loginError\" class=\"error\"></div>\n"
            "                    <form onsubmit=\"handleLogin(event)\">\n"
            "                        <input type=\"text\" id=\"username\" placeholder=\"Username\" required>\n"
            "                        <input type=\"password\" id=\"password\" placeholder=\"Password\" required>\n"
            "                        <button type=\"submit\">Login</button>\n"
            "                    </form>\n"
            "                </div>\n"
            "            `;\n"
            "        }\n"
            "\n"
            "        function renderDashboard() {\n"
            "            return `\n"
            "                <div class=\"content\">\n"
            "                    <h2>Dashboard</h2>\n"
            "                    <div class=\"grid\">\n"
            "                        <div class=\"card\">\n"
            "                            <h3>Properties</h3>\n"
            "                            <p>${data.properties.length}</p>\n"
            "                        </div>\n"
            "                        <div class=\"card\">\n"
            "                            <h3>Tenants</h3>\n"
            "                            <p>${data.tenants.length}</p>\n"
            "                        </div>\n"
            "                        <div class=\"card\">\n"
            "                            <h3>Active Maintenance</h3>\n"
            "                            <p>${data.maintenance.filter(m => m.status !== 'Resolved').length}</p>\n"
            "                        </div>\n"
            "                    </div>\n"
            "                </div>\n"
            "            `;\n"
            "        }\n"
            "\n"
            "        function handleLogin(event) {\n"
            "            event.preventDefault();\n"
            "            const username = document.getElementById('username').value;\n"
            "            const password = document.getElementById('password').value;\n"
            "            \n"
            "            const user = data.users.find(u => u.username === username && u.password === password);\n"
            "            if (user) {\n"
            "                currentUser = user;\n"
            "                currentPage = 'dashboard';\n"
            "                render();\n"
            "            } else {\n"
            "                document.getElementById('loginError').textContent = 'Invalid credentials';\n"
            "            }\n"
            "        }\n"
            "\n"
            "        function render() {\n"
            "            const app = document.getElementById('app');\n"
            "            app.innerHTML = currentUser ? renderDashboard() : renderLogin();\n"
            "        }\n"
            "\n"
            "        render();\n"
            "    </script>\n"
            "</body>\n"
            "</html>\n";
    }
    else {
        response = "HTTP/1.1 404 Not Found\r\n";
        response += "Content-Type: text/html\r\n";
        response += "Connection: close\r\n\r\n";
        response += "<html><body><h1>404 Not Found</h1></body></html>";
    }

    send(client_socket, response.c_str(), response.size(), 0);
    closesocket(client_socket);
}

int main() {
    WSADATA wsaData;
    SOCKET server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    int client_len;

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed." << std::endl;
        return 1;
    }

    // Create socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == INVALID_SOCKET) {
        std::cerr << "Failed to create socket. Error: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

    // Set socket options
    BOOL opt = TRUE;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt)) == SOCKET_ERROR) {
        std::cerr << "Failed to set socket options. Error: " << WSAGetLastError() << std::endl;
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }

    // Setup server address structure
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind socket
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed. Error: " << WSAGetLastError() << std::endl;
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }

    // Listen for incoming connections
    if (listen(server_socket, BACKLOG) == SOCKET_ERROR) {
        std::cerr << "Listen failed. Error: " << WSAGetLastError() << std::endl;
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }

    std::cout << "Server running on port " << PORT << "..." << std::endl;
    std::cout << "Open your web browser and navigate to http://localhost:8080" << std::endl;

    client_len = sizeof(client_addr);
    while (true) {
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket == INVALID_SOCKET) {
            std::cerr << "Accept failed. Error: " << WSAGetLastError() << std::endl;
            continue;
        }

        handle_request(client_socket);
    }

    // Cleanup
    closesocket(server_socket);
    WSACleanup();
    return 0;
}