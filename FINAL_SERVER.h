// propertymanagementsystem_c++.h
#ifndef PROPERTY_MANAGEMENT_SYSTEM_H
#define PROPERTY_MANAGEMENT_SYSTEM_H

#include <iostream>
#include <string>
#include <vector>
#include <map>
// Add these necessary headers for socket programming
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

using namespace std;

class PropertyManagementSystem {
private:
    int connectToDb() {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            std::cerr << "Failed to create socket" << std::endl;
            return -1;
        }

        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(8081);  // Database server port
        server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

        if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            std::cerr << "Failed to connect to database" << std::endl;
            close(sock);
            return -1;
        }

        return sock;
    }

    std::string sendDbRequest(const std::string& request) {
        int sock = connectToDb();
        if (sock < 0) return "ERROR Database connection failed";

        // Send request
        send(sock, request.c_str(), request.length(), 0);

        // Get response
        char buffer[1024] = {0};
        read(sock, buffer, sizeof(buffer) - 1);
        
        close(sock);
        return std::string(buffer);
    }

public:
    PropertyManagementSystem() {}
    ~PropertyManagementSystem() {}

    bool createAccount(const string& username, const string& password, const string& role) {
        std::string request = "CREATE " + username + " " + password + " " + role;
        std::string response = sendDbRequest(request);
        return response.find("SUCCESS") != std::string::npos;
    }

    bool userLogin(const string& username, const string& password) {
        std::string request = "LOGIN " + username + " " + password;
        std::string response = sendDbRequest(request);
        return response.find("SUCCESS") != std::string::npos;
    }

    void submitMaintenanceRequest(int tenantId, const string& description) {
        cout << "Maintenance request submitted for tenant " << tenantId << ": " << description << endl;
    }

    void managePropertyDescription(int propertyId, const string& description) {
        cout << "Property " << propertyId << " description updated: " << description << endl;
    }
};

#endif
