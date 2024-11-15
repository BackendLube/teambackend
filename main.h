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
#include <mysql/mysql.h>

using namespace std;

class PropertyManagementSystem {
private:
    MYSQL* conn;

    // Original socket connection for frontend
    int connectToDb() {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            std::cerr << "Failed to create socket" << std::endl;
            return -1;
        }

        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(3306);  // Database server port
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

    // MySQL initialization
    bool initializeDB() {
        conn = mysql_init(NULL);
        if (conn == NULL) {
            std::cerr << "MySQL initialization failed" << std::endl;
            return false;
        }

        // Connect to MySQL database
        if (!mysql_real_connect(conn,
            "127.0.0.1",  // host
            "root",       // user
            "Lubinsky6",  // password
            "server",     // database
            3306,         // port
            NULL,         // unix socket
            0            // client flag
        )) {
            std::cerr << "Database connection failed: " << mysql_error(conn) << std::endl;
            return false;
        }

        std::cout << "Successfully connected to MySQL database" << std::endl;
        return true;
    }

public:
    PropertyManagementSystem() {
        if (!initializeDB()) {
            throw std::runtime_error("Failed to initialize database connection");
        }
    }

    ~PropertyManagementSystem() {
        if (conn) {
            mysql_close(conn);
        }
    }

  // In test.h, update the createAccount method:

bool createAccount(const string& username, const string& password, const string& role) {
    try {
        if (!conn) {
            std::cerr << "No database connection" << std::endl;
            return false;
        }

        // First check if username exists
        string check_query = "SELECT COUNT(*) FROM users WHERE username = '" + username + "'";
        
        if (mysql_query(conn, check_query.c_str())) {
            std::cerr << "Username check failed: " << mysql_error(conn) << std::endl;
            return false;
        }

        MYSQL_RES* result = mysql_store_result(conn);
        if (!result) {
            std::cerr << "Failed to get query result" << std::endl;
            return false;
        }

        MYSQL_ROW row = mysql_fetch_row(result);
        if (row && atoi(row[0]) > 0) {
            mysql_free_result(result);
            std::cerr << "Username already exists" << std::endl;
            return false;
        }
        mysql_free_result(result);

        // Create insert query
        string insert_query = "INSERT INTO users (username, password, role) VALUES ('" +
                            username + "', '" + password + "', '" + role + "')";
        
        std::cout << "Executing query: " << insert_query << std::endl;
        
        if (mysql_query(conn, insert_query.c_str())) {
            std::cerr << "Account creation failed: " << mysql_error(conn) << std::endl;
            return false;
        }

        if (mysql_affected_rows(conn) > 0) {
            std::cout << "Account successfully created in database" << std::endl;
            return true;
        } else {
            std::cerr << "No rows were inserted" << std::endl;
            return false;
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception during account creation: " << e.what() << std::endl;
        return false;
    }
}
    bool userLogin(const string& username, const string& password) {
        // Check MySQL database
        string query = "SELECT COUNT(*) FROM users WHERE username='" + 
                      username + "' AND password='" + password + "'";
                      
        if (mysql_query(conn, query.c_str())) {
            std::cerr << "Login query failed: " << mysql_error(conn) << std::endl;
            return false;
        }

        MYSQL_RES* result = mysql_store_result(conn);
        if (result == NULL) {
            return false;
        }

        MYSQL_ROW row = mysql_fetch_row(result);
        bool valid = (row && atoi(row[0]) > 0);
        mysql_free_result(result);

        // Also send to original socket system for frontend compatibility
        std::string request = "LOGIN " + username + " " + password;
        sendDbRequest(request);
        
        return valid;
    }

    void submitMaintenanceRequest(int tenantId, const string& description) {
        // Store in MySQL
        string query = "INSERT INTO maintenance_requests (tenant_id, description) VALUES (" +
                      to_string(tenantId) + ", '" + description + "')";
                      
        if (mysql_query(conn, query.c_str())) {
            std::cerr << "Maintenance request failed: " << mysql_error(conn) << std::endl;
        }
        
        cout << "Maintenance request submitted for tenant " << tenantId << ": " << description << endl;
    }

    void managePropertyDescription(int propertyId, const string& description) {
        cout << "Property " << propertyId << " description updated: " << description << endl;
    }
};

#endif
