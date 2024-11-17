// propertymanagementsystem_c++.h
#ifndef PROPERTY_MANAGEMENT_SYSTEM_H
#define PROPERTY_MANAGEMENT_SYSTEM_H

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <mysql/mysql.h>

using namespace std;

class PropertyManagementSystem {
private:
    MYSQL* conn;

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

        send(sock, request.c_str(), request.length(), 0);

        char buffer[1024] = {0};
        read(sock, buffer, sizeof(buffer) - 1);
        
        close(sock);
        return std::string(buffer);
    }

    bool initializeDB() {
        conn = mysql_init(NULL);
        if (conn == NULL) {
            std::cerr << "MySQL initialization failed" << std::endl;
            return false;
        }

        if (!mysql_real_connect(conn,
            "localhost",  // Changed from 127.0.0.1 to localhost
            "root",       
            "Lubinsky6",  
            "server",     
            3306,         
            NULL,         
            0            
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

    bool userLogin(const string& username, const string& password) {
        if (!conn) {
            std::cerr << "No database connection for login" << std::endl;
            return false;
        }

        // Escape the input strings to prevent SQL injection
        char* escaped_username = new char[username.length() * 2 + 1];
        char* escaped_password = new char[password.length() * 2 + 1];
        
        mysql_real_escape_string(conn, escaped_username, username.c_str(), username.length());
        mysql_real_escape_string(conn, escaped_password, password.c_str(), password.length());

        // Create the query
        string query = "SELECT * FROM users WHERE username='" + 
                      string(escaped_username) + "' AND password='" + 
                      string(escaped_password) + "'";

        delete[] escaped_username;
        delete[] escaped_password;

        std::cout << "Executing login query: " << query << std::endl;  // Debug log

        if (mysql_query(conn, query.c_str())) {
            std::cerr << "Login query failed: " << mysql_error(conn) << std::endl;
            return false;
        }

        MYSQL_RES* result = mysql_store_result(conn);
        if (result == NULL) {
            std::cerr << "Failed to get query result" << std::endl;
            return false;
        }

        // Check if we got any rows
        my_ulonglong num_rows = mysql_num_rows(result);
        std::cout << "Found " << num_rows << " matching users" << std::endl;  // Debug log

        bool valid = (num_rows > 0);
        mysql_free_result(result);

        return valid;
    }

    bool createAccount(const string& username, const string& password, const string& role) {
        try {
            if (!conn) {
                std::cerr << "No database connection" << std::endl;
                return false;
            }

            // First check if username exists
            char* escaped_username = new char[username.length() * 2 + 1];
            mysql_real_escape_string(conn, escaped_username, username.c_str(), username.length());
            
            string check_query = "SELECT COUNT(*) FROM users WHERE username = '" + 
                               string(escaped_username) + "'";
            
            delete[] escaped_username;

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

            // Escape all input strings
            char* escaped_password = new char[password.length() * 2 + 1];
            char* escaped_role = new char[role.length() * 2 + 1];
            escaped_username = new char[username.length() * 2 + 1];
            
            mysql_real_escape_string(conn, escaped_username, username.c_str(), username.length());
            mysql_real_escape_string(conn, escaped_password, password.c_str(), password.length());
            mysql_real_escape_string(conn, escaped_role, role.c_str(), role.length());

            // Create insert query with escaped strings
            string insert_query = "INSERT INTO users (username, password, role) VALUES ('" +
                                string(escaped_username) + "', '" + 
                                string(escaped_password) + "', '" + 
                                string(escaped_role) + "')";

            delete[] escaped_username;
            delete[] escaped_password;
            delete[] escaped_role;
            
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
