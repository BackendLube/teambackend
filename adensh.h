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
    int connectToDb();

    // Function to send a request to the database via socket
    std::string sendDbRequest(const std::string& request);

    // MySQL initialization
    bool initializeDB();

public:
    // Constructor and Destructor
    PropertyManagementSystem();
    ~PropertyManagementSystem();

    // Account management
    bool createAccount(const string& username, const string& password, const string& role);
    bool userLogin(const string& username, const string& password);

    // Password management
    bool changePassword(const string& username, const string& oldPassword, const string& newPassword);

    // Maintenance request handling
    void submitMaintenanceRequest(int tenantId, const string& description);

    // Property management functions
    void managePropertyDescription(int propertyId, const string& description);
};

// Function definitions

// Establishes a connection to the database socket
int PropertyManagementSystem::connectToDb() {
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

// Sends a request to the database and returns the response
std::string PropertyManagementSystem::sendDbRequest(const std::string& request) {
    int sock = connectToDb();
    if (sock < 0) return "ERROR Database connection failed";

    send(sock, request.c_str(), request.length(), 0);

    char buffer[1024] = {0};
    read(sock, buffer, sizeof(buffer) - 1);

    close(sock);
    return std::string(buffer);
}

// Initializes the MySQL connection
bool PropertyManagementSystem::initializeDB() {
    conn = mysql_init(NULL);
    if (conn == NULL) {
        std::cerr << "MySQL initialization failed" << std::endl;
        return false;
    }

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

// Creates a new user account in the database
bool PropertyManagementSystem::createAccount(const string& username, const string& password, const string& role) {
    try {
        if (!conn) {
            std::cerr << "No database connection" << std::endl;
            return false;
        }

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

        string insert_query = "INSERT INTO users (username, password, role) VALUES ('" +
                              username + "', '" + password + "', '" + role + "')";
        std::cout << "Executing query: " << insert_query << std::endl;

        if (mysql_query(conn, insert_query.c_str())) {
            std::cerr << "Account creation failed: " << mysql_error(conn) << std::endl;
            return false;
        }

        return mysql_affected_rows(conn) > 0;
    } catch (const std::exception& e) {
        std::cerr << "Exception during account creation: " << e.what() << std::endl;
        return false;
    }
}

// Handles user login
bool PropertyManagementSystem::userLogin(const string& username, const string& password) {
    string query = "SELECT COUNT(*) FROM users WHERE username='" + username + "' AND password='" + password + "'";
    if (mysql_query(conn, query.c_str())) {
        std::cerr << "Login query failed: " << mysql_error(conn) << std::endl;
        return false;
    }

    MYSQL_RES* result = mysql_store_result(conn);
    if (!result) return false;

    MYSQL_ROW row = mysql_fetch_row(result);
    bool valid = (row && atoi(row[0]) > 0);
    mysql_free_result(result);

    sendDbRequest("LOGIN " + username + " " + password);
    return valid;
}

// Changes the user's password
bool PropertyManagementSystem::changePassword(const string& username, const string& oldPassword, const string& newPassword) {
    // Check if old password is correct
    string query = "SELECT COUNT(*) FROM users WHERE username='" + username + "' AND password='" + oldPassword + "'";
    if (mysql_query(conn, query.c_str())) {
        std::cerr << "Password check query failed: " << mysql_error(conn) << std::endl;
        return false;
    }

    MYSQL_RES* result = mysql_store_result(conn);
    if (!result) return false;

    MYSQL_ROW row = mysql_fetch_row(result);
    if (row && atoi(row[0]) > 0) {
        // Old password is correct, proceed to update the new password
        string update_query = "UPDATE users SET password = '" + newPassword + "' WHERE username = '" + username + "'";
        if (mysql_query(conn, update_query.c_str())) {
            std::cerr << "Password update failed: " << mysql_error(conn) << std::endl;
            mysql_free_result(result);
            return false;
        }

        mysql_free_result(result);
        std::cout << "Password successfully updated for user " << username << std::endl;
        return true;
    } else {
        mysql_free_result(result);
        std::cerr << "Old password is incorrect" << std::endl;
        return false;
    }
}

// Submits a maintenance request
void PropertyManagementSystem::submitMaintenanceRequest(int tenantId, const string& description) {
    string query = "INSERT INTO maintenance_requests (tenant_id, description) VALUES (" +
                   to_string(tenantId) + ", '" + description + "')";
    if (mysql_query(conn, query.c_str())) {
        std::cerr << "Maintenance request failed: " << mysql_error(conn) << std::endl;
    }

    std::cout << "Maintenance request submitted for tenant " << tenantId << ": " << description << std::endl;
}

// Updates property description
void PropertyManagementSystem::managePropertyDescription(int propertyId, const string& description) {
    std::cout << "Property " << propertyId << " description updated: " << description << std::endl;
}

#endif
