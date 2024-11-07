#ifndef PORTFOLIO_MANAGEMENT_H
#define PORTFOLIO_MANAGEMENT_H

#include <iostream>
#include <string>
#include <sqlite3.h>
#include <netinet/in.h>
#include <sys/socket.h>

// Database connection
extern sqlite3* db;

// Function declarations
bool openDatabase();
void closeDatabase();
bool initializeDatabase();
bool submitMaintenanceRequest(int tenantId, const std::string& description);
std::string renderTenantPage(int tenantId);
std::string renderPortfolioSummary();
void startServer(int port);
void handle_request(int client_socket);

#endif // PORTFOLIO_MANAGEMENT_H
#include "portfolio_management.h"

sqlite3* db = nullptr;  // Database connection

// Open the SQLite database connection
bool openDatabase() {
    int result = sqlite3_open("portfolio_management.db", &db);
    if (result != SQLITE_OK) {
        std::cerr << "SQLite error: " << sqlite3_errmsg(db) << std::endl;
        return true;
    }
    return false;
}

// Close the SQLite database connection
void closeDatabase() {
    if (db) {
        sqlite3_close(db);
    }
}

// Initialize database by creating required tables
bool initializeDatabase() {
    const char* create_properties_table = 
    "CREATE TABLE IF NOT EXISTS properties ("
    "id INTEGER PRIMARY KEY AUTOINCREMENT, "
    "address TEXT NOT NULL, "
    "type TEXT NOT NULL, "
    "rent_income REAL NOT NULL);";

    const char* create_tenants_table = 
    "CREATE TABLE IF NOT EXISTS tenants ("
    "tenant_id INTEGER PRIMARY KEY AUTOINCREMENT, "
    "name TEXT NOT NULL, "
    "email TEXT NOT NULL, "
    "lease_status TEXT NOT NULL);";

    const char* create_maintenance_requests_table = 
    "CREATE TABLE IF NOT EXISTS maintenance_requests ("
    "request_id INTEGER PRIMARY KEY AUTOINCREMENT, "
    "tenant_id INTEGER NOT NULL, "
    "description TEXT NOT NULL, "
    "status TEXT NOT NULL DEFAULT 'Pending', "
    "FOREIGN KEY(tenant_id) REFERENCES tenants(tenant_id));";

    char* errMsg = 0;
    int result;

    // Execute the SQL commands to create tables
    result = sqlite3_exec(db, create_properties_table, 0, 0, &errMsg);
    if (result != SQLITE_OK) {
        std::cerr << "SQLite error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
        return false;
    }

    result = sqlite3_exec(db, create_tenants_table, 0, 0, &errMsg);
    if (result != SQLITE_OK) {
        std::cerr << "SQLite error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
        return false;
    }

    result = sqlite3_exec(db, create_maintenance_requests_table, 0, 0, &errMsg);
    if (result != SQLITE_OK) {
        std::cerr << "SQLite error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
        return false;
    }

    return true;
}

// Function to submit maintenance request (stores it in the database)
bool submitMaintenanceRequest(int tenantId, const std::string& description) {
    std::string sql = "INSERT INTO maintenance_requests (tenant_id, description) VALUES (" + std::to_string(tenantId) + ", '" + description + "');";
    char* errMsg = 0;
    int result = sqlite3_exec(db, sql.c_str(), 0, 0, &errMsg);

    if (result != SQLITE_OK) {
        std::cerr << "SQLite error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
        return false;
    }
    return true;
}

// Function to render tenant page
std::string renderTenantPage(int tenantId) {
    std::string sql = "SELECT name, email, lease_status FROM tenants WHERE tenant_id = " + std::to_string(tenantId) + ";";
    sqlite3_stmt* stmt;
    int result = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);

    if (result != SQLITE_OK) {
        std::cerr << "SQLite error: " << sqlite3_errmsg(db) << std::endl;
        return "<html><body><h1>Error fetching tenant data</h1></body></html>";
    }

    result = sqlite3_step(stmt);
    std::string tenantPage = "<html><body><h1>Tenant Details</h1>";

    if (result == SQLITE_ROW) {
        const char* name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        const char* email = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        const char* lease_status = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));

        tenantPage += "<p>Name: " + std::string(name) + "</p>";
        tenantPage += "<p>Email: " + std::string(email) + "</p>";
        tenantPage += "<p>Lease Status: " + std::string(lease_status) + "</p>";
    }

    tenantPage += "<h2>Maintenance Requests</h2>";
    sql = "SELECT description, status FROM maintenance_requests WHERE tenant_id = " + std::to_string(tenantId) + ";";
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);
    result = sqlite3_step(stmt);

    while (result == SQLITE_ROW) {
        const char* description = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        const char* status = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        tenantPage += "<p>" + std::string(description) + " - " + std::string(status) + "</p>";
        result = sqlite3_step(stmt);
    }

    tenantPage += "<a href='/'>Back to Home</a>";
    tenantPage += "</body></html>";
    sqlite3_finalize(stmt);

    return tenantPage;
}

// Function to render portfolio summary page
std::string renderPortfolioSummary() {
    std::string sql = "SELECT address, type, rent_income FROM properties;";
    sqlite3_stmt* stmt;
    int result = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);

    if (result != SQLITE_OK) {
        std::cerr << "SQLite error: " << sqlite3_errmsg(db) << std::endl;
        return "<html><body><h1>Error fetching properties</h1></body></html>";
    }

    std::string portfolioPage = "<html><body><h1>Portfolio Summary</h1><table border='1'>";
    portfolioPage += "<tr><th>Address</th><th>Type</th><th>Rent Income</th></tr>";

    result = sqlite3_step(stmt);
    while (result == SQLITE_ROW) {
        const char* address = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        const char* type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        double rent_income = sqlite3_column_double(stmt, 2);
        
        portfolioPage += "<tr>";
        portfolioPage += "<td>" + std::string(address) + "</td>";
        portfolioPage += "<td>" + std::string(type) + "</td>";
        portfolioPage += "<td>" + std::to_string(rent_income) + "</td>";
        portfolioPage += "</tr>";

        result = sqlite3_step(stmt);
    }

    portfolioPage += "</table><a href='/'>Back to Home</a></body></html>";
    sqlite3_finalize(stmt);

    return portfolioPage;
}

// Function to handle requests from clients (server loop)
void startServer(int port) {
    int server_fd, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    std::cout << "Server is running on port " << port << std::endl;

    // Server loop
    while (true) {
        if ((client_socket = accept(server_fd, (struct sockaddr*)&client_addr, &client_len)) < 0) {
            perror("Accept failed");
            exit(EXIT_FAILURE);
        }

        // Handle client request
        handle_request(client_socket);
    }
}
#include "portfolio_management.h"

int main() {
    if (openDatabase()) {
        std::cerr << "Failed to open the database" << std::endl;
        return 1;
    }

    if (!initializeDatabase()) {
        std::cerr << "Failed to initialize the database" << std::endl;
        return 1;
    }

    startServer(8080);

    closeDatabase();
    return 0;
}
