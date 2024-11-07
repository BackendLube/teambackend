#ifndef PORTFOLIO_MANAGEMENT_H
#define PORTFOLIO_MANAGEMENT_H

#include <iostream>
#include <string>
#include <sqlite3.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <vector>

// Database connection
extern sqlite3* db;

// Function declarations related to database management
bool openDatabase();
void closeDatabase();
bool initializeDatabase();
bool submitMaintenanceRequest(int tenantId, const std::string& description);
std::string renderTenantPage(int tenantId);
std::string renderPortfolioSummary();
bool addProperty(const std::string& address, const std::string& type, double rent_income);
bool addTenant(const std::string& name, const std::string& email, const std::string& lease_status);
bool updateTenantLease(int tenantId, const std::string& leaseStatus);

// Server functions
void startServer(int port);
void handle_request(int client_socket);
void sendResponse(int client_socket, const std::string& response);

// Utilities (for socket connection)
std::string getClientIP(int client_socket);

// Additional helper functions
std::string queryToHtml(const std::string& sql);
void logError(const std::string& errorMessage);

// Global constants
const int BACKLOG = 10;
const int PORT = 8080;

#endif // PORTFOLIO_MANAGEMENT_H
