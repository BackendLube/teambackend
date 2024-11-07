#ifndef PORTFOLIO_MANAGEMENT_H
#define PORTFOLIO_MANAGEMENT_H

#include <iostream>
#include <string>
#include <sqlite3.h>
#include <netinet/in.h>  // For sockaddr_in (Linux/UNIX)
#include <sys/socket.h>  // For socket functions

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
