#include <iostream>
#include <string>
#include <sstream>
#include <unistd.h>
#include <netinet/in.h>
#include <sqlite3.h>

#define PORT 8080
#define BACKLOG 5

// SQLite database setup
sqlite3* db;
char* errMsg = 0;

bool openDatabase() {
    if (sqlite3_open("realestate.db", &db)) {
        std::cerr << "Failed to open database: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    return true;
}

void closeDatabase() {
    sqlite3_close(db);
}

bool getUserFromDB(const std::string& username, const std::string& password) {
    std::string sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "';";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0) != SQLITE_OK) {
        std::cerr << "SQLite error: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    int result = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (result == SQLITE_ROW);
}

// Function to handle requests
void handle_request(int client_socket) {
    char buffer[1024];
    std::string request;
    int received = recv(client_socket, buffer, sizeof(buffer), 0);
    if (received < 0) {
        std::cerr << "Error reading request" << std::endl;
        return;
    }
    buffer[received] = '\0';
    request = std::string(buffer);

    std::string response;
    if (strstr(buffer, "GET /")) {
        // Render homepage or any other page
        response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Type: text/html\r\n";
        response += "Connection: close\r\n\r\n";
        response += "<html><body><h1>Welcome to the Real Estate Management System</h1></body></html>";
    }
    else if (strstr(buffer, "POST /login")) {
        // Extract login data
        std::string postData = request.substr(request.find("\r\n\r\n") + 4);
        size_t userPos = postData.find("username=") + 9;
        size_t passPos = postData.find("password=") + 9;
        size_t userEnd = postData.find("&", userPos);
        std::string username = postData.substr(userPos, userEnd - userPos);
        std::string password = postData.substr(passPos);

        bool success = getUserFromDB(username, password);

        response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Type: text/html\r\n";
        response += "Connection: close\r\n\r\n";
        response += "<html><body>";
        response += success ? "<h1>Login Successful!</h1>" : "<h1>Login Failed!</h1>";
        response += "<a href='/'>Back to Home</a>";
        response += "</body></html>";
    }
    else if (strstr(buffer, "POST /maintenance")) {
        // Extract maintenance request data
        std::string postData = request.substr(request.find("\r\n\r\n") + 4);
        size_t idPos = postData.find("tenant_id=") + 10;
        size_t descPos = postData.find("description=") + 12;
        size_t idEnd = postData.find("&", idPos);
        int tenantId = std::stoi(postData.substr(idPos, idEnd - idPos));
        std::string description = postData.substr(descPos);

        // Normally, you would insert this data into the database here, e.g., pms.submitMaintenanceRequest(tenantId, description);
        // For now, we will just simulate the process.

        response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Type: text/html\r\n";
        response += "Connection: close\r\n\r\n";
        response += "<html><body>";
        response += "<h1>Maintenance Request Submitted!</h1>";
        response += "<a href='/'>Back to Home</a>";
        response += "</body></html>";
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

// Server setup
int main() {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;

    if (!openDatabase()) {
        std::cerr << "Database connection failed!" << std::endl;
        return 1;
    }

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        std::cerr << "Failed to create socket." << std::endl;
        closeDatabase();
        return 1;
    }

    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::cerr << "Failed to set socket options." << std::endl;
        close(server_socket);
        closeDatabase();
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (::bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Failed to bind to port." << std::endl;
        close(server_socket);
        closeDatabase();
        return 1;
    }

    if (listen(server_socket, BACKLOG) < 0) {
        std::cerr << "Listen failed." << std::endl;
        close(server_socket);
        closeDatabase();
        return 1;
    }

    std::cout << "Server running on port " << PORT << "..." << std::endl;

    client_len = sizeof(client_addr);
    while (true) {
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket < 0) {
            std::cerr << "Failed to accept connection." << std::endl;
            continue;
        }

        handle_request(client_socket);
    }

    close(server_socket);
    closeDatabase();
    return 0;
}
// Function to handle maintenance requests
bool submitMaintenanceRequest(int tenantId, const std::string& description) {
    // Insert the maintenance request into the database (this is a basic example)
    std::string sql = "INSERT INTO maintenance_requests (tenant_id, description) VALUES (" + std::to_string(tenantId) + ", '" + description + "');";
    char* errMsg = 0;
    int rc = sqlite3_exec(db, sql.c_str(), 0, 0, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQLite error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
        return false;
    }
    return true;
}

// Function to handle tenant data page
std::string renderTenantPage(int tenantId) {
    std::string sql = "SELECT * FROM tenants WHERE tenant_id = " + std::to_string(tenantId) + ";";
    sqlite3_stmt* stmt;
    std::string htmlContent = "<html><body>";

    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0) != SQLITE_OK) {
        std::cerr << "SQLite error: " << sqlite3_errmsg(db) << std::endl;
        return "Error fetching tenant data.";
    }

    int result = sqlite3_step(stmt);
    if (result == SQLITE_ROW) {
        // Assuming tenant data has columns: tenant_id, name, email, lease_status
        htmlContent += "<h2>Tenant Information</h2>";
        htmlContent += "<p>ID: " + std::to_string(sqlite3_column_int(stmt, 0)) + "</p>";
        htmlContent += "<p>Name: " + std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1))) + "</p>";
        htmlContent += "<p>Email: " + std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2))) + "</p>";
        htmlContent += "<p>Lease Status: " + std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3))) + "</p>";
    } else {
        htmlContent += "<p>No tenant found with that ID.</p>";
    }

    sqlite3_finalize(stmt);
    htmlContent += "<a href='/'>Back to Home</a>";
    htmlContent += "</body></html>";
    return htmlContent;
}

// Function to handle portfolio summary page
std::string renderPortfolioSummary() {
    std::string sql = "SELECT * FROM properties;";
    sqlite3_stmt* stmt;
    std::string htmlContent = "<html><body>";
    htmlContent += "<h2>Property Portfolio Summary</h2>";

    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0) != SQLITE_OK) {
        std::cerr << "SQLite error: " << sqlite3_errmsg(db) << std::endl;
        return "Error fetching portfolio data.";
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        // Assuming property data has columns: property_id, address, type, rent_income
        htmlContent += "<div><p>Property ID: " + std::to_string(sqlite3_column_int(stmt, 0)) + "</p>";
        htmlContent += "<p>Address: " + std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1))) + "</p>";
        htmlContent += "<p>Type: " + std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2))) + "</p>";
        htmlContent += "<p>Rent Income: $" + std::to_string(sqlite3_column_double(stmt, 3)) + "</p></div><hr>";
    }

    sqlite3_finalize(stmt);
    htmlContent += "<a href='/'>Back to Home</a>";
    htmlContent += "</body></html>";
    return htmlContent;
}

// Updated request handler to include more pages
void handle_request(int client_socket) {
    char buffer[1024];
    std::string request;
    int received = recv(client_socket, buffer, sizeof(buffer), 0);
    if (received < 0) {
        std::cerr << "Error reading request" << std::endl;
        return;
    }
    buffer[received] = '\0';
    request = std::string(buffer);

    std::string response;
    if (strstr(buffer, "GET /")) {
        // Render homepage or any other page
        response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Type: text/html\r\n";
        response += "Connection: close\r\n\r\n";
        response += "<html><body><h1>Welcome to the Real Estate Management System</h1>";
        response += "<a href='/tenant/1'>View Tenant 1</a><br>";
        response += "<a href='/portfolio'>View Portfolio Summary</a><br>";
        response += "<form action='/login' method='post'>";
        response += "Username: <input type='text' name='username'><br>";
        response += "Password: <input type='password' name='password'><br>";
        response += "<input type='submit' value='Login'>";
        response += "</form></body></html>";
    }
    else if (strstr(buffer, "POST /login")) {
        // Extract login data
        std::string postData = request.substr(request.find("\r\n\r\n") + 4);
        size_t userPos = postData.find("username=") + 9;
        size_t passPos = postData.find("password=") + 9;
        size_t userEnd = postData.find("&", userPos);
        std::string username = postData.substr(userPos, userEnd - userPos);
        std::string password = postData.substr(passPos);

        bool success = getUserFromDB(username, password);

        response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Type: text/html\r\n";
        response += "Connection: close\r\n\r\n";
        response += "<html><body>";
        response += success ? "<h1>Login Successful!</h1>" : "<h1>Login Failed!</h1>";
        response += "<a href='/'>Back to Home</a>";
        response += "</body></html>";
    }
    else if (strstr(buffer, "POST /maintenance")) {
        // Extract maintenance request data
        std::string postData = request.substr(request.find("\r\n\r\n") + 4);
        size_t idPos = postData.find("tenant_id=") + 10;
        size_t descPos = postData.find("description=") + 12;
        size_t idEnd = postData.find("&", idPos);
        int tenantId = std::stoi(postData.substr(idPos, idEnd - idPos));
        std::string description = postData.substr(descPos);

        bool success = submitMaintenanceRequest(tenantId, description);

        response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Type: text/html\r\n";
        response += "Connection: close\r\n\r\n";
        response += "<html><body>";
        response += success ? "<h1>Maintenance Request Submitted!</h1>" : "<h1>Failed to Submit Request</h1>";
        response += "<a href='/'>Back to Home</a>";
        response += "</body></html>";
    }
    else if (strstr(buffer, "GET /tenant/")) {
        // Render tenant page
        int tenantId = std::stoi(request.substr(request.find("/tenant/") + 8));
        response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Type: text/html\r\n";
        response += "Connection: close\r\n\r\n";
        response += renderTenantPage(tenantId);
    }
    else if (strstr(buffer, "GET /portfolio")) {
        // Render portfolio page
        response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Type: text/html\r\n";
        response += "Connection: close\r\n\r\n";
        response += renderPortfolioSummary();
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

// Utility function to check if a user exists
bool getUserFromDB(const std::string& username, const std::string& password) {
    std::string sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "';";
    sqlite3_stmt* stmt;
    int result = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);

    if (result != SQLITE_OK) {
        std::cerr << "SQLite error: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    result = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (result == SQLITE_ROW);
}

// Function to initialize the database (create tables)
void initializeDatabase() {
    const char* create_users_table = "CREATE TABLE IF NOT EXISTS users ("
                                     "user_id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                     "username TEXT NOT NULL, "
                                     "password TEXT NOT NULL, "
                                     "role TEXT NOT NULL);";
    const char* create_tenants_table = "CREATE TABLE IF NOT EXISTS tenants ("
                                       "tenant_id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                       "name TEXT NOT NULL, "
                                       "email TEXT NOT NULL, "
                                       "lease_status TEXT NOT NULL);";
    const char* create_properties_table = "CREATE TABLE IF NOT EXISTS properties ("
                                         "property_id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                         "address TEXT NOT NULL, "
                                         "type TEXT NOT NULL, "
                                         "rent_income REAL NOT NULL);";
    const char* create_maintenance_requests_table = "CREATE TABLE IF NOT EXISTS maintenance_requests ("
                                                   "request_id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                   "tenant_id INTEGER NOT NULL, "
                                                   "description TEXT NOT NULL, "
                                                   "FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id));";

    char* errMsg = 0;
    if (sqlite3_exec(db, create_users_table, 0, 0, &errMsg) != SQLITE_OK) {
        std::cerr << "SQLite error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
    }

    if (sqlite3_exec(db, create_tenants_table, 0, 0, &errMsg) != SQLITE_OK) {
        std::cerr << "SQLite error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
    }

    if (sqlite3_exec(db, create_properties_table, 0, 0, &errMsg) != SQLITE_OK) {
        std::cerr << "SQLite error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
    }

    if (sqlite3_exec(db, create_maintenance_requests_table, 0, 0, &errMsg) != SQLITE_OK) {
        std::cerr << "SQLite error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
    }
}

// Function to handle user role-based access control
bool hasAccess(const std::string& username, const std::string& requiredRole) {
    std::string sql = "SELECT role FROM users WHERE username = '" + username + "';";
    sqlite3_stmt* stmt;
    int result = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);

    if (result != SQLITE_OK) {
        std::cerr << "SQLite error: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    result = sqlite3_step(stmt);
    if (result == SQLITE_ROW) {
        std::string role = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        sqlite3_finalize(stmt);
        return (role == requiredRole);
    }

    sqlite3_finalize(stmt);
    return false;
}

// Function to authenticate the user (simple username and password check)
bool authenticateUser(const std::string& username, const std::string& password) {
    return getUserFromDB(username, password);
}

// Function to initialize SQLite database connection
int openDatabase() {
    if (sqlite3_open("real_estate.db", &db)) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        return 1;
    }
    return 0;
}

// Function to close SQLite database connection
void closeDatabase() {
    sqlite3_close(db);
}

// Request handler for handling login requests
void handleLoginRequest(int client_socket, const std::string& request) {
    size_t userPos = request.find("username=") + 9;
    size_t passPos = request.find("password=") + 9;
    size_t userEnd = request.find("&", userPos);
    std::string username = request.substr(userPos, userEnd - userPos);
    std::string password = request.substr(passPos);

    bool success = authenticateUser(username, password);

    std::string response = "HTTP/1.1 200 OK\r\n";
    response += "Content-Type: text/html\r\n";
    response += "Connection: close\r\n\r\n";
    response += "<html><body>";
    response += success ? "<h1>Login Successful!</h1>" : "<h1>Login Failed!</h1>";
    response += "<a href='/'>Back to Home</a>";
    response += "</body></html>";

    send(client_socket, response.c_str(), response.size(), 0);
    close(client_socket);
}

// Handle the request (full version handling more routes)
void handle_request(int client_socket) {
    char buffer[1024];
    std::string request;
    int received = recv(client_socket, buffer, sizeof(buffer), 0);
    if (received < 0) {
        std::cerr << "Error reading request" << std::endl;
        return;
    }
    buffer[received] = '\0';
    request = std::string(buffer);

    std::string response;
    if (strstr(buffer, "GET /")) {
        // Render homepage or any other page
        response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Type: text/html\r\n";
        response += "Connection: close\r\n\r\n";
        response += "<html><body><h1>Welcome to the Real Estate Management System</h1>";
        response += "<a href='/tenant/1'>View Tenant 1</a><br>";
        response += "<a href='/portfolio'>View Portfolio Summary</a><br>";
        response += "<form action='/login' method='post'>";
        response += "Username: <input type='text' name='username'><br>";
        response += "Password: <input type='password' name='password'><br>";
        response += "<input type='submit' value='Login'>";
        response += "</form></body></html>";
    }
    else if (strstr(buffer, "POST /login")) {
        handleLoginRequest(client_socket, request);
    }
    else if (strstr(buffer, "POST /maintenance")) {
        // Extract maintenance request data
        std::string postData = request.substr(request.find("\r\n\r\n") + 4);
        size_t idPos = postData.find("tenant_id=") + 10;
        size_t descPos = postData.find("description=") + 12;
        size_t idEnd = postData.find("&", idPos);
        int tenantId = std::stoi(postData.substr(idPos, idEnd - idPos));
        std::string description = postData.substr(descPos);

        bool success = submitMaintenanceRequest(tenantId, description);

        response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Type: text/html\r\n";
        response += "Connection: close\r\n\r\n";
        response += "<html><body>";
        response += success ? "<h1>Maintenance Request Submitted!</h1>" : "<h1>Failed to Submit Request</h1>";
        response += "<a href='/'>Back to Home</a>";
        response += "</body></html>";
    }
    else if (strstr(buffer, "GET /tenant/")) {
        // Render tenant page
        int tenantId = std::stoi(request.substr(request.find("/tenant/") + 8));
        response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Type: text/html\r\n";
        response += "Connection: close\r\n\r\n";
        response += renderTenantPage(tenantId);
    }
    else if (strstr(buffer, "GET /portfolio")) {
        // Render portfolio page
        response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Type: text/html\r\n";
        response += "Connection: close\r\n\r\n";
        response += renderPortfolioSummary();
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
int main() {
    // Open SQLite database
    if (openDatabase()) {
        std::cerr << "Failed to open the database" << std::endl;
        return 1;
    }

    // Initialize the database and create tables
    initializeDatabase();

    // Start the server loop (on port 8080)
    startServer(8080);

    // Close the database connection
    closeDatabase();

    return 0;
}
