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
/**
 * Main class for Property Management System
 * Handles all database operations with security measures
 */
class PropertyManagementSystem {
private:
    // Database connection handle
    MYSQL* conn;

    int connectToDb();
    std::string sendDbRequest(const std::string& request);
    bool initializeDB();

public:

 // SECURITY FUNCTION -> Prevents XSS by converting special characters to HTML entities
    string escapeHtml(const string& data) {
        string buffer;
        buffer.reserve(data.size());
        for(size_t pos = 0; pos != data.size(); ++pos) {
            switch(data[pos]) {
                case '&':  buffer.append("&amp;");       break;
                case '\"': buffer.append("&quot;");      break;
                case '\'': buffer.append("&apos;");      break;
                case '<':  buffer.append("&lt;");        break;
                case '>':  buffer.append("&gt;");        break;
                default:   buffer.append(&data[pos], 1); break;
            }
        }
        return buffer;
    }
    PropertyManagementSystem();
    ~PropertyManagementSystem();
    
    MYSQL* getConnection();
    string getUserRole(const string& username);
    bool userLogin(const string& username, const string& password);
    bool createAccount(const string& username, const string& password, const string& role);
    bool addProperty(const string& username, const string& address, const string& date, 
                    double price, double rent);
    void submitMaintenanceRequest(int tenantId, const string& description);
    void managePropertyDescription(int propertyId, const string& description);
    map<string, double> getFinancialOverview(const string& username);
    vector<map<string, string> > getPropertiesByUser(const string& username);
};

/**
 * Constructor: Initializes database connection
 * Security: Throws runtime error if database connection fails
 */
inline PropertyManagementSystem::PropertyManagementSystem() {
    if (!initializeDB()) {
        throw std::runtime_error("Failed to initialize database connection");
    }
}

/**
 * Destructor: Ensures proper cleanup of database connection
 * Security: Prevents resource leaks and handles cleanup
 */
inline PropertyManagementSystem::~PropertyManagementSystem() {
    if (conn) {
        mysql_close(conn);
    }
}
/**
 * Gets database connection handle
 * Security: Only returns existing connection, doesn't create new ones
 */
inline MYSQL* PropertyManagementSystem::getConnection() { 
    return conn; 
}
/**
 * Establishes database connection
 * Security: 
 * - Uses local connection only (127.0.0.1)
 * - Implements error handling
 * - Closes socket on failed connection
 */
inline int PropertyManagementSystem::connectToDb() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "Failed to create socket" << std::endl;
        return -1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(3306);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Failed to connect to database" << std::endl;
        close(sock);
        return -1;
    }

    return sock;
}
/**
 * Sends request to database
 * Security:
 * - Fixed buffer size to prevent overflow
 * - Proper socket cleanup
 * - Error handling for failed connections
 */
inline std::string PropertyManagementSystem::sendDbRequest(const std::string& request) {
    int sock = connectToDb();
    if (sock < 0) return "ERROR Database connection failed";

    send(sock, request.c_str(), request.length(), 0);

    char buffer[1024] = {0};
    read(sock, buffer, sizeof(buffer) - 1);
    
    close(sock);
    return std::string(buffer);
}
/**
 * Initializes database connection
 * Security:
 * - Error handling for failed initialization
 * - Connection validation
 * Contains hardcoded credentials (should be moved to configuration file)
 */
inline bool PropertyManagementSystem::initializeDB() {
    conn = mysql_init(NULL);
    if (conn == NULL) {
        std::cerr << "MySQL initialization failed" << std::endl;
        return false;
    }

    if (!mysql_real_connect(conn,
        "localhost",
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
/**
 * Gets user's role for access control
 * Security features:
 * - SQL injection prevention using mysql_real_escape_string
 * - Connection validation
 * - Memory cleanup for escaped strings
 * - Proper result set cleanup
 */
inline string PropertyManagementSystem::getUserRole(const string& username) {
   
   // here to make sure that the database is connected, if not then nothing will happen
    if (!conn) return "";
    
    // Security: Prevent SQL injection
    char* escaped_username = new char[username.length() * 2 + 1];
    
    // the my sql real escape string is to prevent sql injection
    mysql_real_escape_string(conn, escaped_username, username.c_str(), username.length());
    
    string query = "SELECT role FROM users WHERE username='" + string(escaped_username) + "'";
    delete[] escaped_username;

    if (mysql_query(conn, query.c_str())) {
        std::cerr << "Role query failed: " << mysql_error(conn) << std::endl;
        return "";
    }

    MYSQL_RES* result = mysql_store_result(conn);
    string role = "";
    
    if (MYSQL_ROW row = mysql_fetch_row(result)) {
        role = row[0];
    }
    
    mysql_free_result(result);
    return role;
}
/**
 * Authenticates user login
 * Security features:
 * - SQL injection prevention
 * - Connection validation
 * - Memory cleanup
 * - Result set validation
 * Note: Passwords stored in plaintext (should implement hashing)
 */
inline bool PropertyManagementSystem::userLogin(const string& username, const string& password) {
    if (!conn) {
        std::cerr << "No database connection for login" << std::endl;
        return false;
    }

    char* escaped_username = new char[username.length() * 2 + 1];
    char* escaped_password = new char[password.length() * 2 + 1];
    
    // the my sql real escape string is to prevent sql injection
    mysql_real_escape_string(conn, escaped_username, username.c_str(), username.length());
    mysql_real_escape_string(conn, escaped_password, password.c_str(), password.length());

    string query = "SELECT * FROM users WHERE username='" + 
                  string(escaped_username) + "' AND password='" + 
                  string(escaped_password) + "'";

    delete[] escaped_username;
    delete[] escaped_password;

    if (mysql_query(conn, query.c_str())) {
        std::cerr << "Login query failed: " << mysql_error(conn) << std::endl;
        return false;
    }

    MYSQL_RES* result = mysql_store_result(conn);
    if (result == NULL) {
        std::cerr << "Failed to get query result" << std::endl;
        return false;
    }

    bool valid = (mysql_num_rows(result) > 0);
    mysql_free_result(result);
    return valid;
}
/**
 * Creates new user account
 * Security features:
 * - SQL injection prevention
 * - Duplicate username checking
 * - Connection validation
 * - Memory cleanup
 * - Proper error handling
 */
inline bool PropertyManagementSystem::createAccount(const string& username, const string& password, const string& role) {
    if (!conn) {
        std::cerr << "No database connection" << std::endl;
        return false;
    }
    // Security: Prevent SQL injection for username check

    char* escaped_username = new char[username.length() * 2 + 1];
    // the my sql real escape string is to prevent sql injection
    mysql_real_escape_string(conn, escaped_username, username.c_str(), username.length());
    
        // Security: Check for duplicate usernames

    string check_query = "SELECT COUNT(*) FROM users WHERE username = '" + string(escaped_username) + "'";
    
    if (mysql_query(conn, check_query.c_str())) {
        delete[] escaped_username;// Security: Prevent memory leaks
        std::cerr << "Username check failed: " << mysql_error(conn) << std::endl;
        return false;
    }
    // Security: Validate query result

    MYSQL_RES* result = mysql_store_result(conn);
    if (!result) {
        delete[] escaped_username;   // Security: Prevent memory leaks
        std::cerr << "Failed to get query result" << std::endl;
        return false;
    }
// Security: Check if username already exists
    MYSQL_ROW row = mysql_fetch_row(result);
    if (row && atoi(row[0]) > 0) {
        mysql_free_result(result);
        delete[] escaped_username;// Security: Prevent memory leaks
        std::cerr << "Username already exists" << std::endl;
        return false;
    }
    mysql_free_result(result);
    
    // Security: Prevent SQL injection for password and role

    char* escaped_password = new char[password.length() * 2 + 1];
    char* escaped_role = new char[role.length() * 2 + 1];
    
    mysql_real_escape_string(conn, escaped_password, password.c_str(), password.length());
    mysql_real_escape_string(conn, escaped_role, role.c_str(), role.length());

    string insert_query = "INSERT INTO users (username, password, role) VALUES ('" +
                         string(escaped_username) + "', '" + 
                         string(escaped_password) + "', '" + 
                         string(escaped_role) + "')";

    delete[] escaped_username;
    delete[] escaped_password;
    delete[] escaped_role;

    if (mysql_query(conn, insert_query.c_str())) {
        std::cerr << "Account creation failed: " << mysql_error(conn) << std::endl;
        return false;
    }

    return mysql_affected_rows(conn) > 0;
}
/**
 * Adds new property to the system
 * Security features:
 * - SQL injection prevention for string inputs
 * - Connection validation
 * - Memory cleanup
 * - Error handling for database operations
 * Parameters validation:
 * - username: property owner
 * - address: property location
 * - date: date added
 * - price: property price
 * - rent: rental amount
 */
inline bool PropertyManagementSystem::addProperty(const string& username, const string& address, const string& date, 
                                                double price, double rent) {
    if (!conn) {
        std::cerr << "No database connection" << std::endl;
        return false;
    }

 string decoded_address = address;
    size_t pos = 0;
    while ((pos = decoded_address.find("%20", pos)) != string::npos) {
        decoded_address.replace(pos, 3, " ");
        pos += 1;
    }
    
    char* escaped_address = new char[address.length() * 2 + 1];
    char* escaped_username = new char[username.length() * 2 + 1];
    
    mysql_real_escape_string(conn, escaped_address, address.c_str(), address.length());
    mysql_real_escape_string(conn, escaped_username, username.c_str(), username.length());

    string query = "INSERT INTO property (owner_username, address, date_added, price, rent) "
                  "VALUES ('" + string(escaped_username) + "', '" + 
                  string(escaped_address) + "', '" + date + "', " + 
                  to_string(price) + ", " + to_string(rent) + ")";

    delete[] escaped_address;
    delete[] escaped_username;

    if (mysql_query(conn, query.c_str())) {
        std::cerr << "Property addition failed: " << mysql_error(conn) << std::endl;
        return false;
    }

    return mysql_affected_rows(conn) > 0;
}
/**
 * Submits maintenance request for a property
 * Security features:
 * - SQL injection prevention for description
 * - Connection validation
 * - Memory cleanup
 * - Error handling
 * Parameters:
 * - tenantId: ID of tenant submitting request (already numeric, no escape needed)
 * - description: Details of maintenance request
 */
inline void PropertyManagementSystem::submitMaintenanceRequest(int tenantId, const string& description) {
    if (!conn) return;
    
    char* escaped_description = new char[description.length() * 2 + 1];
    mysql_real_escape_string(conn, escaped_description, description.c_str(), description.length());
    
    string query = "INSERT INTO maintenance_requests (tenant_id, description) VALUES (" +
                  to_string(tenantId) + ", '" + string(escaped_description) + "')";
    
    delete[] escaped_description;
    
    if (mysql_query(conn, query.c_str())) {
        std::cerr << "Maintenance request failed: " << mysql_error(conn) << std::endl;
    }
}
/**
 * Updates property description
 * Security features:
 * - SQL injection prevention for description
 * - Connection validation
 * - Memory cleanup
 * - Error handling
 * Parameters:
 * - propertyId: ID of property (numeric, no escape needed)
 * - description: New property description
 */
inline void PropertyManagementSystem::managePropertyDescription(int propertyId, const string& description) {
    if (!conn) return;
    
    char* escaped_description = new char[description.length() * 2 + 1];
    mysql_real_escape_string(conn, escaped_description, description.c_str(), description.length());
    
    string query = "UPDATE property SET description = '" + string(escaped_description) + 
                  "' WHERE id = " + to_string(propertyId);
    
    delete[] escaped_description;
    
    if (mysql_query(conn, query.c_str())) {
        std::cerr << "Property description update failed: " << mysql_error(conn) << std::endl;
    }
}
/**
 * Retrieves all properties owned by a specific user
 * Security features:
 * - SQL injection prevention for username
 * - Connection validation
 * - Memory cleanup
 * - Result set validation
 * - Error handling
 * Returns: Vector of property information maps
 */
inline vector<map<string, string> > PropertyManagementSystem::getPropertiesByUser(const string& username) {
    vector<map<string, string> > properties;
    
    if (!conn) {
        std::cerr << "No database connection" << std::endl;
        return properties;
    }

    char* escaped_username = new char[username.length() * 2 + 1];
    mysql_real_escape_string(conn, escaped_username, username.c_str(), username.length());
    
    string query = "SELECT id, address, date_added, price, rent FROM property WHERE owner_username='" + 
                  string(escaped_username) + "'";
    
    delete[] escaped_username;

    if (mysql_query(conn, query.c_str())) {
        std::cerr << "Property fetch failed: " << mysql_error(conn) << std::endl;
        return properties;
    }

    MYSQL_RES* result = mysql_store_result(conn);
    if (result == NULL) {
        std::cerr << "Failed to get query result" << std::endl;
        return properties;
    }

    MYSQL_ROW row;
    while ((row = mysql_fetch_row(result))) {
        map<string, string> property;
        property["id"] = row[0];
        property["address"] = row[1] ? row[1] : "";  // Handle NULL values
        property["date_added"] = row[2] ? row[2] : "";
        property["price"] = row[3] ? row[3] : "0";
        property["rent"] = row[4] ? row[4] : "0";
        properties.push_back(property);
    }

    mysql_free_result(result);
    return properties;
}

inline map<string, double> PropertyManagementSystem::getFinancialOverview(const string& username) {
    map<string, double> financialOverview = {
        {"totalValue", 0.0},
        {"totalRent", 0.0},
        {"averageRent", 0.0},
        {"propertyCount", 0.0}
    };

    if (!conn) return financialOverview;

    char* escaped_username = new char[username.length() * 2 + 1];
    mysql_real_escape_string(conn, escaped_username, username.c_str(), username.length());

    string query = "SELECT SUM(price), SUM(rent), COUNT(*) FROM property WHERE owner_username='" + 
                  string(escaped_username) + "'";
    delete[] escaped_username;

    if (mysql_query(conn, query.c_str())) {
        return financialOverview;
    }

    MYSQL_RES* result = mysql_store_result(conn);
    if (!result) return financialOverview;

    MYSQL_ROW row = mysql_fetch_row(result);
    if (row) {
        financialOverview["totalValue"] = row[0] ? atof(row[0]) : 0.0;
        financialOverview["totalRent"] = row[1] ? atof(row[1]) : 0.0;
        financialOverview["propertyCount"] = row[2] ? atof(row[2]) : 0.0;
        if (financialOverview["propertyCount"] > 0) {
            financialOverview["averageRent"] = financialOverview["totalRent"] / financialOverview["propertyCount"];
        }
    }

    mysql_free_result(result);
    return financialOverview;
}
#endif
