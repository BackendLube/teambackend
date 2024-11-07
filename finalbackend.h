#ifndef PROPERTY_MANAGEMENT_SYSTEM_H
#define PROPERTY_MANAGEMENT_SYSTEM_H

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <stdexcept>
#include <unordered_map>
#include <memory>
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>

using namespace std;

// Base class for all users
class User {
protected:
    string username;
    string role;

public:
    User(string name, string userRole);
    virtual ~User();
    string getUsername() const;
    string getRole() const;
};

// Property Management System
class PropertyManagementSystem {
private:
    unique_ptr<sql::Connection> conn;
    sql::Driver *driver;
    map<string, string> userPasswords;
    map<string, bool> twoFactorEnabled;
    vector<string> ipWhitelist;

public:
    // Constructor: Initializes the SQL connection
    PropertyManagementSystem();
    // Destructor: Closes the SQL connection
    ~PropertyManagementSystem();

    // User login function with 2FA and IP whitelisting
    bool userLogin(const string& username, const string& password, const string& ipAddress);

    // Helper function for user authentication
    bool authenticateUser(const string& username, const string& password);

    // Setup Two-Factor Authentication (2FA)
    void setupTwoFactorAuth(const string& username);

    // Role-based access control
    void grantRole(const string& username, const string& role, const string& requestedBy);

    // Audit logging
    void logAuditEvent(const string& action, const string& username);

    // Intrusion detection based on excessive login attempts
    void detectIntrusion(const string& ipAddress);

    // Backup data with encryption
    void backupData(bool encrypt = true);

    // IP Whitelisting
    bool isIPWhitelisted(const string& ipAddress);
    void whitelistIP(const string& ipAddress);

    // Validate file uploads
    void validateFileUpload(const string& filename);

    // Check session timeout
    void checkSessionTimeout(const string& username);

    // Misuse case handling (example misuse case)
    void handleExcessiveLoginAttempts(const string& username);
};

#endif // PROPERTY_MANAGEMENT_SYSTEM_H
