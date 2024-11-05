#include "PropertyManagementSystem.h"
#include <stdexcept>
#include <iostream>
#include <unordered_map>
#include <vector>

using namespace std;

// Constructor: Initializes the SQL connection
PropertyManagementSystem::PropertyManagementSystem() {
    driver = sql::mysql::get_mysql_driver_instance();
    conn = unique_ptr<sql::Connection>(driver->connect("tcp://localhost:3306", "username", "password"));
    conn->setSchema("property_management_db");
}

// Destructor: Closes the SQL connection
PropertyManagementSystem::~PropertyManagementSystem() {
    conn->close();
}

// User login function
bool PropertyManagementSystem::userLogin(const string& username, const string& password) {
    try {
        unique_ptr<sql::PreparedStatement> pstmt(
            conn->prepareStatement("SELECT COUNT(*) FROM users WHERE username = ? AND password = ?")
        );
        pstmt->setString(1, username);
        pstmt->setString(2, password);
        unique_ptr<sql::ResultSet> res(pstmt->executeQuery());
        
        if (res->next() && res->getInt(1) > 0) {
            cout << "User login successful for " << username << endl;
            return true;
        }
    } catch (sql::SQLException& e) {
        cerr << "Error in userLogin: " << e.what() << endl;
    }
    return false;
}

// Security functions
void PropertyManagementSystem::setupTwoFactorAuth(const string& username) {
    try {
        unique_ptr<sql::PreparedStatement> pstmt(
            conn->prepareStatement("UPDATE users SET two_factor_enabled = 1 WHERE username = ?")
        );
        pstmt->setString(1, username);
        pstmt->executeUpdate();
        cout << "Two-factor authentication set up for user: " << username << endl;
    } catch (sql::SQLException& e) {
        cerr << "Error in setupTwoFactorAuth: " << e.what() << endl;
    }
}

void PropertyManagementSystem::changePassword(const string& username, const string& newPassword) {
    try {
        unique_ptr<sql::PreparedStatement> pstmt(
            conn->prepareStatement("UPDATE users SET password = ? WHERE username = ?")
        );
        pstmt->setString(1, newPassword);
        pstmt->setString(2, username);
        pstmt->executeUpdate();
        cout << "Password changed for user: " << username << endl;
    } catch (sql::SQLException& e) {
        cerr << "Error in changePassword: " << e.what() << endl;
    }
}

void PropertyManagementSystem::grantRole(const string& username, const string& role) {
    try {
        unique_ptr<sql::PreparedStatement> pstmt(
            conn->prepareStatement("UPDATE users SET role = ? WHERE username = ?")
        );
        pstmt->setString(1, role);
        pstmt->setString(2, username);
        pstmt->executeUpdate();
        cout << "Role " << role << " granted to user: " << username << endl;
    } catch (sql::SQLException& e) {
        cerr << "Error in grantRole: " << e.what() << endl;
    }
}

void PropertyManagementSystem::logAuditEvent(const string& action, const string& username) {
    try {
        unique_ptr<sql::PreparedStatement> pstmt(
            conn->prepareStatement("INSERT INTO audit_logs (username, action, timestamp) VALUES (?, ?, NOW())")
        );
        pstmt->setString(1, username);
        pstmt->setString(2, action);
        pstmt->executeUpdate();
        cout << "Audit event logged: " << action << " by " << username << endl;
    } catch (sql::SQLException& e) {
        cerr << "Error in logAuditEvent: " << e.what() << endl;
    }
}

void PropertyManagementSystem::detectIntrusion(const string& ipAddress) {
    try {
        unique_ptr<sql::PreparedStatement> pstmt(
            conn->prepareStatement("INSERT INTO intrusion_logs (ip_address, timestamp) VALUES (?, NOW())")
        );
        pstmt->setString(1, ipAddress);
        pstmt->executeUpdate();
        cout << "Intrusion detected from IP: " << ipAddress << endl;
    } catch (sql::SQLException& e) {
        cerr << "Error in detectIntrusion: " << e.what() << endl;
    }
}

void PropertyManagementSystem::backupData() {
    cout << "Data backup in progress..." << endl;
    // Logic to perform data backup (external script or storage routine)
}

void PropertyManagementSystem::whitelistIP(const string& ipAddress) {
    try {
        unique_ptr<sql::PreparedStatement> pstmt(
            conn->prepareStatement("INSERT INTO ip_whitelist (ip_address) VALUES (?)")
        );
        pstmt->setString(1, ipAddress);
        pstmt->executeUpdate();
        cout << "IP address " << ipAddress << " whitelisted." << endl;
    } catch (sql::SQLException& e) {
        cerr << "Error in whitelistIP: " << e.what() << endl;
    }
}

void PropertyManagementSystem::validateFileUpload(const string& filename) {
    cout << "Validating file: " << filename << endl;
    // Logic for file validation (checking file type, size, etc.)
}

void PropertyManagementSystem::checkSessionTimeout(const string& username) {
    cout << "Checking session timeout for user: " << username << endl;
    // Logic to check session timeout (based on last activity timestamp)
}

// Misuse case implementations
void PropertyManagementSystem::checkUnauthorizedAccess(int propertyId, const string& username) {
    // Logic to check for unauthorized access to property data
    cout << "Checking unauthorized access for user: " << username << " on property ID: " << propertyId << endl;
}

void PropertyManagementSystem::checkDataTampering(int propertyId) {
    // Logic to check for data tampering
    cout << "Checking for data tampering on property ID: " << propertyId << endl;
}

void PropertyManagementSystem::deleteProperty(int propertyId) {
    // Logic to handle property deletion
    cout << "Attempting to delete property ID: " << propertyId << endl;
}

void PropertyManagementSystem::overrideMaintenanceRequest(int requestId, const string& username) {
    // Logic to override maintenance requests
    cout << "User: " << username << " is attempting to override maintenance request ID: " << requestId << endl;
}

void PropertyManagementSystem::assignVendor(int vendorId, const string& username) {
    // Logic to assign a vendor
    cout << "User: " << username << " is assigning vendor ID: " << vendorId << endl;
}

void PropertyManagementSystem::changeUserRole(const string& username, const string& newRole) {
    // Logic to change user roles
    cout << "Changing role for user: " << username << " to " << newRole << endl;
}

void PropertyManagementSystem::manipulateFinancialData(int propertyId, const string& username) {
    // Logic to manipulate financial data
    cout << "User: " << username << " is attempting to manipulate financial data for property ID: " << propertyId << endl;
}

void PropertyManagementSystem::misuseCommunicationChannels(int userId) {
    // Logic to check for misuse of communication channels
    cout << "Checking for misuse of communication channels for user ID: " << userId << endl;
}

void PropertyManagementSystem::deleteSystemLogs() {
    // Logic to delete system logs
    cout << "Attempting to delete system logs." << endl;
}

void PropertyManagementSystem::handleExcessiveLoginAttempts(const string& username) {
    // Logic to handle excessive login attempts
    cout << "Checking for excessive login attempts for user: " << username << endl;
}
