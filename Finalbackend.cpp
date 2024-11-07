#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <stdexcept>
#include <unordered_map>

using namespace std;

// Base class for all users
class User {
protected:
    string username;
    string role;
public:
    User(string name, string userRole) 
        : username(name), role(userRole) {}
    virtual ~User() {}
};

// Property Manager class (Admin or Employee)
class PropertyManager : public User {
public:
    PropertyManager(string name, bool isAdmin) 
        : User(name, isAdmin ? "Admin" : "Employee") {}
};

// Tenant class for people living in properties
class Tenant : public User {
public:
    Tenant(string name) : User(name, "Tenant") {}
};

// Real Estate Owner class
class RealEstateOwner : public User {
public:
    RealEstateOwner(string name) : User(name, "Owner") {}
};

// Financial Advisor class
class FinancialAdvisor : public User {
public:
    FinancialAdvisor(string name) : User(name, "Advisor") {}
};

// IT Support class
class ITSupport : public User {
public:
    ITSupport(string name) : User(name, "IT") {}
};

// Structure for property information
struct Property {
    int id;
    string address;
    string description;
    double value;
};

// Structure for maintenance requests
struct MaintenanceRequest {
    int id;
    string description;
    string status;
};

// Structure for vendor information
struct Vendor {
    int id;
    string name;
    bool isVerified;
};

class PropertyManagementSystem {
private:
    sql::mysql::MySQL_Driver* driver;
    unique_ptr<sql::Connection> conn;

public:
    // Constructor: Initializes the SQL connection
    PropertyManagementSystem() {
        driver = sql::mysql::get_mysql_driver_instance();
        conn = unique_ptr<sql::Connection>(driver->connect("tcp://localhost:3306", "username", "password"));
        conn->setSchema("property_management_db");
    }

    // Destructor: Closes the SQL connection
    ~PropertyManagementSystem() {
        conn->close();
    }

    // User login function
    bool userLogin(const string& username, const string& password) {
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

    // Property Management Functions
    void managePropertyDescription(int propertyId, string description) {
        cout << "Managing property " << propertyId << endl;
    }

    void uploadPropertyPhotos(int propertyId, vector<string> photoUrls) {
        cout << "Uploading photos for property " << propertyId << endl;
    }

    void viewPropertyMetrics(int propertyId) {
        cout << "Viewing metrics for property " << propertyId << endl;
    }

    void sendTenantCommunication(int tenantId, string message) {
        cout << "Message sent to tenant " << tenantId << endl;
    }

    void submitMaintenanceRequest(int tenantId, string description) {
        cout << "Maintenance request from tenant " << tenantId << endl;
    }

    void manageVendor(int vendorId, bool verify) {
        cout << "Managing vendor " << vendorId << endl;
    }

    void viewPortfolioOverview(int ownerId) {
        cout << "Viewing portfolio for owner " << ownerId << endl;
    }

    void generateCashFlowForecast(int propertyId) {
        cout << "Generating forecast for property " << propertyId << endl;
    }

    void analyzeInvestment(int propertyId) {
        cout << "Analyzing investment for property " << propertyId << endl;
    }

    // Security Functions
    void setupTwoFactorAuth(const string& username) {
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

    void changePassword(const string& username, const string& newPassword) {
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

    void grantRole(const string& username, const string& role) {
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

    void logAuditEvent(const string& action, const string& username) {
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

    void detectIntrusion(const string& ipAddress) {
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

    void backupData() {
        cout << "Data backup in progress..." << endl;
    }

    void whitelistIP(const string& ipAddress) {
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

    void validateFileUpload(const string& filename) {
        cout << "Validating file: " << filename << endl;
    }

    void checkSessionTimeout(const string& username) {
        cout << "Checking session timeout for user: " << username << endl;
    }

    // Misuse case implementations
    void checkUnauthorizedAccess(int propertyId, const string& username) {
        cout << "Checking unauthorized access for user: " << username << " on property ID: " << propertyId << endl;
    }

    void checkDataTampering(int propertyId) {
        cout << "Checking for data tampering on property ID: " << propertyId << endl;
    }

    void deleteProperty(int propertyId) {
        cout << "Attempting to delete property ID: " << propertyId << endl;
    }

    void overrideMaintenanceRequest(int requestId, const string& username) {
        cout << "User: " << username << " is attempting to override maintenance request ID: " << requestId << endl;
    }

    void assignVendor(int vendorId, const string& username) {
        cout << "User: " << username << " is assigning vendor ID: " << vendorId << endl;
    }

    void changeUserRole(const string& username, const string& newRole) {
        cout << "Changing role for user: " << username << " to " << newRole << endl;
    }

    void manipulateFinancialData(int propertyId, const string& username) {
        cout << "User: " << username << " is attempting to manipulate financial data for property ID: " << propertyId << endl;
    }

    void misuseCommunicationChannels(int userId) {
        cout << "Checking for misuse of communication channels for user ID: " << userId << endl;
    }

    void deleteSystemLogs() {
        cout << "Attempting to delete system logs." << endl;
    }

    void handleExcessiveLoginAttempts(const string& username) {
        cout << "Checking for excessive login attempts for user: " << username << endl;
    }
};

int main() {
    // Create the system
    PropertyManagementSystem system;
    
    // Create users
    PropertyManager admin("", true);
    Tenant tenant("");
    RealEstateOwner owner("");
    FinancialAdvisor advisor("");
    ITSupport support("");
    
    //basic operations
    cout << "\n=== Test  ===\n";
    system.userLogin("admin", "password");
    system.managePropertyDescription(1, "New property");
    system.submitMaintenanceRequest(1, "Broken window");
    
    //security operations
    cout << "\n=== Security test ===\n";
    system.setupTwoFactorAuth("admin");
    system.logAuditEvent("login", "admin");
    system.checkSessionTimeout("admin");
    
    return 0;
}
