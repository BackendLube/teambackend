#include <iostream>
#include <string>
#include <vector>
#include <map>

using namespace std; // Using standard library

// Base class for all users
class User {
protected:
    string username;  // User's name
    string role;      // User's role (like admin or tenant)
public:
    // Constructor to create a user with a name and role
    User(string name, string userRole) 
        : username(name), role(userRole) {}
    // Destructor
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
    int id;                 // Unique property ID
    string address;        // Property address
    string description;    // What the property is like
    double value;          // How much the property is worth
};

// Structure for maintenance requests
struct MaintenanceRequest {
    int id;                 // Unique request ID
    string description;     // What needs fixing
    string status;         // Current status of the request
};

// Structure for vendor information
struct Vendor {
    int id;                 // Unique vendor ID
    string name;           // Vendor name
    bool isVerified;       // Is the vendor verified?
};

// Main system class for managing properties
class PropertyManagementSystem {
public:
    // User login function
    bool userLogin(string username, string password) {
        cout << "Login attempt: " << username << endl;
        return true; // For now, just return true
    }

    // Manage property descriptions
    void managePropertyDescription(int propertyId, string description) {
        cout << "Managing property " << propertyId << endl;
    }

    // Upload property photos
    void uploadPropertyPhotos(int propertyId, vector<string> photoUrls) {
        cout << "Uploading photos for property " << propertyId << endl;
    }

    // View property metrics
    void viewPropertyMetrics(int propertyId) {
        cout << "Viewing metrics for property " << propertyId << endl;
    }

    // Send messages to tenants
    void sendTenantCommunication(int tenantId, string message) {
        cout << "Message sent to tenant " << tenantId << endl;
    }

    // Submit maintenance requests
    void submitMaintenanceRequest(int tenantId, string description) {
        cout << "Maintenance request from tenant " << tenantId << endl;
    }

    // Manage vendors
    void manageVendor(int vendorId, bool verify) {
        cout << "Managing vendor " << vendorId << endl;
    }

    // View portfolio overview
    void viewPortfolioOverview(int ownerId) {
        cout << "Viewing portfolio for owner " << ownerId << endl;
    }

    // Generate cash flow forecasts
    void generateCashFlowForecast(int propertyId) {
        cout << "Generating forecast for property " << propertyId << endl;
    }

    // Analyze investments
    void analyzeInvestment(int propertyId) {
        cout << "Analyzing investment for property " << propertyId << endl;
    }

    // Set up two-factor authentication
    void setupTwoFactorAuth(string username) {
        cout << "Setting up 2FA for " << username << endl;
    }

    // Change user password
    void changePassword(string username, string newPassword) {
        cout << "Changing password for " << username << endl;
    }

    // Grant user roles
    void grantRole(string username, string role) {
        cout << "Granting role " << role << " to " << username << endl;
    }

    // Log system activities
    void logAuditEvent(string action, string username) {
        cout << "Logging: " << username << " did " << action << endl;
    }

    // Check for suspicious activity
    void detectIntrusion(string ipAddress) {
        cout << "Checking activity from " << ipAddress << endl;
    }

    // Backup system data
    void backupData() {
        cout << "Performing system backup" << endl;
    }

    // Whitelist IP addresses
    void whitelistIP(string ipAddress) {
        cout << "Whitelisting IP: " << ipAddress << endl;
    }

    // Validate uploaded files
    void validateFileUpload(string filename) {
        cout << "Validating file: " << filename << endl;
    }

    // Check user session timeout
    void checkSessionTimeout(string username) {
        cout << "Checking session for " << username << endl;
    }
};



int main() {
    // Create the system
    PropertyManagementSystem system;
    
    // Create users
    PropertyManager admin("John", true);      // Admin property manager
    Tenant tenant("Alice");                   // Regular tenant
    RealEstateOwner owner("Bob");            // Property owner
    FinancialAdvisor advisor("Charlie");      // Financial advisor
    ITSupport support("Dave");                // IT support staff
    
    // Do some basic operations
    cout << "\n=== Basic Operations Demo ===\n";
    system.userLogin("admin", "password");
    system.managePropertyDescription(1, "New property");
    system.submitMaintenanceRequest(1, "Broken window");
    
    // Do some security operations
    cout << "\n=== Security Operations Demo ===\n";
    system.setupTwoFactorAuth("admin");
    system.logAuditEvent("login", "admin");
    system.checkSessionTimeout("admin");
    
    return 0;
}
