#include <iostream>
#include <string>
#include <vector>
#include <map>

//////////////////////////////////////////////
// Actor Class Hierarchy
//////////////////////////////////////////////

// Base class for all users in the system
class User {
protected:
    std::string username;  // User's login name
    std::string role;      // User's role in the system (admin, tenant, etc.)
public:
    // Constructor for creating a user with a name and role
    User(std::string name, std::string userRole) 
        : username(name), role(userRole) {}
    // Virtual destructor for proper inheritance
    virtual ~User() {}
};

// Property Manager can be either admin or regular employee
// Actors: Property Manager (Admin), Property Manager (Employee)
// Use Cases: Property Description Management, Vendor Management
class PropertyManager : public User {
public:
    PropertyManager(std::string name, bool isAdmin) 
        : User(name, isAdmin ? "Admin" : "Employee") {}
};

// Tenant class for property residents
// Actors: Tenant
// Use Cases: Maintenance Request Submission, Tenant Communication
class Tenant : public User {
public:
    Tenant(std::string name) : User(name, "Tenant") {}
};

// Real Estate Owner class
// Actors: Real Estate Owners
// Use Cases: View Property Performance Metrics, Investment Analysis
class RealEstateOwner : public User {
public:
    RealEstateOwner(std::string name) : User(name, "Owner") {}
};

// Financial Advisor class
// Actors: Financial Advisor
// Use Cases: Cash Flow Forecasting, Investment Analysis
class FinancialAdvisor : public User {
public:
    FinancialAdvisor(std::string name) : User(name, "Advisor") {}
};

// IT Support class
// Actors: IT Support
// Use Cases: System Log Deletion, Intrusion Detection System
class ITSupport : public User {
public:
    ITSupport(std::string name) : User(name, "IT") {}
};

//////////////////////////////////////////////
// Data Structures
//////////////////////////////////////////////

// Basic property information structure
struct Property {
    int id;                 // Unique property identifier
    std::string address;    // Property address
    std::string description;// Property description
    double value;          // Property value
};

// Maintenance request structure
struct MaintenanceRequest {
    int id;                 // Unique request identifier
    std::string description;// Description of the maintenance issue
    std::string status;     // Current status of the request
};

// Vendor information structure
struct Vendor {
    int id;                 // Unique vendor identifier
    std::string name;       // Vendor name
    bool isVerified;        // Verification status
};

//////////////////////////////////////////////
// Main System Class
//////////////////////////////////////////////

class PropertyManagementSystem {
public:
    //////////////////////////////////////////////
    // Use Case Functions
    //////////////////////////////////////////////

    // UC1: User Login
    // Actors: All Users
    // Description: Authenticates user credentials
    bool userLogin(std::string username, std::string password) {
        std::cout << "Login attempt: " << username << std::endl;
        return true;
    }

    // UC2: Property Description Management
    // Actors: Property Manager
    // Description: Updates property information
    void managePropertyDescription(int propertyId, std::string description) {
        std::cout << "Managing property " << propertyId << std::endl;
    }

    // UC3: Upload Property Photos
    // Actors: Property Manager, Real Estate Agent
    // Description: Handles property image uploads
    void uploadPropertyPhotos(int propertyId, std::vector<std::string> photoUrls) {
        std::cout << "Uploading photos for property " << propertyId << std::endl;
    }

    // UC4: View Property Performance Metrics
    // Actors: Real Estate Owners, Portfolio Analysts
    // Description: Displays property performance data
    void viewPropertyMetrics(int propertyId) {
        std::cout << "Viewing metrics for property " << propertyId << std::endl;
    }

    // UC5: Tenant Communication
    // Actors: Tenant, Property Manager
    // Description: Handles messaging between tenants and managers
    void sendTenantCommunication(int tenantId, std::string message) {
        std::cout << "Message sent to tenant " << tenantId << std::endl;
    }

    // UC6: Maintenance Request Submission
    // Actors: Tenant
    // Description: Creates new maintenance requests
    void submitMaintenanceRequest(int tenantId, std::string description) {
        std::cout << "Maintenance request from tenant " << tenantId << std::endl;
    }

    // UC7: Vendor Management
    // Actors: Property Manager (Admin)
    // Description: Manages vendor relationships and verification
    void manageVendor(int vendorId, bool verify) {
        std::cout << "Managing vendor " << vendorId << std::endl;
    }

    // UC8: Portfolio Overview Dashboard
    // Actors: Property Manager, Portfolio Analyst
    // Description: Displays portfolio summary
    void viewPortfolioOverview(int ownerId) {
        std::cout << "Viewing portfolio for owner " << ownerId << std::endl;
    }

    // UC9: Cash Flow Forecasting
    // Actors: Financial Advisor, Property Manager
    // Description: Generates financial forecasts
    void generateCashFlowForecast(int propertyId) {
        std::cout << "Generating forecast for property " << propertyId << std::endl;
    }

    // UC10: Investment Analysis
    // Actors: Real Estate Owners, Financial Advisor
    // Description: Analyzes investment opportunities
    void analyzeInvestment(int propertyId) {
        std::cout << "Analyzing investment for property " << propertyId << std::endl;
    }

    //////////////////////////////////////////////
    // Security Functions
    //////////////////////////////////////////////

    // SEC1: Two-Factor Authentication Setup
    // Actors: All Users
    // Description: Enables 2FA security
    void setupTwoFactorAuth(std::string username) {
        std::cout << "Setting up 2FA for " << username << std::endl;
    }

    // SEC2: Password Management
    // Actors: All Users
    // Description: Handles password changes
    void changePassword(std::string username, std::string newPassword) {
        std::cout << "Changing password for " << username << std::endl;
    }

    // SEC3: Role-Based Access Control
    // Actors: Admin
    // Description: Manages user roles and permissions
    void grantRole(std::string username, std::string role) {
        std::cout << "Granting role " << role << " to " << username << std::endl;
    }

    // SEC4: Audit Logging
    // Actors: System Admin
    // Description: Logs system activities
    void logAuditEvent(std::string action, std::string username) {
        std::cout << "Logging: " << username << " performed " << action << std::endl;
    }

    // SEC5: Intrusion Detection
    // Actors: IT Support
    // Description: Monitors for suspicious activity
    void detectIntrusion(std::string ipAddress) {
        std::cout << "Checking activity from " << ipAddress << std::endl;
    }

    // SEC6: Data Backup
    // Actors: IT Support
    // Description: Performs system backups
    void backupData() {
        std::cout << "Performing system backup" << std::endl;
    }

    // SEC7: IP Whitelisting
    // Actors: Admin
    // Description: Manages allowed IP addresses
    void whitelistIP(std::string ipAddress) {
        std::cout << "Whitelisting IP: " << ipAddress << std::endl;
    }

    // SEC8: File Upload Validation
    // Actors: All Users
    // Description: Validates uploaded files
    void validateFileUpload(std::string filename) {
        std::cout << "Validating file: " << filename << std::endl;
    }

    // SEC9: Session Management
    // Actors: All Users
    // Description: Manages user sessions
    void checkSessionTimeout(std::string username) {
        std::cout << "Checking session for " << username << std::endl;
    }
};

//////////////////////////////////////////////
// Main Function - Demo Usage
//////////////////////////////////////////////

int main() {
    // Initialize the system
    PropertyManagementSystem system;
    
    // Create example actors
    PropertyManager admin("John", true);      // Admin property manager
    Tenant tenant("Alice");                   // Regular tenant
    RealEstateOwner owner("Bob");            // Property owner
    FinancialAdvisor advisor("Charlie");      // Financial advisor
    ITSupport support("Dave");                // IT support staff
    
    // Demonstrate basic operations
    std::cout << "\n=== Basic Operations Demo ===\n";
    system.userLogin("admin", "password");
    system.managePropertyDescription(1, "New property");
    system.submitMaintenanceRequest(1, "Broken window");
    
    // Demonstrate security operations
    std::cout << "\n=== Security Operations Demo ===\n";
    system.setupTwoFactorAuth("admin");
    system.logAuditEvent("login", "admin");
    system.checkSessionTimeout("admin");
    
    return 0;
}
