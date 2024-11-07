#ifndef PROPERTY_MANAGEMENT_SYSTEM_H
#define PROPERTY_MANAGEMENT_SYSTEM_H

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <stdexcept>
#include <unordered_map>
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
};

// Property Manager class (Admin or Employee)
class PropertyManager : public User {
public:
    PropertyManager(string name, bool isAdmin);
};

// Tenant class for people living in properties
class Tenant : public User {
public:
    Tenant(string name);
};

// Real Estate Owner class
class RealEstateOwner : public User {
public:
    RealEstateOwner(string name);
};

// Financial Advisor class
class FinancialAdvisor : public User {
public:
    FinancialAdvisor(string name);
};

// IT Support class
class ITSupport : public User {
public:
    ITSupport(string name);
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
    PropertyManagementSystem();

    // Destructor: Closes the SQL connection
    ~PropertyManagementSystem();

    // User login function
    bool userLogin(const string& username, const string& password);

    // Property Management Functions
    void managePropertyDescription(int propertyId, string description);
    void uploadPropertyPhotos(int propertyId, vector<string> photoUrls);
    void viewPropertyMetrics(int propertyId);
    void sendTenantCommunication(int tenantId, string message);
    void submitMaintenanceRequest(int tenantId, string description);
    void manageVendor(int vendorId, bool verify);
    void viewPortfolioOverview(int ownerId);
    void generateCashFlowForecast(int propertyId);
    void analyzeInvestment(int propertyId);

    // Security Functions
    void setupTwoFactorAuth(const string& username);
    void changePassword(const string& username, const string& newPassword);
    void grantRole(const string& username, const string& role);
    void logAuditEvent(const string& action, const string& username);
    void detectIntrusion(const string& ipAddress);
    void backupData();
    void whitelistIP(const string& ipAddress);
    void validateFileUpload(const string& filename);
    void checkSessionTimeout(const string& username);

    // Misuse case implementations
    void checkUnauthorizedAccess(int propertyId, const string& username);
    void checkDataTampering(int propertyId);
    void deleteProperty(int propertyId);
    void overrideMaintenanceRequest(int requestId, const string& username);
    void assignVendor(int vendorId, const string& username);
    void changeUserRole(const string& username, const string& newRole);
    void manipulateFinancialData(int propertyId, const string& username);
    void misuseCommunicationChannels(int userId);
    void deleteSystemLogs();
    void handleExcessiveLoginAttempts(const string& username);
};

#endif // PROPERTY_MANAGEMENT_SYSTEM_H
