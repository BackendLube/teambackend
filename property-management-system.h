#ifndef PROPERTY_MANAGEMENT_SYSTEM_H
#define PROPERTY_MANAGEMENT_SYSTEM_H

#include <iostream>
#include <string>
#include <vector>
#include <map>

using namespace std;

// Base class for all users
class User {
protected:
    string username;  // User's name
    string role;      // User's role (like admin or tenant)
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
    int id;                 // Unique property ID
    string address;         // Property address
    string description;     // What the property is like
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
    int id;                // Unique vendor ID
    string name;           // Vendor name
    bool isVerified;       // Is the vendor verified?
};

// Main system class for managing properties
class PropertyManagementSystem {
public:
    bool userLogin(string username, string password);
    void managePropertyDescription(int propertyId, string description);
    void uploadPropertyPhotos(int propertyId, vector<string> photoUrls);
    void viewPropertyMetrics(int propertyId);
    void sendTenantCommunication(int tenantId, string message);
    void submitMaintenanceRequest(int tenantId, string description);
    void manageVendor(int vendorId, bool verify);
    void viewPortfolioOverview(int ownerId);
    void generateCashFlowForecast(int propertyId);
    void analyzeInvestment(int propertyId);
    void setupTwoFactorAuth(string username);
    void changePassword(string username, string newPassword);
    void grantRole(string username, string role);
    void logAuditEvent(string action, string username);
    void detectIntrusion(string ipAddress);
    void backupData();
    void whitelistIP(string ipAddress);
    void validateFileUpload(string filename);
    void checkSessionTimeout(string username);
};

#endif // PROPERTY_MANAGEMENT_SYSTEM_H
