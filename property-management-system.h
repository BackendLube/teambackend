#ifndef PROPERTY_MANAGEMENT_SYSTEM_H
#define PROPERTY_MANAGEMENT_SYSTEM_H

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <stdexcept>
#include <mysql_driver.h>
#include <mysql_connection.h>
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
    User(string name, string userRole) : username(name), role(userRole) {}
    virtual ~User() {}
};

// Property Manager class
class PropertyManager : public User {
public:
    PropertyManager(string name, bool isAdmin) : User(name, isAdmin ? "admin" : "employee") {}
};

// Tenant class
class Tenant : public User {
public:
    Tenant(string name) : User(name, "tenant") {}
};

// Real Estate Owner class
class RealEstateOwner : public User {
public:
    RealEstateOwner(string name) : User(name, "owner") {}
};

// Financial Advisor class
class FinancialAdvisor : public User {
public:
    FinancialAdvisor(string name) : User(name, "advisor") {}
};

// IT Support class
class ITSupport : public User {
public:
    ITSupport(string name) : User(name, "it_support") {}
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

// Main system class
class PropertyManagementSystem {
private:
    sql::mysql::MySQL_Driver* driver;
    unique_ptr<sql::Connection> conn;

public:
    PropertyManagementSystem();
    ~PropertyManagementSystem();

    bool userLogin(const string& username, const string& password);
    void managePropertyDescription(int propertyId, const string& description);
    void uploadPropertyPhotos(int propertyId, const vector<string>& photoUrls);
    void viewPropertyMetrics(int propertyId);
    void sendTenantCommunication(int tenantId, const string& message);
    void submitMaintenanceRequest(int tenantId, const string& description);
    void manageVendor(int vendorId, bool verify);
    void viewPortfolioOverview(int ownerId);
    void generateCashFlowForecast(int propertyId);
    void analyzeInvestment(int propertyId);

    // Security-related methods with SQL
    void setupTwoFactorAuth(const string& username);
    void changePassword(const string& username, const string& newPassword);
    void grantRole(const string& username, const string& role);
    void logAuditEvent(const string& action, const string& username);
    void detectIntrusion(const string& ipAddress);
    void backupData();
    void whitelistIP(const string& ipAddress);
    void validateFileUpload(const string& filename);
    void checkSessionTimeout(const string& username);
};

#endif // PROPERTY_MANAGEMENT_SYSTEM_H

