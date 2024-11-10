#ifndef PORTFOLIO_MANAGEMENT_H
#define PORTFOLIO_MANAGEMENT_H

#include <iostream>
#include <string>
#include <vector>

// Structure for Property, Tenant, Vendor, etc.
struct Property {
    int id;
    std::string address;
    std::string description;
    std::vector<std::string> photos;
    std::vector<std::string> metrics;
};

struct Tenant {
    int id;
    std::string name;
    std::string lease_start;
    std::string lease_end;
    double rent;
};

struct MaintenanceRequest {
    int property_id;
    std::string description;
    std::string status;
    std::string created_at;
};

struct Vendor {
    int id;
    std::string name;
    std::string contact_info;
    std::string service_type;
};

struct Portfolio {
    std::vector<Property> properties;
    std::vector<Tenant> tenants;
    std::vector<MaintenanceRequest> maintenanceRequests;
    std::vector<Vendor> vendors;
};

// Function Declarations
void managePropertyDescriptions();
void updatePropertyPhotos();
void viewPropertyMetrics();
void sendTenantCommunication();
void submitMaintenanceRequest();
void manageVendor();
void viewPortfolioOverview();
void generateCashFlowForecast();
void analyzeInvestment();

// Utility functions
void displayMenu();
void handleUserInput(int choice);

#endif // PORTFOLIO_MANAGEMENT_H
