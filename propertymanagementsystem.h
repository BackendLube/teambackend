#ifndef PROPERTY_MANAGEMENT_SYSTEM_H
#define PROPERTY_MANAGEMENT_SYSTEM_H

#include <iostream>
#include <string>
#include <vector>
#include <map>

using namespace std;


class PropertyManagementSystem {
public:
    PropertyManagementSystem() {}
    ~PropertyManagementSystem() {}

    bool userLogin(const string& username, const string& password) {
        // Simple hardcoded check for demonstration
        return (username == "admin" && password == "password");
    }

    void submitMaintenanceRequest(int tenantId, const string& description) {
        cout << "Maintenance request submitted for tenant " << tenantId << ": " << description << endl;
    }

    void managePropertyDescription(int propertyId, const string& description) {
        cout << "Property " << propertyId << " description updated: " << description << endl;
    }
};

#endif