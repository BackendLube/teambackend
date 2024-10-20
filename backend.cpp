#include <iostream>
#include <string>
#include <vector>
using namespace std;
// User types
enum class UserType {
    RealEstateOwner,
    PropertyManagerOwner,
    PropertyManagerEmployee,
    PropertyManagerAdmin,
    RealEstateAgent,
    Tenant,
    SoftwareDeveloper,
    LeasingAgent,
    Accountant,
    FinancialAdvisor,
    Lender,
    PortfolioAnalyst,
    ITSupport
};

// Basic user structure
struct User {
    int id;
    string username;
    string password;
    UserType type;
};

// Basic property structure
struct Property {
    int id;
    string description;
 vector<string> photos;
    double performance_metric;
};

// Basic tenant structure
struct Tenant {
    int id;
   string name;
    int property_id;
};

// Basic maintenance request structure
struct MaintenanceRequest {
    int id;
    int property_id;
   string description;
    bool resolved;
};

// Basic vendor structure
struct Vendor {
    int id;
   string name;
   string service_type;
};

// Function declarations

// Authentication and User Management
void login(string username, string password);
void logout();
bool authenticate2FA(int user_id);
void changePassword(int user_id, string new_password);
void createUserProfile(User user);
void updateUserProfile(int user_id, User updated_user);

// Property Management
void addProperty(Property property);
void updateProperty(int property_id, Property updated_property);
void addPropertyPhoto(int property_id, string photo_url);
double calculatePropertyPerformance(int property_id);

// Tenant Management
void addTenant(Tenant tenant);
void communicateWithTenant(int tenant_id, string message);

// Maintenance Management
void createMaintenanceRequest(MaintenanceRequest request);
void resolveMaintenanceRequest(int request_id);

// Vendor Management
void addVendor(Vendor vendor);
void assignVendorToProperty(int vendor_id, int property_id);

// Portfolio Management
void generatePortfolioOverview(int user_id);
void generateDashboard(int user_id);

// Financial Management
double performInvestmentAnalysis(int property_id);
double assessRisk(int property_id);
void compareProperties(int property_id1, int property_id2);
double forecastCashFlow(int property_id, int months);

// Main function
int main() {
    // Initialize system
   cout << "Real Estate Management System Initialized" << endl;

    // Main program loop would go here

    return 0;
}

