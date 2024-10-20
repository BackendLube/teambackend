#include <iostream>
#include <string>
#include <vector>
using namespace std;

// Enumeration that is going to categorize different types of users in the system
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

// Structure that is used for representing a system user with an ID, username, password, and their role (UserType)
struct User {
    int id;
    string username;
    string password;
    UserType type;
};

// Structure that will hold property details such as description, photos, and performance metrics
struct Property {
    int id;
    string description;
    vector<string> photos;
    double performance_metric;
};

// Structure that is going to store information about a tenant, such as their name and associated property
struct Tenant {
    int id;
    string name;
    int property_id;
};

// Structure representing a request for maintenance made for a property
struct MaintenanceRequest {
    int id;
    int property_id;
    string description;
    bool resolved;
};

// Structure that is there to represent a vendor and the services they provide
struct Vendor {
    int id;
    string name;
    string service_type;
};

// Function declarations

// Function to log in a user by checking their credentials
void login(string username, string password);

// Function to log out the current user
void logout();

// Function for 2FA authentication, returns true if the second factor is verified
bool authenticate2FA(int user_id);

// Function to allow users to change their password
void changePassword(int user_id, string new_password);

// Function to create a new user profile
void createUserProfile(User user);

// Function to update an existing user's profile information
void updateUserProfile(int user_id, User updated_user);



// Function to add a new property to the system
void addProperty(Property property);

// Function to update the details of an existing property
void updateProperty(int property_id, Property updated_property);

// Function to add a photo to a property's photo gallery
void addPropertyPhoto(int property_id, string photo_url);

// Function to calculate and return a performance metric for a property
double calculatePropertyPerformance(int property_id);



// Function to add a new tenant to the system
void addTenant(Tenant tenant);

// Function to send a message to a tenant (e.g., reminders, notifications)
void communicateWithTenant(int tenant_id, string message);


// Function to create a new maintenance request for a property
void createMaintenanceRequest(MaintenanceRequest request);

// Function to mark a maintenance request as resolved
void resolveMaintenanceRequest(int request_id);

// Vendor Management

// Function to add a new vendor to the system
void addVendor(Vendor vendor);

// Function to assign a vendor to a property for services
void assignVendorToProperty(int vendor_id, int property_id);

// Portfolio Management

// Function to generate a portfolio overview for a given user
void generatePortfolioOverview(int user_id);

// Function to generate a dashboard with key information for a user
void generateDashboard(int user_id);


// Function to perform an investment analysis for a property (e.g., ROI, risk assessment)
double performInvestmentAnalysis(int property_id);

// Function to assess the financial risk associated with a property
double assessRisk(int property_id);

// Function to compare two properties based on performance and other factors
void compareProperties(int property_id1, int property_id2);

// Function to forecast cash flow over a given number of months for a property
double forecastCashFlow(int property_id, int months);

int main() {
    // Initialize system
    cout << "Real Estate Management System Initialized" << endl;

    // Main program loop would go here
    // (User interactions, system state management, etc.)

    return 0;
}
