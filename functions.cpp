#include <iostream>
#include <vector>
#include <string>
#include <limits>

using namespace std;

// Property structure to store information about properties
struct Property {
    int id;
    string address;
    string description;
    double value;
    double performance;
};

// Global vector of properties (simulating the `data.properties` array)
vector<Property> properties = {
    {1, "123 Main St", "Modern Apartment", 1200000, 85.5},
    {2, "456 Meridian Rd", "Commercial Space", 2500000, 92.0},
    {3, "789 Normal Ave", "Residential Home", 450000, 78.3}
};

// Function to display all properties with their descriptions
void displayProperties() {
    cout << "Properties List: \n";
    for (const auto& property : properties) {
        cout << "ID: " << property.id << ", Address: " << property.address 
             << ", Description: " << property.description << endl;
    }
}

// Function to manage property descriptions
void managePropertyDescriptions() {
    int choice, propertyID;
    string newDescription;

    while (true) {
        // Display all properties
        displayProperties();

        // Prompt the user for an action
        cout << "\nChoose an option: \n";
        cout << "1. Edit Property Description\n";
        cout << "2. Delete Property Description\n";
        cout << "3. Exit\n";
        cout << "Enter your choice: ";
        cin >> choice;

        // Clear the input buffer
        cin.ignore(numeric_limits<streamsize>::max(), '\n');

        switch (choice) {
            case 1:
                cout << "Enter the Property ID to edit: ";
                cin >> propertyID;

                // Find the property by ID
                bool found = false;
                for (auto& property : properties) {
                    if (property.id == propertyID) {
                        found = true;
                        cout << "Current Description: " << property.description << endl;
                        cout << "Enter new description: ";
                        getline(cin, newDescription);
                        property.description = newDescription; // Update description
                        cout << "Description updated successfully!\n";
                        break;
                    }
                }

                if (!found) {
                    cout << "Property with ID " << propertyID << " not found.\n";
                }
                break;

            case 2:
                cout << "Enter the Property ID to delete description: ";
                cin >> propertyID;

                // Find the property by ID and delete its description
                found = false;
                for (auto& property : properties) {
                    if (property.id == propertyID) {
                        found = true;
                        property.description = ""; // Clear description
                        cout << "Description deleted successfully!\n";
                        break;
                    }
                }

                if (!found) {
                    cout << "Property with ID " << propertyID << " not found.\n";
                }
                break;

            case 3:
                cout << "Exiting Property Management.\n";
                return; // Exit the function

            default:
                cout << "Invalid choice. Please try again.\n";
                break;
        }
}

// Define a structure for Property that includes a vector of photos.
struct Property {
    int id;
    string address;
    string description;
    vector<string> photos; // A vector to store photo URLs or file paths.
};

// Function to update property photos
void updatePropertyPhotos(vector<Property>& properties, int propertyId, const vector<string>& newPhotos) {
    // Search for the property with the given ID
    for (auto& property : properties) {
        if (property.id == propertyId) {
            // Update the photos for the property
            property.photos = newPhotos;
            cout << "Photos for property ID " << propertyId << " have been updated." << endl;
            return;
        }
    }

    // If the property ID is not found
    cout << "Property with ID " << propertyId << " not found." << endl;
}

// Helper function to display the photos for a property
void displayPropertyPhotos(const vector<Property>& properties, int propertyId) {
    for (const auto& property : properties) {
        if (property.id == propertyId) {
            cout << "Photos for Property ID " << propertyId << ":\n";
            if (property.photos.empty()) {
                cout << "No photos available for this property.\n";
            } else {
                for (const auto& photo : property.photos) {
                    cout << photo << endl;
                }
            }
            return;
        }
    }
    cout << "Property with ID " << propertyId << " not found." << endl;
}
// Define a structure for Property that includes value and performance.
struct Property {
    int id;
    string address;
    string description;
    double value; // Property value (in dollars).
    double performance; // Percentage value representing performance.
};

// Function to view property metrics (value and performance)
void viewPropertyMetrics(const vector<Property>& properties, int propertyId) {
    // Search for the property with the given ID
    for (const auto& property : properties) {
        if (property.id == propertyId) {
            // Display the property metrics (value and performance)
            cout << "Metrics for Property ID " << propertyId << ":\n";
            cout << "Address: " << property.address << endl;
            cout << "Description: " << property.description << endl;
            cout << "Value: $" << property.value << endl;
            cout << "Performance: " << property.performance << "%" << endl;
            return;
        }
    }

    // If the property ID is not found
    cout << "Property with ID " << propertyId << " not found." << endl;
}
// Define a structure for Tenant that includes tenant details and communication history.
struct Tenant {
    int id;
    string name;
    string email;
    string phone;
    string property_id; // Linking to property ID.
    vector<string> communicationHistory; // List of previous communications with the tenant.
};

// Function to message a tenant
void sendTenantCommunication(vector<Tenant>& tenants, int tenantId, const string& message) {
    // Search for the tenant with the given ID
    for (auto& tenant : tenants) {
        if (tenant.id == tenantId) {
            // Add the new message to the tenant's communication history
            tenant.communicationHistory.push_back(message);
            
            // Simulate sending communication (e.g., printing to console, email, etc.)
            cout << "Sending message to " << tenant.name << " at " << tenant.email << ":\n";
            cout << message << endl;
            
            // Optional: If you were integrating with a real email service, you would do that here.
            cout << "Message sent successfully.\n";
            return;
        }
    }

    // If the tenant ID is not found
    cout << "Tenant with ID " << tenantId << " not found.\n";
}
// Define a structure for MaintenanceRequest
struct MaintenanceRequest {
    int id;
    string property_id;
    string description;
    string status; // Status of the request, e.g., "Pending", "In Progress", "Resolved".
    string created_at;
};

// Function to submit a maintenance request
void submitMaintenanceRequest(vector<MaintenanceRequest>& maintenanceRequests, const string& property_id, const string& description) {
    // Create a new maintenance request with a unique ID (for simplicity, increment based on size)
    int newId = maintenanceRequests.size() + 1;  // Or use a more robust ID generation approach
    string createdAt = "2024-11-10"; // In a real-world scenario, this would be the current date
    
    // Create the new request
    MaintenanceRequest newRequest = {newId, property_id, description, "Pending", createdAt};

    // Add the new request to the list of maintenance requests
    maintenanceRequests.push_back(newRequest);

    // Simulate submitting the request
    cout << "Maintenance request submitted for Property ID: " << property_id << endl;
    cout << "Description: " << description << endl;
    cout << "Status: " << newRequest.status << endl;
    cout << "Request created on: " << newRequest.created_at << endl;
    cout << "Request ID: " << newRequest.id << endl;
    cout << "Maintenance request has been successfully submitted.\n";
}
void manageVendor() {
    int vendorId;
    cout << "Enter Vendor ID to manage: ";
    cin >> vendorId;

    // Check if vendor exists
    auto it = find_if(vendors.begin(), vendors.end(), 
                      [vendorId](const Vendor& v) { return v.id == vendorId; });
    
    if (it != vendors.end()) {
        Vendor& vendor = *it;
        
        cout << "Managing Vendor: " << vendor.name << endl;
        
        // Show vendor details
        cout << "1. View Vendor Details" << endl;
        cout << "2. Update Vendor Details" << endl;
        cout << "3. Remove Vendor" << endl;
        cout << "4. Exit" << endl;

        int choice;
        cout << "Enter your choice: ";
        cin >> choice;

        switch(choice) {
            case 1:
                // Display vendor details
                cout << "Vendor Name: " << vendor.name << endl;
                cout << "Vendor Contact: " << vendor.contact << endl;
                cout << "Vendor Address: " << vendor.address << endl;
                break;

            case 2:
                // Update vendor details
                cout << "Enter new Vendor Name: ";
                cin.ignore(); // Ignore the newline character left in the buffer
                getline(cin, vendor.name);
                cout << "Enter new Vendor Contact: ";
                getline(cin, vendor.contact);
                cout << "Enter new Vendor Address: ";
                getline(cin, vendor.address);
                cout << "Vendor details updated!" << endl;
                break;

            case 3:
                // Remove vendor
                vendors.erase(it);
                cout << "Vendor removed!" << endl;
                break;

            case 4:
                cout << "Exiting vendor management." << endl;
                break;

            default:
                cout << "Invalid choice!" << endl;
                break;
        }
    } else {
        cout << "Vendor with ID " << vendorId << " not found!" << endl;
    }
}
void viewPortfolioOverview() {
    double totalValue = 0;
    double totalMonthlyIncome = 0;
    double totalExpenses = 0;

    // Calculate total property value, total monthly rent, and estimated expenses
    for (const auto& property : properties) {
        totalValue += property.value;
    }

    for (const auto& tenant : tenants) {
        totalMonthlyIncome += tenant.rent;
    }

    totalExpenses = totalMonthlyIncome * 0.4; // Assuming 40% of income is spent on expenses

    // Calculate net monthly cash flow and annual profit
    double monthlyProfit = totalMonthlyIncome - totalExpenses;
    double annualProfit = monthlyProfit * 12;

    // Display the overview
    cout << "Portfolio Overview:" << endl;
    cout << "--------------------" << endl;
    cout << "Total Property Value: $" << totalValue << endl;
    cout << "Total Monthly Income from Rent: $" << totalMonthlyIncome << endl;
    cout << "Estimated Monthly Expenses (40% of income): $" << totalExpenses << endl;
    cout << "Net Monthly Cash Flow: $" << monthlyProfit << endl;
    cout << "Annual Profit/Loss (Based on current monthly performance): $" << annualProfit << endl;
}
void generateCashFlowForecast(int months) {
    double totalMonthlyIncome = 0;
    double totalExpenses = 0;
    double monthlyProfit = 0;

    // Calculate total monthly income and expenses
    for (const auto& tenant : tenants) {
        totalMonthlyIncome += tenant.rent;
    }

    totalExpenses = totalMonthlyIncome * 0.4; // Assuming 40% of income is spent on expenses

    monthlyProfit = totalMonthlyIncome - totalExpenses;

    // Generate and display the cash flow forecast for the specified number of months
    cout << "Cash Flow Forecast for the Next " << months << " Months:" << endl;
    cout << "------------------------------------------------------" << endl;
    for (int i = 1; i <= months; ++i) {
        double projectedProfit = monthlyProfit * i;
        cout << "Month " << i << ": Net Cash Flow: $" << projectedProfit << endl;
    }
}
void analyzeInvestment() {
    double totalPropertyValue = 0;
    double totalMonthlyRent = 0;
    double totalExpenses = 0;
    double netMonthlyProfit = 0;
    double annualProfit = 0;

    // Calculate total property value and monthly rental income
    for (const auto& property : properties) {
        totalPropertyValue += property.value;
    }

    for (const auto& tenant : tenants) {
        totalMonthlyRent += tenant.rent;
    }

    // Assume 40% of monthly rent is used for expenses
    totalExpenses = totalMonthlyRent * 0.4;
    netMonthlyProfit = totalMonthlyRent - totalExpenses;
    annualProfit = netMonthlyProfit * 12;

    // Output the analysis results
    cout << "Investment Analysis:" << endl;
    cout << "------------------------------------------------------" << endl;
    cout << "Total Property Value: $" << totalPropertyValue << endl;
    cout << "Total Monthly Rent: $" << totalMonthlyRent << endl;
    cout << "Estimated Monthly Expenses: $" << totalExpenses << endl;
    cout << "Net Monthly Profit: $" << netMonthlyProfit << endl;
    cout << "Projected Annual Profit: $" << annualProfit << endl;
}
using namespace std;

int main() {
    int choice;

    while (true) {
        // Main menu for the user to choose the action
        cout << "\nPortfolio Management System" << endl;
        cout << "1. Manage Property Descriptions" << endl;
        cout << "2. Update Property Photos" << endl;
        cout << "3. View Property Metrics" << endl;
        cout << "4. Send Tenant Communication" << endl;
        cout << "5. Submit Maintenance Request" << endl;
        cout << "6. Manage Vendor" << endl;
        cout << "7. View Portfolio Overview" << endl;
        cout << "8. Generate Cash Flow Forecast" << endl;
        cout << "9. Analyze Investment" << endl;
        cout << "0. Exit" << endl;
        cout << "Enter your choice: ";
        cin >> choice;

        switch (choice) {
            case 1:
                managePropertyDescriptions();
                break;
            case 2:
                updatePropertyPhotos();
                break;
            case 3:
                viewPropertyMetrics();
                break;
            case 4:
                sendTenantCommunication();
                break;
            case 5:
                submitMaintenanceRequest();
                break;
            case 6:
                manageVendor();
                break;
            case 7:
                viewPortfolioOverview();
                break;
            case 8:
                generateCashFlowForecast();
                break;
            case 9:
                analyzeInvestment();
                break;
            case 0:
                cout << "Exiting program..." << endl;
                return 0;
            default:
                cout << "Invalid choice. Please try again." << endl;
        }
    }

    return 0;
}



