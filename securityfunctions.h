#ifndef SECURITY_FUNCTIONS_H
#define SECURITY_FUNCTIONS_H

#include <iostream>
#include <string>
#include <stdexcept>
#include <memory>
#include <vector>
#include <regex>
#include <set>

using namespace std;

class SecurityFunctions {
private:
    PropertyManagementSystem& system;  // Reference to the main system

      // Set of valid roles
    const set<string> validRoles = {
        "Admin", "Property Manager", "Tenant", "Investment Analyst"
    };
    
    // Private helper methods for role management
    bool isValidRole(const string& role);
    bool hasPermissionToGrantRole(const string& granterUsername, const string& targetRole);
    void logRoleChange(const string& username, const string& oldRole, const string& newRole);

public:
    // Constructor takes a reference to PropertyManagementSystem
    SecurityFunctions(PropertyManagementSystem& sys) : system(sys) {}

    // Password change function
    bool handlePasswordChange(const string& username, 
                            const string& currentPassword, 
                            const string& newPassword, 
                            const string& confirmPassword);
    
    // Additional security functions can be added here
    bool validatePasswordStrength(const string& password);
    void logSecurityEvent(const string& event, const string& username);
    bool checkLoginAttempts(const string& username);
    void handleSecurityBreach(const string& username, const string& ipAddress);

    // New role management functions
    bool grantRole(const string& granterUsername,
                  const string& targetUsername, 
                  const string& newRole);
    bool revokeRole(const string& granterUsername,
                   const string& targetUsername);
    string getCurrentRole(const string& username);
    bool hasRole(const string& username, const string& role);
   
};

#endif 
