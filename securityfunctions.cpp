#include "SecurityFunctions.h"

bool SecurityFunctions::handlePasswordChange(const string& username, 
                                          const string& currentPassword, 
                                          const string& newPassword, 
                                          const string& confirmPassword) {
    try {
        // Verify user login with current password
        if (!system.userLogin(username, currentPassword)) {
            cout << "Error: Current password is incorrect." << endl;
            system.logAuditEvent("failed_password_change", username);
            return false;
        }

        // Verify that new password matches confirmation
        if (newPassword != confirmPassword) {
            cout << "Error: New password and confirmation do not match." << endl;
            system.logAuditEvent("failed_password_change", username);
            return false;
        }

        // Check if new password is same as old password
        if (currentPassword == newPassword) {
            cout << "Error: New password must be different from current password." << endl;
            system.logAuditEvent("failed_password_change", username);
            return false;
        }

        // Validate password strength
        if (!validatePasswordStrength(newPassword)) {
            system.logAuditEvent("failed_password_change", username);
            return false;
        }

        // Enforce password policy
        try {
            system.enforcePasswordPolicy(username, newPassword);
        } catch (const exception& e) {
            cout << "Error: Password does not meet security requirements:" << endl;
            cout << "- Minimum 8 characters" << endl;
            cout << "- At least one number" << endl;
            cout << "- At least one special character (!@#$%^&*)" << endl;
            system.logAuditEvent("failed_password_change", username);
            return false;
        }

        // Change the password
        system.changePassword(username, newPassword);
        // Log the successful password change
        system.logAuditEvent("successful_password_change", username;
        // Monitor for suspicious activity
        system.monitorSuspiciousActivity(username);
        // Encrypt the new password data
        system.encryptSensitiveData("password_change", username);

        cout << "Password successfully changed." << endl;
        return true;

    } catch (const exception& e) {
        cerr << "Error during password change: " << e.what() << endl;
        system.logAuditEvent("error_password_change", username);
        return false;
    }
}

bool SecurityFunctions::validatePasswordStrength(const string& password) {
    // Check minimum length
    if (password.length() < 8) {
        cout << "Password must be at least 8 characters long." << endl;
        return false;
    }

    // Check for at least one uppercase letter
    if (password.find_first_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ") == string::npos) {
        cout << "Password must contain at least one uppercase letter." << endl;
        return false;
    }

    // Check for at least one lowercase letter
    if (password.find_first_of("abcdefghijklmnopqrstuvwxyz") == string::npos) {
        cout << "Password must contain at least one lowercase letter." << endl;
        return false;
    }

    // Check for at least one number
    if (password.find_first_of("0123456789") == string::npos) {
        cout << "Password must contain at least one number." << endl;
        return false;
    }

    // Check for at least one special character
    if (password.find_first_of("!@#$%^&*()_+-=[]{}|;:,.<>?") == string::npos) {
        cout << "Password must contain at least one special character." << endl;
        return false;
    }

    return true;
}

void SecurityFunctions::logSecurityEvent(const string& event, const string& username) {
    system.logAuditEvent(event, username);
    
    // Additional logging logic can be added here
    cout << "Security event logged: " << event << " for user: " << username << endl;
}

bool SecurityFunctions::checkLoginAttempts(const string& username) {
    system.monitorSuspiciousActivity(username);
    return true; // Return true if within acceptable limits
}

void SecurityFunctions::handleSecurityBreach(const string& username, const string& ipAddress) {
    // Log the security breach
    system.logAuditEvent("security_breach", username);
    system.detectIntrusion(ipAddress);
    
    // Additional breach handling logic
    cout << "Security breach detected for user: " << username << " from IP: " << ipAddress << endl;
}
//User role function
bool SecurityFunctions::isValidRole(const string& role) {
    return validRoles.find(role) != validRoles.end();
}

bool SecurityFunctions::hasPermissionToGrantRole(const string& granterUsername, const string& targetRole) {
    try {
        string granterRole = getCurrentRole(granterUsername);
        
        // Only Admins can grant Admin roles
        if (targetRole == "Admin") {
            return granterRole == "Admin";
        }
        
        // Admins can grant any role
        if (granterRole == "Admin") {
            return true;
        }
        
        // Employees can grant basic roles (Tenant, Maintenance)
        if (granterRole == "Employee") {
            return (targetRole == "Tenant" || targetRole == "Anaylist");
        }
        
        // Other roles cannot grant roles
        return false;
        
    } catch (const exception& e) {
        cerr << "Error checking role permissions: " << e.what() << endl;
        return false;
    }
}

void SecurityFunctions::logRoleChange(const string& username, const string& oldRole, const string& newRole) {
    string logMessage = "Role change: User '" + username + "' from '" + 
                       oldRole + "' to '" + newRole + "'";
    system.logAuditEvent("role_change", logMessage);
}

// Public role management methods
bool SecurityFunctions::grantRole(const string& granterUsername,
                                const string& targetUsername, 
                                const string& newRole) {
    try {
        // Validate the new role
        if (!isValidRole(newRole)) {
            cout << "Error: Invalid role specified." << endl;
            system.logAuditEvent("invalid_role_grant_attempt", 
                               "Attempt to grant invalid role: " + newRole);
            return false;
        }

        // Check if granter has permission to assign this role
        if (!hasPermissionToGrantRole(granterUsername, newRole)) {
            cout << "Error: Insufficient permissions to grant this role." << endl;
            system.logAuditEvent("unauthorized_role_grant_attempt",
                               granterUsername + " attempted to grant " + newRole);
            return false;
        }

        // Get current role of target user
        string currentRole = getCurrentRole(targetUsername);
        
        // Check if it's the same role
        if (currentRole == newRole) {
            cout << "User already has this role." << endl;
            return true;
        }

        // Grant the new role
        system.grantRole(targetUsername, newRole);
        
        // Log the role change
        logRoleChange(targetUsername, currentRole, newRole);
        
        // Monitor for suspicious activity
        system.monitorSuspiciousActivity(targetUsername);
        
        cout << "Role successfully granted: " << newRole << " to user: " << targetUsername << endl;
        return true;

    } catch (const exception& e) {
        cerr << "Error granting role: " << e.what() << endl;
        system.logAuditEvent("role_grant_error", 
                           "Error granting " + newRole + " to " + targetUsername);
        return false;
    }
}

// Audit Logging Functions
string SecurityFunctions::getCurrentTimestamp() {
    auto now = chrono::system_clock::now();
    auto time = chrono::system_clock::to_time_t(now);
    auto ms = chrono::duration_cast<chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    stringstream ss;
    ss << put_time(localtime(&time), "%Y-%m-%d %H:%M:%S");
    ss << '.' << setfill('0') << setw(3) << ms.count();
    
    return ss.str();
}

string SecurityFunctions::formatLogMessage(const string& event, 
                                        const string& username, 
                                        const string& details) {
    stringstream ss;
    ss << "["  << getCurrentTimestamp() << "] "
       << "[" << getSeverityLevel(event) << "] "
       << "[" << event << "] "
       << "User: " << username << " "
       << (details.empty() ? "" : "Details: " + details);
    return ss.str();
}

string SecurityFunctions::getSeverityLevel(const string& event) {
    if (event.find("failed") != string::npos || 
        event.find("error") != string::npos ||
        event.find("breach") != string::npos ||
        event.find("intrusion") != string::npos) {
        return "HIGH";
    }
    
    if (event.find("warning") != string::npos ||
        event.find("attempt") != string::npos) {
        return "MEDIUM";
    }
    
    return "LOW";
}

bool SecurityFunctions::isHighRiskEvent(const string& event) {
    return getSeverityLevel(event) == "HIGH";
}

bool SecurityFunctions::logAuditEvent(const string& event, 
                                    const string& username,
                                    const string& details,
                                    const string& ipAddress) {
    try {
        // Step 1: Validate input parameters
        if (event.empty() || username.empty()) {
            cerr << "Error: Event and username are required for audit logging." << endl;
            return false;
        }

        // Step 2: Format the log message
        string logMessage = formatLogMessage(event, username, details);

        // Step 3: Add IP address if provided
        if (!ipAddress.empty()) {
            logMessage += " IP: " + ipAddress;
        }

        // Step 4: Log to system
        system.logAuditEvent(event, logMessage);

        // Step 5: Handle high-risk events
        if (isHighRiskEvent(event)) {
            system.monitorSuspiciousActivity(username);
            if (!ipAddress.empty()) {
                system.detectIntrusion(ipAddress);
            }
        }

        // Step 6: Encrypt sensitive log data if necessary
        if (event.find("password") != string::npos || 
            event.find("credential") != string::npos) {
            system.encryptSensitiveData("audit_log", logMessage);
        }

        return true;

    } catch (const exception& e) {
        cerr << "Error in audit logging: " << e.what() << endl;
        try {
            system.logAuditEvent("audit_log_error", 
                               "Failed to log event: " + event + 
                               " for user: " + username);
        } catch (...) {
            cerr << "Critical: Failed to log audit error" << endl;
        }
        return false;
    }
}

// Additional methods that need to be implemented...
void SecurityFunctions::logRoleChange(const string& username, const string& oldRole, const string& newRole) {
    string logMessage = "Role change: User '" + username + "' from '" + 
                       oldRole + "' to '" + newRole + "'";
    logAuditEvent("role_change", username, logMessage);
}

bool SecurityFunctions::checkLoginAttempts(const string& username) {
    system.monitorSuspiciousActivity(username);
    return true;
}

void SecurityFunctions::handleSecurityBreach(const string& username, const string& ipAddress) {
    logSecurityEvent("security_breach", username, "Potential security breach detected");
    system.detectIntrusion(ipAddress);
}

string SecurityFunctions::getCurrentRole(const string& username) {
    // This would typically query the database through PropertyManagementSystem
    return "User"; // Replace with actual implementation
}

bool SecurityFunctions::hasRole(const string& username, const string& role) {
    return getCurrentRole(username) == role;
}
