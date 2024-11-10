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
