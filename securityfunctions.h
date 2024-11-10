#ifndef SECURITY_FUNCTIONS_H
#define SECURITY_FUNCTIONS_H

#include <iostream>
#include <string>
#include <stdexcept>
#include <memory>
#include <vector>
#include <regex>
#include <random>
#include <chrono>
#include <ctime>
#include <map>

using namespace std;

class SecurityFunctions {
private:
    PropertyManagementSystem& system;  // Reference to the main system
    map<string, string> tempTwoFactorCodes; // Stores temporary 2FA codes
    map<string, chrono::system_clock::time_point> codeExpiryTimes; // Stores code expiry times
    
    // Private helper methods for 2FA
    string generateTwoFactorCode();
    bool isCodeValid(const string& code, const string& username);
    bool isCodeExpired(const string& username);
    void storeTwoFactorCode(const string& username, const string& code);
    void cleanupExpiredCodes();

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

    // New 2FA functions
    bool setupTwoFactorAuth(const string& username);
    bool verifyTwoFactorAuth(const string& username, const string& code);
    bool disableTwoFactorAuth(const string& username, const string& password);
    bool generateNewTwoFactorCode(const string& username);
    bool isTwoFactorEnabled(const string& username);
};

#endif 
