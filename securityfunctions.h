#ifndef SECURITY_FUNCTIONS_H
#define SECURITY_FUNCTIONS_H

#include <iostream>
#include <string>
#include <stdexcept>
#include <memory>
#include <vector>
#include <regex>
#include <set>
#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <map>
#include <queue>

using namespace std;

class SecurityFunctions {
private:
    PropertyManagementSystem& system;
    
    // Set of valid roles
    const set<string> validRoles = {
        "Admin", "Employee", "Tenant", "Owner", 
        "Advisor", "IT", "Maintenance"
    };
    
    // Intrusion detection related members
    struct LoginAttempt {
        string ipAddress;
        chrono::system_clock::time_point timestamp;
    };
    
    map<string, queue<LoginAttempt>> loginAttempts;  // Track login attempts per IP
    map<string, int> blacklistedIPs;                 // Track blocked IPs and their violation count
    const int MAX_LOGIN_ATTEMPTS = 5;                // Maximum allowed login attempts
    const int ATTEMPT_WINDOW_SECONDS = 300;          // Time window for tracking attempts (5 minutes)
    const int BLACKLIST_THRESHOLD = 3;               // Number of violations before permanent blacklist
    
    // Private helper methods for role management
    bool isValidRole(const string& role);
    bool hasPermissionToGrantRole(const string& granterUsername, const string& targetRole);
    void logRoleChange(const string& username, const string& oldRole, const string& newRole);

    // Private helper methods for audit logging
    string getCurrentTimestamp();
    string formatLogMessage(const string& event, 
                          const string& username, 
                          const string& details);
    string getSeverityLevel(const string& event);
    bool isHighRiskEvent(const string& event);

    // Private helper methods for intrusion detection
    void cleanupOldAttempts(const string& ipAddress);
    bool isIPBlacklisted(const string& ipAddress);
    void updateLoginAttempts(const string& ipAddress);
    string analyzeIPPattern(const string& ipAddress);
    bool isKnownMaliciousPattern(const string& pattern);

public:
    // Constructor
    SecurityFunctions(PropertyManagementSystem& sys) : system(sys) {}

    // Password management functions
    bool handlePasswordChange(const string& username, 
                            const string& currentPassword, 
                            const string& newPassword, 
                            const string& confirmPassword);
    bool validatePasswordStrength(const string& password);
    
    // Basic security functions
    bool checkLoginAttempts(const string& username);
    void handleSecurityBreach(const string& username, const string& ipAddress);

    // Role management functions
    bool grantRole(const string& granterUsername,
                  const string& targetUsername, 
                  const string& newRole);
    bool revokeRole(const string& granterUsername,
                   const string& targetUsername);
    string getCurrentRole(const string& username);
    bool hasRole(const string& username, const string& role);

    // Audit logging functions
    bool logAuditEvent(const string& event, 
                      const string& username,
                      const string& details = "",
                      const string& ipAddress = "");
    bool logSecurityEvent(const string& event, 
                         const string& username,
                         const string& details = "");
    vector<string> getRecentAuditLogs(const string& username, 
                                    int numberOfLogs = 10);
    bool clearAuditLogs(const string& adminUsername);

    // New intrusion detection functions
    bool detectIntrusion(const string& ipAddress, 
                        const string& username = "",
                        const string& actionType = "");
    void blacklistIP(const string& ipAddress, const string& reason);
    bool isIPSuspicious(const string& ipAddress);
    void clearBlacklist(const string& adminUsername);
    vector<string> getBlacklistedIPs();
    void handleFailedLogin(const string& username, const string& ipAddress);
    void reportSuspiciousActivity(const string& ipAddress, 
                                const string& activityType,
                                const string& details = "");
};

#endif 
