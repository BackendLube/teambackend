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
#include <filesystem>
#include <fstream>

using namespace std;
namespace fs = std::filesystem;

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

    struct BackupMetadata {
        string backupId;
        chrono::system_clock::time_point timestamp;
        string type;  
        string status;
        size_t size;
        string encryptionKey;
    };

    map<string, BackupMetadata> backupHistory;
    const string BACKUP_BASE_PATH = "/secure/backups/";
    const int MAX_BACKUP_RETENTION_DAYS = 30;
    const int INCREMENTAL_BACKUP_INTERVAL = 24; 

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
    //Private helper for backup
    string generateBackupId();
    bool validateBackupIntegrity(const string& backupPath, const string& checksum);
    void encryptBackup(const string& backupPath, const string& encryptionKey);
    bool compressBackupData(const string& sourcePath, const string& destPath);
    void cleanupOldBackups();
    string calculateChecksum(const string& filePath);
    bool verifyBackupPermissions(const string& username);

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

// New backup security functions
    bool performSecureBackup(const string& username, 
                           const string& backupType = "full",
                           const string& customPath = "");
    bool restoreFromBackup(const string& username,
                          const string& backupId,
                          const string& targetPath = "");
    vector<BackupMetadata> getBackupHistory(const string& username);
    bool verifyBackup(const string& backupId);
    bool deleteBackup(const string& username, const string& backupId);
    bool scheduleAutomaticBackup(const string& username,
                               const string& frequency,
                               const string& backupType);
    bool performIncrementalBackup(const string& username);
    string getLatestBackupStatus(const string& username);
    size_t getBackupSize(const string& backupId);
    bool exportBackupMetadata(const string& username, const string& outputPath);
};

#endif 
