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

    // whitelist-related members
    set<string> whitelistedIPs;
    map<string, string> whitelistReasons;   
    map<string, string> whitelistApprovers; 
    map<string, chrono::system_clock::time_point> whitelistExpiry;

    // Private helper methods for whitelist
    bool validateIPFormat(const string& ipAddress);
    bool isIPExpired(const string& ipAddress);
    void cleanupExpiredWhitelists();
    void logWhitelistChange(const string& ipAddress, 
                           const string& action, 
                           const string& username);

 // New file validation related members
    const set<string> allowedFileExtensions = {
        ".pdf", ".doc", ".docx", ".txt", ".jpg", ".jpeg", 
        ".png", ".csv", ".xlsx", ".xls"
    };
    const size_t MAX_FILE_SIZE = 10 * 1024 * 1024;  
    const map<string, string> mimeTypes = {
        {".pdf", "application/pdf"},
        {".doc", "application/msword"},
        {".docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
        {".txt", "text/plain"},
        {".jpg", "image/jpeg"},
        {".jpeg", "image/jpeg"},
        {".png", "image/png"},
        {".csv", "text/csv"},
        {".xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
        {".xls", "application/vnd.ms-excel"}
    };

    struct FileMetadata {
        string filename;
        string mimeType;
        size_t fileSize;
        string uploadedBy;
        chrono::system_clock::time_point uploadTime;
        string checksum;
        bool isScanned;
        bool isSafe;
    };

    map<string, FileMetadata> fileRegistry;

    // Private helper methods for file validation
    bool isFileExtensionAllowed(const string& filename);
    string getFileExtension(const string& filename);
    string getMimeType(const string& filename);
    bool scanForMalware(const string& filePath);
    string calculateFileChecksum(const string& filePath);
    bool validateFileContent(const string& filePath, const string& expectedMimeType);
    void logFileActivity(const string& filename, 
                        const string& action, 
                        const string& username);

// Private helper methods for file validation
bool SecurityFunctions::isFileExtensionAllowed(const string& filename) {
    string ext = getFileExtension(filename);
    transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    return allowedFileExtensions.find(ext) != allowedFileExtensions.end();
}

string SecurityFunctions::getFileExtension(const string& filename) {
    size_t pos = filename.find_last_of(".");
    return (pos == string::npos) ? "" : filename.substr(pos);
}

string SecurityFunctions::getMimeType(const string& filename) {
    string ext = getFileExtension(filename);
    transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    auto it = mimeTypes.find(ext);
    return (it != mimeTypes.end()) ? it->second : "application/octet-stream";
}

bool SecurityFunctions::scanForMalware(const string& filePath) {
    try {
        // Implement actual malware scanning here
        logAuditEvent("malware_scan", "", "Scanning file: " + filePath);
        return true;  // File is safe
    } catch (const exception& e) {
        logSecurityEvent("malware_scan_error", "", e.what());
        return false;
    }
}

string SecurityFunctions::calculateFileChecksum(const string& filePath) {
    try {
        // Implement actual checksum calculation here
        return "checksum_placeholder";
    } catch (const exception& e) {
        throw runtime_error("Failed to calculate checksum: " + string(e.what()));
    }
}

bool SecurityFunctions::validateFileContent(const string& filePath, const string& expectedMimeType) {
    try {
        // Implement actual file content validation here
        return true;
    } catch (const exception& e) {
        logSecurityEvent("content_validation_error", "", e.what());
        return false;
    }
}

void SecurityFunctions::logFileActivity(const string& filename, 
                                      const string& action, 
                                      const string& username) {
    string details = "File: " + filename + ", Action: " + action;
    logAuditEvent("file_activity", username, details);
}

// file validation methods
SecurityFunctions::FileValidationResult 
SecurityFunctions::validateFileUpload(const string& filePath,
                                    const string& username,
                                    const set<string>& allowedTypes) {
    FileValidationResult result;
    result.isValid = true;
    
    try {
        // Basic file checks
        fs::path path(filePath);
        string filename = path.filename().string();

        // Check if file exists
        if (!fs::exists(filePath)) {
            result.errors.push_back("File does not exist");
            result.isValid = false;
            return result;
        }

        // File size check
        size_t fileSize = fs::file_size(filePath);
        if (fileSize > MAX_FILE_SIZE) {
            result.errors.push_back("File exceeds maximum size limit");
            result.isValid = false;
        }

        // File extension check
        if (!isFileExtensionAllowed(filename)) {
            result.errors.push_back("File type not allowed");
            result.isValid = false;
        }

        // Custom allowed types check
        if (!allowedTypes.empty()) {
            string ext = getFileExtension(filename);
            if (allowedTypes.find(ext) == allowedTypes.end()) {
                result.errors.push_back("File type not in allowed list");
                result.isValid = false;
            }
        }

        // MIME type validation
        string expectedMimeType = getMimeType(filename);
        if (!validateFileContent(filePath, expectedMimeType)) {
            result.errors.push_back("File content does not match extension");
            result.isValid = false;
        }

        // Malware scan
        if (!scanForMalware(filePath)) {
            result.errors.push_back("File failed security scan");
            result.isValid = false;
        }

        // Create metadata
        if (result.isValid) {
            string checksum = calculateFileChecksum(filePath);
            result.metadata = {
                filename,
                expectedMimeType,
                fileSize,
                username,
                chrono::system_clock::now(),
                checksum,
                true,  
                true   
            };

            // Register the file
            fileRegistry[filename] = result.metadata;
            
            // Log successful validation
            logFileActivity(filename, "validated", username);
        } else {
            // Log failed validation
            string errorList = "Errors: ";
            for (const auto& error : result.errors) {
                errorList += error + "; ";
            }
            logSecurityEvent("file_validation_failed", username, errorList);
        }

    } catch (const exception& e) {
        result.isValid = false;
        result.errors.push_back("Validation error: " + string(e.what()));
        logSecurityEvent("file_validation_error", username, e.what());
    }

    return result;
}

bool SecurityFunctions::processFileUpload(const string& filePath,
                                        const string& username,
                                        const string& destinationPath) {
    try {
        // Validate file
        auto validationResult = validateFileUpload(filePath, username);
        if (!validationResult.isValid) {
            return false;
        }

        // Create destination directory if it doesn't exist
        fs::create_directories(destinationPath);

        // Generate unique filename to prevent overwrites
        fs::path sourcePath(filePath);
        string filename = sourcePath.filename().string();
        string uniqueFilename = filename;
        int counter = 1;
        
        while (fs::exists(destinationPath + "/" + uniqueFilename)) {
            string extension = getFileExtension(filename);
            string baseName = filename.substr(0, filename.length() - extension.length());
            uniqueFilename = baseName + "_" + to_string(counter++) + extension;
        }

        // Copy file to destination
        fs::copy(filePath, destinationPath + "/" + uniqueFilename);

        // Update file registry
        fileRegistry[uniqueFilename] = validationResult.metadata;

        // Log successful upload
        logFileActivity(uniqueFilename, "uploaded", username);

        return true;

    } catch (const exception& e) {
        logSecurityEvent("file_upload_error", username, e.what());
        return false;
    }
}

bool SecurityFunctions::deleteFile(const string& filename, const string& username) {
    try {
        // Check permissions
        if (!hasRole(username, "Admin") && !hasRole(username, "IT")) {
            logSecurityEvent("unauthorized_file_deletion", username);
            return false;
        }

        auto it = fileRegistry.find(filename);
        if (it == fileRegistry.end()) {
            logSecurityEvent("file_not_found", username, "File: " + filename);
            return false;
        }

        // Delete file
        fs::remove(filename);
        fileRegistry.erase(it);
        
        logFileActivity(filename, "deleted", username);
        return true;

    } catch (const exception& e) {
        logSecurityEvent("file_deletion_error", username, e.what());
        return false;
    }
}

bool SecurityFunctions::quarantineFile(const string& filename, const string& username) {
    try {
        auto it = fileRegistry.find(filename);
        if (it == fileRegistry.end()) {
            return false;
        }

        // Move to quarantine directory
        fs::path quarantinePath = "/quarantine/" + filename;
        fs::create_directories(quarantinePath.parent_path());
        fs::rename(filename, quarantinePath);

        // Update metadata
        it->second.isSafe = false;
        
        logFileActivity(filename, "quarantined", username);
        return true;

    } catch (const exception& e) {
        logSecurityEvent("quarantine_error", username, e.what());
        return false;
    }
}

map<string, int> SecurityFunctions::getFileStatistics() {
    map<string, int> stats;
    for (const auto& file : fileRegistry) {
        string ext = getFileExtension(file.first);
        stats[ext]++;
    }
    return stats;
}

bool SecurityFunctions::verifyFileIntegrity(const string& filename) {
    try {
        auto it = fileRegistry.find(filename);
        if (it == fileRegistry.end()) {
            return false;
        }

        string currentChecksum = calculateFileChecksum(filename);
        return currentChecksum == it->second.checksum;

    } catch (const exception& e) {
        logSecurityEvent("integrity_check_error", "", e.what());
        return false;
    }
}

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

    // whitelist management functions
    bool whitelistIP(const string& ipAddress,
                    const string& username,
                    const string& reason,
                    int expiryDays = 30);
    bool removeFromWhitelist(const string& ipAddress,
                           const string& username);
    bool isIPWhitelisted(const string& ipAddress);
    vector<pair<string, string>> getWhitelistedIPs(); // Returns IP-Reason pairs
    bool updateWhitelistExpiry(const string& ipAddress,
                             const string& username,
                             int newExpiryDays);
    bool bulkWhitelistIPs(const vector<string>& ipAddresses,
                         const string& username,
                         const string& reason);
    string getWhitelistReason(const string& ipAddress);
    string getWhitelistApprover(const string& ipAddress);
    chrono::system_clock::time_point getWhitelistExpiry(const string& ipAddress);
    vector<string> getExpiringWhitelists(int daysToExpiry = 7);
    void exportWhitelist(const string& filePath);
    bool importWhitelist(const string& filePath, const string& username);

// New file validation methods
    struct FileValidationResult {
        bool isValid;
        vector<string> errors;
        FileMetadata metadata;
    };

    FileValidationResult validateFileUpload(const string& filePath,
                                          const string& username,
                                          const set<string>& allowedTypes = {});
    bool processFileUpload(const string& filePath,
                          const string& username,
                          const string& destinationPath);
    bool deleteFile(const string& filename, const string& username);
    vector<FileMetadata> getFileHistory(const string& username);
    bool quarantineFile(const string& filename, const string& username);
    bool restoreFile(const string& filename, const string& username);
    bool isFileQuarantined(const string& filename);
    vector<FileMetadata> getQuarantinedFiles();
    void cleanupOldFiles(int daysToKeep = 30);
    map<string, int> getFileStatistics();
    bool verifyFileIntegrity(const string& filename);

// New session management methods
    struct SessionResult {
        bool success;
        string sessionId;
        string message;

    SessionResult createSession(const string& username, 
                              const string& ipAddress,
                              int timeoutMinutes = 30);
    bool validateSession(const string& sessionId);
    bool endSession(const string& sessionId);
    bool extendSession(const string& sessionId, int additionalMinutes);
    bool forceLogout(const string& username);
    vector<SessionInfo> getActiveSessions(const string& username);
    bool checkSessionTimeout(const string& sessionId);
    bool updateSessionData(const string& sessionId, 
                          const string& key, 
                          const string& value);
    string getSessionData(const string& sessionId, const string& key);
    bool terminateAllSessions(const string& username);
    map<string, int> getSessionStatistics();
    bool isUserLoggedIn(const string& username);
};

#endif 
