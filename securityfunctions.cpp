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
    detectIntrusion(ipAddress, username, "security_breach");
    system.monitorSuspiciousActivity(username);
}

string SecurityFunctions::getCurrentRole(const string& username) {
    // This would typically query the database through PropertyManagementSystem
    return "User"; // Replace with actual implementation
}

bool SecurityFunctions::hasRole(const string& username, const string& role) {
    return getCurrentRole(username) == role;
}

// Private helper methods for intrusion detection
void SecurityFunctions::cleanupOldAttempts(const string& ipAddress) {
    if (loginAttempts.find(ipAddress) == loginAttempts.end()) {
        return;
    }

    auto& attempts = loginAttempts[ipAddress];
    auto now = chrono::system_clock::now();

    while (!attempts.empty()) {
        auto& oldestAttempt = attempts.front();
        auto seconds = chrono::duration_cast<chrono::seconds>(
            now - oldestAttempt.timestamp).count();
        
        if (seconds > ATTEMPT_WINDOW_SECONDS) {
            attempts.pop();
        } else {
            break;
        }
    }
}

bool SecurityFunctions::isIPBlacklisted(const string& ipAddress) {
    return blacklistedIPs.find(ipAddress) != blacklistedIPs.end();
}

void SecurityFunctions::updateLoginAttempts(const string& ipAddress) {
    LoginAttempt attempt = {
        ipAddress,
        chrono::system_clock::now()
    };
    
    if (loginAttempts.find(ipAddress) == loginAttempts.end()) {
        queue<LoginAttempt> newQueue;
        loginAttempts[ipAddress] = newQueue;
    }
    
    loginAttempts[ipAddress].push(attempt);
    cleanupOldAttempts(ipAddress);
}

string SecurityFunctions::analyzeIPPattern(const string& ipAddress) {
    // Implement pattern analysis logic here
    // For example, check if IP is from known malicious ranges
    // or if it follows suspicious patterns
    return "normal"; // Replace with actual pattern analysis
}

bool SecurityFunctions::isKnownMaliciousPattern(const string& pattern) {
    // Check against known malicious patterns
    return false; // Replace with actual pattern checking
}

// Public intrusion detection methods
bool SecurityFunctions::detectIntrusion(const string& ipAddress, 
                                     const string& username,
                                     const string& actionType) {
    try {
        // Step 1: Check if IP is already blacklisted
        if (isIPBlacklisted(ipAddress)) {
            logSecurityEvent("blocked_blacklisted_ip", username,
                           "Blocked attempt from blacklisted IP: " + ipAddress);
            return true;
        }

        // Step 2: Update and check login attempts
        updateLoginAttempts(ipAddress);
        auto& attempts = loginAttempts[ipAddress];
        
        if (attempts.size() >= MAX_LOGIN_ATTEMPTS) {
            blacklistIP(ipAddress, "Exceeded maximum login attempts");
            logSecurityEvent("ip_blacklisted", username,
                           "IP blacklisted for excessive attempts: " + ipAddress);
            return true;
        }

        // Step 3: Analyze IP pattern
        string pattern = analyzeIPPattern(ipAddress);
        if (isKnownMaliciousPattern(pattern)) {
            blacklistIP(ipAddress, "Matched malicious pattern: " + pattern);
            logSecurityEvent("malicious_pattern_detected", username,
                           "Malicious pattern from IP: " + ipAddress);
            return true;
        }

        // Step 4: Check for suspicious activity patterns
        if (isIPSuspicious(ipAddress)) {
            logSecurityEvent("suspicious_activity", username,
                           "Suspicious activity detected from IP: " + ipAddress);
            system.monitorSuspiciousActivity(username);
            return true;
        }

        // Step 5: Log the activity
        if (!actionType.empty()) {
            logAuditEvent("security_check", username,
                         "Action type: " + actionType, ipAddress);
        }

        return false;

    } catch (const exception& e) {
        cerr << "Error in intrusion detection: " << e.what() << endl;
        logSecurityEvent("intrusion_detection_error", username, e.what());
        return false;
    }
}

void SecurityFunctions::blacklistIP(const string& ipAddress, const string& reason) {
    blacklistedIPs[ipAddress]++;
    
    if (blacklistedIPs[ipAddress] >= BLACKLIST_THRESHOLD) {
        logSecurityEvent("permanent_ip_blacklist", "",
                        "IP: " + ipAddress + " permanently blacklisted. Reason: " + reason);
    } else {
        logSecurityEvent("temporary_ip_blacklist", "",
                        "IP: " + ipAddress + " temporarily blacklisted. Reason: " + reason);
    }
}

bool SecurityFunctions::isIPSuspicious(const string& ipAddress) {
    cleanupOldAttempts(ipAddress);
    
    if (loginAttempts.find(ipAddress) == loginAttempts.end()) {
        return false;
    }

    // Check for rapid successive attempts
    auto& attempts = loginAttempts[ipAddress];
    if (attempts.size() >= 3) {  // Threshold for suspicious activity
        auto now = chrono::system_clock::now();
        auto oldestAttempt = attempts.front().timestamp;
        auto seconds = chrono::duration_cast<chrono::seconds>(
            now - oldestAttempt).count();
        
        // If 3 or more attempts within 60 seconds
        if (seconds < 60) {
            return true;
        }
    }

    return false;
}

void SecurityFunctions::clearBlacklist(const string& adminUsername) {
    if (!hasRole(adminUsername, "Admin")) {
        logSecurityEvent("unauthorized_blacklist_clear", adminUsername,
                        "Attempted to clear IP blacklist without admin privileges");
        return;
    }

    blacklistedIPs.clear();
    logAuditEvent("blacklist_cleared", adminUsername);
}

vector<string> SecurityFunctions::getBlacklistedIPs() {
    vector<string> ips;
    for (const auto& pair : blacklistedIPs) {
        ips.push_back(pair.first);
    }
    return ips;
}

void SecurityFunctions::handleFailedLogin(const string& username, const string& ipAddress) {
    updateLoginAttempts(ipAddress);
    
    if (detectIntrusion(ipAddress, username, "failed_login")) {
        logSecurityEvent("login_attempt_blocked", username,
                        "Failed login attempt blocked from IP: " + ipAddress);
    }
}

void SecurityFunctions::reportSuspiciousActivity(const string& ipAddress,
                                               const string& activityType,
                                               const string& details) {
    string fullDetails = "Activity Type: " + activityType + 
                        (details.empty() ? "" : ", Details: " + details);
    
    logSecurityEvent("suspicious_activity_reported", "",
                    fullDetails + " from IP: " + ipAddress);
                    
    if (isIPSuspicious(ipAddress)) {
        blacklistIP(ipAddress, "Multiple suspicious activities reported");
    }
}

// Private helper methods for backup
string SecurityFunctions::generateBackupId() {
    auto now = chrono::system_clock::now();
    auto timestamp = chrono::system_clock::to_time_t(now);
    stringstream ss;
    ss << "backup_" << put_time(localtime(&timestamp), "%Y%m%d_%H%M%S")
       << "_" << rand() % 1000;
    return ss.str();
}

bool SecurityFunctions::validateBackupIntegrity(const string& backupPath, const string& checksum) {
    string calculatedChecksum = calculateChecksum(backupPath);
    return calculatedChecksum == checksum;
}

void SecurityFunctions::encryptBackup(const string& backupPath, const string& encryptionKey) {
    try {
        // Implementation would use encryption library
        system.encryptSensitiveData("backup", backupPath);
        logAuditEvent("backup_encrypted", "", "Backup encrypted: " + backupPath);
    } catch (const exception& e) {
        throw runtime_error("Backup encryption failed: " + string(e.what()));
    }
}

bool SecurityFunctions::compressBackupData(const string& sourcePath, const string& destPath) {
    try {
        // Implementation would use compression library
        logAuditEvent("backup_compressed", "", "Backup compressed: " + sourcePath);
        return true;
    } catch (const exception& e) {
        logSecurityEvent("backup_compression_failed", "", e.what());
        return false;
    }
}

void SecurityFunctions::cleanupOldBackups() {
    try {
        auto now = chrono::system_clock::now();
        vector<string> backupsToDelete;

        for (const auto& backup : backupHistory) {
            auto age = chrono::duration_cast<chrono::hours>(
                now - backup.second.timestamp).count();
            if (age > MAX_BACKUP_RETENTION_DAYS * 24) {
                backupsToDelete.push_back(backup.first);
            }
        }

        for (const auto& backupId : backupsToDelete) {
            string backupPath = BACKUP_BASE_PATH + backupId;
            if (fs::exists(backupPath)) {
                fs::remove_all(backupPath);
                backupHistory.erase(backupId);
                logAuditEvent("backup_cleaned", "", "Removed old backup: " + backupId);
            }
        }
    } catch (const exception& e) {
        logSecurityEvent("backup_cleanup_error", "", e.what());
    }
}

string SecurityFunctions::calculateChecksum(const string& filePath) {
    try {
        // Implementation would calculate file checksum
        return "checksum_placeholder";
    } catch (const exception& e) {
        throw runtime_error("Checksum calculation failed: " + string(e.what()));
    }
}

bool SecurityFunctions::verifyBackupPermissions(const string& username) {
    try {
        string userRole = getCurrentRole(username);
        return userRole == "Admin" || userRole == "IT";
    } catch (const exception& e) {
        logSecurityEvent("backup_permission_check_failed", username, e.what());
        return false;
    }
}

// Public backup methods
bool SecurityFunctions::performSecureBackup(const string& username, 
                                          const string& backupType,
                                          const string& customPath) {
    try {
        // Step 1: Verify permissions
        if (!verifyBackupPermissions(username)) {
            logSecurityEvent("unauthorized_backup_attempt", username);
            return false;
        }

        // Step 2: Generate backup ID and paths
        string backupId = generateBackupId();
        string backupPath = customPath.empty() ? 
            BACKUP_BASE_PATH + backupId : customPath + backupId;

        // Step 3: Create backup directory
        fs::create_directories(backupPath);

        // Step 4: Perform the backup based on type
        if (backupType == "incremental" && !performIncrementalBackup(username)) {
            throw runtime_error("Incremental backup failed");
        }

        // Step 5: Compress the backup
        if (!compressBackupData(backupPath, backupPath + ".zip")) {
            throw runtime_error("Backup compression failed");
        }

        // Step 6: Calculate checksum
        string checksum = calculateChecksum(backupPath + ".zip");

        // Step 7: Encrypt the backup
        string encryptionKey = generateBackupId(); // Use proper key generation in practice
        encryptBackup(backupPath + ".zip", encryptionKey);

        // Step 8: Store backup metadata
        BackupMetadata metadata {
            backupId,
            chrono::system_clock::now(),
            backupType,
            "completed",
            fs::file_size(backupPath + ".zip"),
            encryptionKey
        };
        backupHistory[backupId] = metadata;

        // Step 9: Log the backup
        logAuditEvent("backup_completed", username,
                     "Backup ID: " + backupId + ", Type: " + backupType);

        // Step 10: Cleanup old backups
        cleanupOldBackups();

        return true;

    } catch (const exception& e) {
        logSecurityEvent("backup_failed", username, e.what());
        return false;
    }
}

bool SecurityFunctions::restoreFromBackup(const string& username,
                                        const string& backupId,
                                        const string& targetPath) {
    try {
        // Step 1: Verify permissions
        if (!verifyBackupPermissions(username)) {
            logSecurityEvent("unauthorized_restore_attempt", username);
            return false;
        }

        // Step 2: Verify backup exists
        if (backupHistory.find(backupId) == backupHistory.end()) {
            throw runtime_error("Backup not found: " + backupId);
        }

        // Step 3: Verify backup integrity
        string backupPath = BACKUP_BASE_PATH + backupId + ".zip";
        if (!validateBackupIntegrity(backupPath, "stored_checksum")) {
            throw runtime_error("Backup integrity check failed");
        }

        // Step 4: Decrypt the backup
        const auto& metadata = backupHistory[backupId];
        system.encryptSensitiveData("restore", backupPath); // Decrypt operation

        // Step 5: Perform the restore
        fs::create_directories(targetPath);
        // Implementation would restore files here

        // Step 6: Log the restore
        logAuditEvent("backup_restored", username,
                     "Restored backup ID: " + backupId);

        return true;

    } catch (const exception& e) {
        logSecurityEvent("restore_failed", username, e.what());
        return false;
    }
}

vector<SecurityFunctions::BackupMetadata> SecurityFunctions::getBackupHistory(
    const string& username) {
    vector<BackupMetadata> history;
    try {
        if (!verifyBackupPermissions(username)) {
            throw runtime_error("Unauthorized access to backup history");
        }

        for (const auto& backup : backupHistory) {
            history.push_back(backup.second);
        }
    } catch (const exception& e) {
        logSecurityEvent("backup_history_access_failed", username, e.what());
    }
    return history;
}

bool SecurityFunctions::verifyBackup(const string& backupId) {
    try {
        if (backupHistory.find(backupId) == backupHistory.end()) {
            return false;
        }

        string backupPath = BACKUP_BASE_PATH + backupId + ".zip";
        return validateBackupIntegrity(backupPath, "stored_checksum");
    } catch (const exception& e) {
        logSecurityEvent("backup_verification_failed", "", e.what());
        return false;
    }
}

bool SecurityFunctions::deleteBackup(const string& username, const string& backupId) {
    try {
        if (!verifyBackupPermissions(username)) {
            logSecurityEvent("unauthorized_backup_deletion", username);
            return false;
        }

        if (backupHistory.find(backupId) == backupHistory.end()) {
            throw runtime_error("Backup not found: " + backupId);
        }

        string backupPath = BACKUP_BASE_PATH + backupId;
        fs::remove_all(backupPath);
        backupHistory.erase(backupId);

        logAuditEvent("backup_deleted", username, "Deleted backup: " + backupId);
        return true;

    } catch (const exception& e) {
        logSecurityEvent("backup_deletion_failed", username, e.what());
        return false;
    }
}

// Private helper methods for whitelist
bool SecurityFunctions::validateIPFormat(const string& ipAddress) {
    // Basic IPv4 format validation using regex
    regex ipv4Pattern("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$");
    if (!regex_match(ipAddress, ipv4Pattern)) {
        return false;
    }

    // Validate each octet
    stringstream ss(ipAddress);
    string octet;
    while (getline(ss, octet, '.')) {
        int value = stoi(octet);
        if (value < 0 || value > 255) {
            return false;
        }
    }
    return true;
}

bool SecurityFunctions::isIPExpired(const string& ipAddress) {
    auto it = whitelistExpiry.find(ipAddress);
    if (it == whitelistExpiry.end()) {
        return true;
    }
    return chrono::system_clock::now() > it->second;
}

void SecurityFunctions::cleanupExpiredWhitelists() {
    auto now = chrono::system_clock::now();
    vector<string> expiredIPs;

    for (const auto& entry : whitelistExpiry) {
        if (now > entry.second) {
            expiredIPs.push_back(entry.first);
        }
    }

    for (const auto& ip : expiredIPs) {
        whitelistedIPs.erase(ip);
        whitelistReasons.erase(ip);
        whitelistApprovers.erase(ip);
        whitelistExpiry.erase(ip);
        logAuditEvent("whitelist_expired", "", "IP removed: " + ip);
    }
}

void SecurityFunctions::logWhitelistChange(const string& ipAddress, 
                                         const string& action, 
                                         const string& username) {
    string details = "IP: " + ipAddress + ", Action: " + action;
    logAuditEvent("whitelist_change", username, details);
}

// Public whitelist methods
bool SecurityFunctions::whitelistIP(const string& ipAddress,
                                  const string& username,
                                  const string& reason,
                                  int expiryDays) {
    try {
        // Step 1: Validate permissions
        if (!hasRole(username, "Admin") && !hasRole(username, "IT")) {
            logSecurityEvent("unauthorized_whitelist_attempt", username);
            return false;
        }

        // Step 2: Validate IP format
        if (!validateIPFormat(ipAddress)) {
            logSecurityEvent("invalid_ip_format", username, "IP: " + ipAddress);
            return false;
        }

        // Step 3: Check if IP is blacklisted
        if (isIPBlacklisted(ipAddress)) {
            logSecurityEvent("whitelist_blocked", username, 
                           "Attempted to whitelist blacklisted IP: " + ipAddress);
            return false;
        }

        // Step 4: Add to whitelist
        whitelistedIPs.insert(ipAddress);
        whitelistReasons[ipAddress] = reason;
        whitelistApprovers[ipAddress] = username;
        
        // Set expiry time
        auto expiry = chrono::system_clock::now() + 
                     chrono::hours(24 * expiryDays);
        whitelistExpiry[ipAddress] = expiry;

        // Step 5: Log the action
        logWhitelistChange(ipAddress, "added", username);
        
        return true;

    } catch (const exception& e) {
        logSecurityEvent("whitelist_error", username, e.what());
        return false;
    }
}

bool SecurityFunctions::removeFromWhitelist(const string& ipAddress,
                                          const string& username) {
    try {
        // Verify permissions
        if (!hasRole(username, "Admin") && !hasRole(username, "IT")) {
            logSecurityEvent("unauthorized_whitelist_removal", username);
            return false;
        }

        // Remove from all whitelist containers
        whitelistedIPs.erase(ipAddress);
        whitelistReasons.erase(ipAddress);
        whitelistApprovers.erase(ipAddress);
        whitelistExpiry.erase(ipAddress);

        logWhitelistChange(ipAddress, "removed", username);
        return true;

    } catch (const exception& e) {
        logSecurityEvent("whitelist_removal_error", username, e.what());
        return false;
    }
}

bool SecurityFunctions::isIPWhitelisted(const string& ipAddress) {
    cleanupExpiredWhitelists();
    return whitelistedIPs.find(ipAddress) != whitelistedIPs.end() && 
           !isIPExpired(ipAddress);
}

vector<pair<string, string>> SecurityFunctions::getWhitelistedIPs() {
    cleanupExpiredWhitelists();
    vector<pair<string, string>> result;
    for (const auto& ip : whitelistedIPs) {
        result.emplace_back(ip, whitelistReasons[ip]);
    }
    return result;
}

bool SecurityFunctions::updateWhitelistExpiry(const string& ipAddress,
                                            const string& username,
                                            int newExpiryDays) {
    try {
        if (!hasRole(username, "Admin") && !hasRole(username, "IT")) {
            logSecurityEvent("unauthorized_whitelist_update", username);
            return false;
        }

        if (whitelistedIPs.find(ipAddress) == whitelistedIPs.end()) {
            return false;
        }

        auto newExpiry = chrono::system_clock::now() + 
                        chrono::hours(24 * newExpiryDays);
        whitelistExpiry[ipAddress] = newExpiry;

        logWhitelistChange(ipAddress, "expiry_updated", username);
        return true;

    } catch (const exception& e) {
        logSecurityEvent("whitelist_update_error", username, e.what());
        return false;
    }
}

bool SecurityFunctions::bulkWhitelistIPs(const vector<string>& ipAddresses,
                                       const string& username,
                                       const string& reason) {
    try {
        if (!hasRole(username, "Admin")) {
            logSecurityEvent("unauthorized_bulk_whitelist", username);
            return false;
        }

        bool allSuccess = true;
        for (const auto& ip : ipAddresses) {
            if (!whitelistIP(ip, username, reason)) {
                allSuccess = false;
            }
        }

        if (allSuccess) {
            logAuditEvent("bulk_whitelist_complete", username, 
                         "Added " + to_string(ipAddresses.size()) + " IPs");
        }

        return allSuccess;

    } catch (const exception& e) {
        logSecurityEvent("bulk_whitelist_error", username, e.what());
        return false;
    }
}

void SecurityFunctions::exportWhitelist(const string& filePath) {
    try {
        ofstream file(filePath);
        for (const auto& ip : whitelistedIPs) {
            file << ip << ","
                 << whitelistReasons[ip] << ","
                 << whitelistApprovers[ip] << ","
                 << chrono::system_clock::to_time_t(whitelistExpiry[ip])
                 << endl;
        }
        logAuditEvent("whitelist_exported", "", "Path: " + filePath);
    } catch (const exception& e) {
        logSecurityEvent("whitelist_export_error", "", e.what());
    }
}

bool SecurityFunctions::importWhitelist(const string& filePath, 
                                      const string& username) {
    try {
        if (!hasRole(username, "Admin")) {
            logSecurityEvent("unauthorized_whitelist_import", username);
            return false;
        }

        ifstream file(filePath);
        string line;
        while (getline(file, line)) {
            stringstream ss(line);
            string ip, reason, approver, expiry_str;
            
            getline(ss, ip, ',');
            getline(ss, reason, ',');
            getline(ss, approver, ',');
            getline(ss, expiry_str, ',');

            time_t expiry_time = stoll(expiry_str);
            auto expiry = chrono::system_clock::from_time_t(expiry_time);
            
            whitelistedIPs.insert(ip);
            whitelistReasons[ip] = reason;
            whitelistApprovers[ip] = approver;
            whitelistExpiry[ip] = expiry;
        }

        logAuditEvent("whitelist_imported", username, "Path: " + filePath);
        return true;

    } catch (const exception& e) {
        logSecurityEvent("whitelist_import_error", username, e.what());
        return false;
    }
}

// Update the existing detectIntrusion method to check whitelist first
bool SecurityFunctions::detectIntrusion(const string& ipAddress, 
                                      const string& username,
                                      const string& actionType) {
    try {
        // First check if IP is whitelisted
        if (isIPWhitelisted(ipAddress)) {
            logAuditEvent("whitelist_access", username, 
                         "Whitelisted IP: " + ipAddress);
            return false;  // Not an intrusion if whitelisted
        }

        // Continue with existing intrusion detection logic...
        if (isIPBlacklisted(ipAddress)) {
            logSecurityEvent("blocked_blacklisted_ip", username,
                           "Blocked attempt from blacklisted IP: " + ipAddress);
            return true;
        }
        // ... rest of the existing detectIntrusion implementation ...

    } catch (const exception& e) {
        logSecurityEvent("intrusion_detection_error", username, e.what());
        return false;
    }
}
