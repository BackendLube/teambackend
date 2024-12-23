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
        // Validate input parameters
        if (event.empty() || username.empty()) {
            cerr << "Error: Event and username are required for audit logging." << endl;
            return false;
        }

        // Format the log message
        string logMessage = formatLogMessage(event, username, details);

        // Add IP address if provided
        if (!ipAddress.empty()) {
            logMessage += " IP: " + ipAddress;
        }

        // Log to system
        system.logAuditEvent(event, logMessage);

        // Handle high-risk events
        if (isHighRiskEvent(event)) {
            system.monitorSuspiciousActivity(username);
            if (!ipAddress.empty()) {
                system.detectIntrusion(ipAddress);
            }
        }

        // Encrypt sensitive log data if necessary
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
    return "User"; // Replace with actual implementation
}

bool SecurityFunctions::hasRole(const string& username, const string& role) {
    return getCurrentRole(username) == role;
}

// intrusion detection
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
    return "normal"; // Replace with actual pattern analysis
}

bool SecurityFunctions::isKnownMaliciousPattern(const string& pattern) {
    // This will check for known malicious patterns
    return false; // Replace with actual pattern checking
}

// intrusion detection methods
bool SecurityFunctions::detectIntrusion(const string& ipAddress, 
                                     const string& username,
                                     const string& actionType) {
    try {
        // Check if IP is already blacklisted
        if (isIPBlacklisted(ipAddress)) {
            logSecurityEvent("blocked_blacklisted_ip", username,
                           "Blocked attempt from blacklisted IP: " + ipAddress);
            return true;
        }

        // Update and check login attempts
        updateLoginAttempts(ipAddress);
        auto& attempts = loginAttempts[ipAddress];
        
        if (attempts.size() >= MAX_LOGIN_ATTEMPTS) {
            blacklistIP(ipAddress, "Exceeded maximum login attempts");
            logSecurityEvent("ip_blacklisted", username,
                           "IP blacklisted for excessive attempts: " + ipAddress);
            return true;
        }

        // Analyze IP pattern
        string pattern = analyzeIPPattern(ipAddress);
        if (isKnownMaliciousPattern(pattern)) {
            blacklistIP(ipAddress, "Matched malicious pattern: " + pattern);
            logSecurityEvent("malicious_pattern_detected", username,
                           "Malicious pattern from IP: " + ipAddress);
            return true;
        }

        // Check for suspicious activity patterns
        if (isIPSuspicious(ipAddress)) {
            logSecurityEvent("suspicious_activity", username,
                           "Suspicious activity detected from IP: " + ipAddress);
            system.monitorSuspiciousActivity(username);
            return true;
        }

        // Log the activity
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

// Methods for backup
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
        system.encryptSensitiveData("backup", backupPath);
        logAuditEvent("backup_encrypted", "", "Backup encrypted: " + backupPath);
    } catch (const exception& e) {
        throw runtime_error("Backup encryption failed: " + string(e.what()));
    }
}

bool SecurityFunctions::compressBackupData(const string& sourcePath, const string& destPath) {
    try {
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
        // Calculate file checksum
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

// backup methods
bool SecurityFunctions::performSecureBackup(const string& username, 
                                          const string& backupType,
                                          const string& customPath) {
    try {
        // Verify permissions
        if (!verifyBackupPermissions(username)) {
            logSecurityEvent("unauthorized_backup_attempt", username);
            return false;
        }

        // Generate backup ID and paths
        string backupId = generateBackupId();
        string backupPath = customPath.empty() ? 
            BACKUP_BASE_PATH + backupId : customPath + backupId;

        // Create backup directory
        fs::create_directories(backupPath);

        // Perform the backup based on type
        if (backupType == "incremental" && !performIncrementalBackup(username)) {
            throw runtime_error("Incremental backup failed");
        }

        // Compress the backup
        if (!compressBackupData(backupPath, backupPath + ".zip")) {
            throw runtime_error("Backup compression failed");
        }

        // Calculate checksum
        string checksum = calculateChecksum(backupPath + ".zip");

        // Encrypt the backup
        string encryptionKey = generateBackupId(); // Use proper key generation in practice
        encryptBackup(backupPath + ".zip", encryptionKey);

        // Store backup metadata
        BackupMetadata metadata {
            backupId,
            chrono::system_clock::now(),
            backupType,
            "completed",
            fs::file_size(backupPath + ".zip"),
            encryptionKey
        };
        backupHistory[backupId] = metadata;

        // Log the backup
        logAuditEvent("backup_completed", username,
                     "Backup ID: " + backupId + ", Type: " + backupType);

        // Cleanup old backups
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
        Verify permissions
        if (!verifyBackupPermissions(username)) {
            logSecurityEvent("unauthorized_restore_attempt", username);
            return false;
        }

        // Verify backup exists
        if (backupHistory.find(backupId) == backupHistory.end()) {
            throw runtime_error("Backup not found: " + backupId);
        }

        // Verify backup integrity
        string backupPath = BACKUP_BASE_PATH + backupId + ".zip";
        if (!validateBackupIntegrity(backupPath, "stored_checksum")) {
            throw runtime_error("Backup integrity check failed");
        }

        // Decrypt the backup
        const auto& metadata = backupHistory[backupId];
        system.encryptSensitiveData("restore", backupPath); // Decrypt operation

        // Perform the restore
        fs::create_directories(targetPath);
        // Implementation would restore files here

        // Log the restore
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


// methods for whitelist
bool SecurityFunctions::validateIPFormat(const string& ipAddress) {
    // format for validation using regex
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
        if (!hasRole(username, "Admin") && !hasRole(username, "IT")) {
            logSecurityEvent("unauthorized_whitelist_attempt", username);
            return false;
        }

        // Validate IP format
        if (!validateIPFormat(ipAddress)) {
            logSecurityEvent("invalid_ip_format", username, "IP: " + ipAddress);
            return false;
        }

        // Check if IP is blacklisted
        if (isIPBlacklisted(ipAddress)) {
            logSecurityEvent("whitelist_blocked", username, 
                           "Attempted to whitelist blacklisted IP: " + ipAddress);
            return false;
        }

        // Add to whitelist
        whitelistedIPs.insert(ipAddress);
        whitelistReasons[ipAddress] = reason;
        whitelistApprovers[ipAddress] = username;
        
        // Set expiry time
        auto expiry = chrono::system_clock::now() + 
                     chrono::hours(24 * expiryDays);
        whitelistExpiry[ipAddress] = expiry;

        // Log the action
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

// Private helper methods for session management
string SecurityFunctions::generateSessionId() {
    const string chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, chars.length() - 1);
    
    string sessionId;
    for (int i = 0; i < SESSION_ID_LENGTH; ++i) {
        sessionId += chars[dis(gen)];
    }
    return sessionId;
}

void SecurityFunctions::cleanupExpiredSessions() {
    auto now = chrono::system_clock::now();
    vector<string> expiredSessions;
    
    for (const auto& [sessionId, session] : activeSessions) {
        if (now > session.expiryTime) {
            expiredSessions.push_back(sessionId);
        }
    }

    for (const auto& sessionId : expiredSessions) {
        logAuditEvent("session_expired", activeSessions[sessionId].username);
        activeSessions.erase(sessionId);
    }
}

bool SecurityFunctions::isValidSession(const string& sessionId) {
    auto it = activeSessions.find(sessionId);
    if (it == activeSessions.end()) {
        return false;
    }

    auto now = chrono::system_clock::now();
    return now <= it->second.expiryTime && it->second.isActive;
}

void SecurityFunctions::updateSessionActivity(const string& sessionId) {
    auto it = activeSessions.find(sessionId);
    if (it != activeSessions.end()) {
        auto now = chrono::system_clock::now();
        it->second.lastActivity = now;
    }
}

void SecurityFunctions::terminateOldestSession(const string& username) {
    string oldestSessionId;
    chrono::system_clock::time_point oldestActivity;
    bool found = false;

    for (const auto& [sessionId, session] : activeSessions) {
        if (session.username == username) {
            if (!found || session.lastActivity < oldestActivity) {
                oldestSessionId = sessionId;
                oldestActivity = session.lastActivity;
                found = true;
            }
        }
    }

    if (found) {
        endSession(oldestSessionId);
    }
}

// Public session management methods
SecurityFunctions::SessionResult 
SecurityFunctions::createSession(const string& username,
                               const string& ipAddress,
                               int timeoutMinutes) {
    SessionResult result;
    try {
        cleanupExpiredSessions();

        // Check concurrent sessions
        int userSessions = 0;
        for (const auto& [sessionId, session] : activeSessions) {
            if (session.username == username) {
                userSessions++;
            }
        }

        if (userSessions >= MAX_CONCURRENT_SESSIONS) {
            terminateOldestSession(username);
        }

        // Create new session
        string sessionId = generateSessionId();
        auto now = chrono::system_clock::now();

        SessionInfo newSession {
            sessionId,
            username,
            now,  
            now + chrono::minutes(timeoutMinutes),  
            ipAddress,
            true,  
            {}     
        };

        activeSessions[sessionId] = newSession;
        
        logAuditEvent("session_created", username, 
                     "IP: " + ipAddress + ", Timeout: " + to_string(timeoutMinutes));

        result.success = true;
        result.sessionId = sessionId;
        result.message = "Session created successfully";

    } catch (const exception& e) {
        result.success = false;
        result.message = "Failed to create session: " + string(e.what());
        logSecurityEvent("session_creation_failed", username, e.what());
    }

    return result;
}

bool SecurityFunctions::validateSession(const string& sessionId) {
    try {
        cleanupExpiredSessions();

        if (!isValidSession(sessionId)) {
            return false;
        }

        updateSessionActivity(sessionId);
        return true;

    } catch (const exception& e) {
        logSecurityEvent("session_validation_error", "", e.what());
        return false;
    }
}

bool SecurityFunctions::endSession(const string& sessionId) {
    try {
        auto it = activeSessions.find(sessionId);
        if (it == activeSessions.end()) {
            return false;
        }

        string username = it->second.username;
        activeSessions.erase(it);
        
        logAuditEvent("session_ended", username);
        return true;

    } catch (const exception& e) {
        logSecurityEvent("session_end_error", "", e.what());
        return false;
    }
}

bool SecurityFunctions::extendSession(const string& sessionId, int additionalMinutes) {
    try {
        auto it = activeSessions.find(sessionId);
        if (!isValidSession(sessionId)) {
            return false;
        }

        auto& session = it->second;
        session.expiryTime += chrono::minutes(additionalMinutes);
        
        logAuditEvent("session_extended", session.username,
                     "Extended by " + to_string(additionalMinutes) + " minutes");
        return true;

    } catch (const exception& e) {
        logSecurityEvent("session_extension_error", "", e.what());
        return false;
    }
}

bool SecurityFunctions::checkSessionTimeout(const string& sessionId) {
    try {
        auto it = activeSessions.find(sessionId);
        if (it == activeSessions.end()) {
            return true;  // Session doesn't exist, consider it timed out
        }

        auto now = chrono::system_clock::now();
        auto& session = it->second;

        // Check if session has expired
        if (now > session.expiryTime) {
            logAuditEvent("session_timeout", session.username);
            activeSessions.erase(it);
            return true;
        }

        // Check if session has been inactive
        auto inactiveTime = chrono::duration_cast<chrono::minutes>(
            now - session.lastActivity).count();
            
        if (inactiveTime >= DEFAULT_SESSION_TIMEOUT) {
            logAuditEvent("session_inactive_timeout", session.username);
            activeSessions.erase(it);
            return true;
        }

        return false;

    } catch (const exception& e) {
        logSecurityEvent("session_timeout_check_error", "", e.what());
        return true;  // timed out on error
    }
}

bool SecurityFunctions::updateSessionData(const string& sessionId,
                                        const string& key,
                                        const string& value) {
    try {
        if (!isValidSession(sessionId)) {
            return false;
        }

        activeSessions[sessionId].sessionData[key] = value;
        updateSessionActivity(sessionId);
        return true;

    } catch (const exception& e) {
        logSecurityEvent("session_data_update_error", "", e.what());
        return false;
    }
}

string SecurityFunctions::getSessionData(const string& sessionId, const string& key) {
    try {
        if (!isValidSession(sessionId)) {
            return "";
        }

        auto& session = activeSessions[sessionId];
        auto it = session.sessionData.find(key);
        if (it == session.sessionData.end()) {
            return "";
        }

        updateSessionActivity(sessionId);
        return it->second;

    } catch (const exception& e) {
        logSecurityEvent("session_data_retrieval_error", "", e.what());
        return "";
    }
}

bool SecurityFunctions::forceLogout(const string& username) {
    try {
        vector<string> userSessions;
        for (const auto& [sessionId, session] : activeSessions) {
            if (session.username == username) {
                userSessions.push_back(sessionId);
            }
        }

        for (const auto& sessionId : userSessions) {
            endSession(sessionId);
        }

        logAuditEvent("force_logout", username);
        return true;

    } catch (const exception& e) {
        logSecurityEvent("force_logout_error", username, e.what());
        return false;
    }
}

vector<SecurityFunctions::SessionInfo> SecurityFunctions::getActiveSessions(const string& username) {
    vector<SessionInfo> sessions;
    cleanupExpiredSessions();

    for (const auto& [sessionId, session] : activeSessions) {
        if (session.username == username) {
            sessions.push_back(session);
        }
    }

    return sessions;
}

map<string, int> SecurityFunctions::getSessionStatistics() {
    map<string, int> stats;
    cleanupExpiredSessions();

    stats["total_active_sessions"] = activeSessions.size();
    
    map<string, int> userSessions;
    for (const auto& [sessionId, session] : activeSessions) {
        userSessions[session.username]++;
    }
    
    stats["unique_users"] = userSessions.size();
    stats["max_sessions_per_user"] = 0;
    
    for (const auto& [username, count] : userSessions) {
        stats["max_sessions_per_user"] = max(stats["max_sessions_per_user"], count);
    }

    return stats;
}

bool SecurityFunctions::isUserLoggedIn(const string& username) {
    cleanupExpiredSessions();
    
    for (const auto& [sessionId, session] : activeSessions) {
        if (session.username == username && session.isActive) {
            return true;
        }
    }
    
    return false;
}
