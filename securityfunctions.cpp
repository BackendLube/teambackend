#include <iostream>
#include <fstream>
#include <ctime>
#include <string>

// Struct to store event data
struct AuditEvent {
    std::string event_type;
    std::string username;
    std::string details;
    std::string timestamp;
};

// Function to get current timestamp
std::string getCurrentTimestamp() {
    time_t now = time(0);
    tm* localtm = localtime(&now);
    char buffer[80];
    strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", localtm);
    return std::string(buffer);
}

// Function to log audit events
void logAuditEvent(const std::string& eventType, const std::string& username, const std::string& eventDetails) {
    // Create an AuditEvent object
    AuditEvent event;
    event.event_type = eventType;
    event.username = username;
    event.details = eventDetails;
    event.timestamp = getCurrentTimestamp();

    // Open the log file in append mode
    std::ofstream logFile("audit_log.txt", std::ios::app);
    if (logFile.is_open()) {
        // Write the event data to the file
        logFile << "[" << event.timestamp << "] "
                << "User: " << event.username << ", "
                << "Event: " << event.event_type << ", "
                << "Details: " << event.details << "\n";
        logFile.close();
    } else {
        std::cerr << "Unable to open log file.\n";
    }
}

int main() {
    // Example usage
    logAuditEvent("Login", "admin", "Successful login from IP 192.168.0.1");
    logAuditEvent("Password Change", "user1", "Password updated successfully.");
    
    return 0;
}

