#include <iostream>
#include <fstream>
#include <ctime>
#include <string>

using namespace std;

// Struct to store event data
struct AuditEvent {
    string event_type;
    string username;
    string details;
    string timestamp;
};

// Function to get current timestamp
string getCurrentTimestamp() {
    time_t now = time(0);
    tm* localtm = localtime(&now);
    char buffer[80];
    strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", localtm);
    return string(buffer);
}

// Function to log audit events
void logAuditEvent(const string& eventType, const string& username, const string& eventDetails) {
    // Create an AuditEvent object
    AuditEvent event;
    event.event_type = eventType;
    event.username = username;
    event.details = eventDetails;
    event.timestamp = getCurrentTimestamp();

    // Open the log file in append mode
    ofstream logFile("audit_log.txt", ios::app);
    if (logFile.is_open()) {
        // Write the event data to the file
        logFile << "[" << event.timestamp << "] "
                << "User: " << event.username << ", "
                << "Event: " << event.event_type << ", "
                << "Details: " << event.details << "\n";
        logFile.close();
    } else {
        cerr << "Unable to open log file.\n";
    }
}
    return 0;
}

