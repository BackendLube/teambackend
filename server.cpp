#include "propertymanagementsystem.h"
#include <iostream>
#include <string>
#include <sstream>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define PORT 8080
#define BACKLOG 5

// Function to handle incoming requests
void handle_request(int client_socket) {
    static PropertyManagementSystem pms;  // Create a single instance
    char buffer[1024] = {0};
    std::string response;

    // Read the HTTP request from the client
    read(client_socket, buffer, sizeof(buffer) - 1);
    std::string request(buffer);

   if (strstr(buffer, "GET / HTTP/1.1")) {
    response = "HTTP/1.1 200 OK\r\n";
    response += "Content-Type: text/html\r\n";
    response += "Connection: close\r\n\r\n";
    response += "<!DOCTYPE html>\n"
        "<html>\n"
        "<head>\n"
        "    <title>Property Management System</title>\n"
        "    <style>\n"
        "        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: white; }\n"
        "        .nav { background-color: black; padding: 1rem; color: white; }\n"
        "        .nav button { background: none; border: none; color: white; padding: 0.5rem 1rem; margin-right: 1rem; cursor: pointer; }\n"
        "        .nav button:hover { background-color: grey; border-radius: 4px; }\n"
        "        .content { padding: 2rem; }\n"
        "        .card { background: white; border-radius: 8px; padding: 1rem; margin-bottom: 1rem; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }\n"
        "        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1rem; margin-top: 1rem; }\n"
        "        .login-container { max-width: 400px; margin: 100px auto; padding: 2rem; background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }\n"
        "        input, select { width: 100%; padding: 0.5rem; margin-bottom: 1rem; border: 1px solid #ddd; border-radius: 4px; }\n"
        "        button { background-color: blue; color: white; border: none; padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer; margin-bottom: 0.5rem; }\n"
        "        button:hover { background-color: darkblue; }\n"
        "        .error { color: red; margin-bottom: 1rem; }\n"
        "        .secondary-button { background-color: #666; width: 100%; }\n"
        "    </style>\n"
        "</head>\n"
        "<body>\n"
        "    <div id=\"app\"></div>\n"
        "    <script>\n"
        "        const data = {\n"
        "            properties: [\n"
        "                { id: 1, address: \"123 Main St\", description: \"Modern Apartment\", value: 1200000, performance: 85.5 },\n"
        "                { id: 2, address: \"456 Meridian Rd\", description: \"Commercial Space\", value: 2500000, performance: 92.0 },\n"
        "                { id: 3, address: \"789 Normal Ave\", description: \"Residential Home\", value: 450000, performance: 78.3 }\n"
        "            ],\n"
        "            tenants: [\n"
        "                { id: 1, name: \"Evan Lubinsky\", property_id: 1, lease_start: \"2024-01-01\", lease_end: \"2024-12-31\", rent: 1500 },\n"
        "                { id: 2, name: \"Aden Llewellyn\", property_id: 1, lease_start: \"2024-02-01\", lease_end: \"2024-12-31\", rent: 1600 },\n"
        "                { id: 3, name: \"Jake Dobson\", property_id: 2, lease_start: \"2024-01-15\", lease_end: \"2024-12-31\", rent: 2500 }\n"
        "            ],\n"
        "            maintenance: [\n"
        "                { id: 1, property_id: 1, description: \"Leaking faucet\", status: \"Open\", created_at: \"2024-03-15\" },\n"
        "                { id: 2, property_id: 2, description: \"HVAC repair\", status: \"In Progress\", created_at: \"2024-03-10\" },\n"
        "                { id: 3, property_id: 1, description: \"Broken window\", status: \"Resolved\", created_at: \"2024-03-01\" }\n"
        "            ],\n"
        "            users: [\n"
        "                { id: 1, username: \"backend\", password: \"backend123\", role: \"property_owner\" },\n"
        "                { id: 2, username: \"tenant1\", password: \"tenant123\", role: \"tenant\" },\n"
        "                { id: 3, username: \"admin\", password: \"admin123\", role: \"admin\" },\n"
        "                { id: 4, username: \"analyst\", password: \"analyst123\", role: \"investment_analyst\" }\n"
        "            ]\n"
        "        };\n"
        "\n"
        "        let currentUser = null;\n"
        "        let currentPage = 'dashboard';\n"
        "        let isSignup = false;\n"
        "\n"
"        function renderLogin() {\n"
"            return `\n"
"                <div class=\"login-container\">\n"
"                    <h2>Property Management Login</h2>\n"
"                    <div id=\"loginError\" class=\"error\"></div>\n"
"                    <form onsubmit=\"handleLogin(event)\">\n"
"                        <input type=\"text\" id=\"backend\" placeholder=\"Username\" required>\n"
"                        <input type=\"password\" id=\"backend123\" placeholder=\"Password\" required>\n"
"                        <button type=\"submit\">Login</button>\n"
"                    </form>\n"
"                    <button class=\"secondary-button\" onclick=\"showSignup()\">Sign Up</button>\n"
"                </div>\n"
"            `;\n"
"        }\n"
"\n"
"        function renderSignup() {\n"
"            return `\n"
"                <div class=\"login-container\">\n"
"                    <h2>Create Account</h2>\n"
"                    <div id=\"signupError\" class=\"error\"></div>\n"
"                    <form onsubmit=\"handleSignup(event)\">\n"
"                        <input type=\"text\" id=\"newUsername\" placeholder=\"Username\" required>\n"
"                        <input type=\"password\" id=\"newPassword\" placeholder=\"Password\" required>\n"
"                        <select id=\"userType\" required>\n"
"                            <option value=\"\">Select Role</option>\n"
"                            <option value=\"property_owner\">Property Owner</option>\n"
"                            <option value=\"admin\">Admin</option>\n"
"                            <option value=\"tenant\">Tenant</option>\n"
"                            <option value=\"investment_analyst\">Investment Analyst</option>\n"
"                        </select>\n"
"                        <button type=\"submit\">Create Account</button>\n"
"                    </form>\n"
"                    <button class=\"secondary-button\" onclick=\"showLogin()\">Back to Login</button>\n"
"                </div>\n"
"            `;\n"
"        }\n"
"\n"
"        function renderNavigation() {\n"
"            let buttons = '';\n"
"            \n"
"            switch(currentUser.role) {\n"
"                case 'property_owner':\n"
"                    buttons = `\n"
"                        <button onclick=\"changePage('dashboard')\">Dashboard</button>\n"
"                        <button onclick=\"changePage('properties')\">Properties</button>\n"
"                        <button onclick=\"changePage('tenants')\">Tenants</button>\n"
"                        <button onclick=\"changePage('maintenance')\">Maintenance</button>\n"
"                        <button onclick=\"changePage('investment')\">Investment Analysis</button>\n"
"                    `;\n"
"                    break;\n"
"                case 'tenant':\n"
"                    buttons = `<button onclick=\"changePage('tenant-portal')\">Tenant Portal</button>`;\n"
"                    break;\n"
"                case 'admin':\n"
"                    buttons = `<button onclick=\"changePage('user-management')\">User Management</button>`;\n"
"                    break;\n"
"                case 'investment_analyst':\n"
"                    buttons = `<button onclick=\"changePage('investment')\">Investment Analysis</button>`;\n"
"                    break;\n"
"            }\n"
"            \n"
"            return `\n"
"                <div class=\"nav\">\n"
"                    ${buttons}\n"
"                    <button onclick=\"handleLogout()\">Logout</button>\n"
"                </div>\n"
"            `;\n"
"        }\n"
"\n"
"        function renderTenantPortal() {\n"
"            return `\n"
"                <div class=\"content\">\n"
"                    <h2>Tenant Portal</h2>\n"
"                    <div class=\"grid\">\n"
"                        <div class=\"card\">\n"
"                            <h3>Monthly Payment</h3>\n"
"                            <p>Current Rent: $${data.tenants[0].rent}</p>\n"
"                            <p>Due Date: 1st of each month</p>\n"
"                            <button onclick=\"alert('Payment processing is not implemented in this demo')\">Make Payment</button>\n"
"                        </div>\n"
"                        <div class=\"card\">\n"
"                            <h3>Maintenance Request</h3>\n"
"                            <form onsubmit=\"event.preventDefault(); alert('Maintenance request submitted');\">\n"
"                                <textarea placeholder=\"Describe the issue...\" required style=\"width: 100%; margin-bottom: 1rem;\"></textarea>\n"
"                                <button type=\"submit\">Submit Request</button>\n"
"                            </form>\n"
"                        </div>\n"
"                    </div>\n"
"                </div>\n"
"            `;\n"
"        }\n"
"\n"
"        function renderUserManagement() {\n"
"            return `\n"
"                <div class=\"content\">\n"
"                    <h2>User Management</h2>\n"
"                    ${data.users.map(user => `\n"
"                        <div class=\"card\">\n"
"                            <h3>${user.username}</h3>\n"
"                            <p>Role: ${user.role}</p>\n"
"                            <button onclick=\"alert('Edit user functionality would go here')\">Edit</button>\n"
"                            <button onclick=\"alert('Delete user functionality would go here')\" style=\"background-color: #ff4444;\">Delete</button>\n"
"                        </div>\n"
"                    `).join('')}\n"
"                </div>\n"
"            `;\n"
"        }\n"
"\n"
"        function renderDashboard() {\n"
"            const totalProperties = data.properties.length;\n"
"            const totalRent = data.tenants.reduce((sum, tenant) => sum + tenant.rent, 0);\n"
"            \n"
"            return `\n"
"                <div class=\"content\">\n"
"                    <h2>Dashboard</h2>\n"
"                    <div class=\"grid\">\n"
"                        <div class=\"card\">\n"
"                            <h3>Properties</h3>\n"
"                            <p>${totalProperties}</p>\n"
"                        </div>\n"
"                        <div class=\"card\">\n"
"                            <h3>Monthly Income</h3>\n"
"                            <p>$${totalRent.toLocaleString()}</p>\n"
"                        </div>\n"
"                        <div class=\"card\">\n"
"                            <h3>Active Maintenance</h3>\n"
"                            <p>${data.maintenance.filter(m => m.status !== 'Resolved').length}</p>\n"
"                        </div>\n"
"                    </div>\n"
"                </div>\n"
"            `;\n"
"        }\n"
"\n"
"        function renderProperties() {\n"
"            return `\n"
"                <div class=\"content\">\n"
"                    <h2>Properties</h2>\n"
"                    <div class=\"grid\">\n"
"                        ${data.properties.map(property => `\n"
"                            <div class=\"card\">\n"
"                                <h3>${property.address}</h3>\n"
"                                <p>${property.description}</p>\n"
"                                <p>Value: $${property.value.toLocaleString()}</p>\n"
"                                <p>Performance: ${property.performance}%</p>\n"
"                            </div>\n"
"                        `).join('')}\n"
"                    </div>\n"
"                </div>\n"
"            `;\n"
"        }\n"
"\n"
"        function renderTenants() {\n"
"            return `\n"
"                <div class=\"content\">\n"
"                    <h2>Tenants</h2>\n"
"                    ${data.tenants.map(tenant => `\n"
"                        <div class=\"card\">\n"
"                            <h3>${tenant.name}</h3>\n"
"                            <p>Property ID: ${tenant.property_id}</p>\n"
"                            <p>Lease: ${tenant.lease_start} to ${tenant.lease_end}</p>\n"
"                            <p>Rent: $${tenant.rent}/month</p>\n"
"                        </div>\n"
"                    `).join('')}\n"
"                </div>\n"
"            `;\n"
"        }\n"
"\n"
"        function renderMaintenance() {\n"
"            return `\n"
"                <div class=\"content\">\n"
"                    <h2>Maintenance Requests</h2>\n"
"                    ${data.maintenance.map(request => `\n"
"                        <div class=\"card\">\n"
"                            <h3>Property ID: ${request.property_id}</h3>\n"
"                            <p>${request.description}</p>\n"
"                            <p>Status: ${request.status}</p>\n"
"                            <p>Created: ${request.created_at}</p>\n"
"                        </div>\n"
"                    `).join('')}\n"
"                </div>\n"
"            `;\n"
"        }\n"
"\n"
"        function renderInvestment() {\n"
"            const totalValue = data.properties.reduce((sum, property) => sum + property.value, 0);\n"
"            const monthlyRent = data.tenants.reduce((sum, tenant) => sum + tenant.rent, 0);\n"
"            const estimatedExpenses = monthlyRent * 0.4;\n"
"            const monthlyProfit = monthlyRent - estimatedExpenses;\n"
"            const annualProfit = monthlyProfit * 12;\n"
"\n"
"            return `\n"
"                <div class=\"content\">\n"
"                    <h2>Investment Analysis</h2>\n"
"                    <div class=\"grid\">\n"
"                        <div class=\"card\">\n"
"                            <h3>Net Worth</h3>\n"
"                            <p>$${totalValue.toLocaleString()}</p>\n"
"                            <p>Total Property Value</p>\n"
"                        </div>\n"
"                        <div class=\"card\">\n"
"                            <h3>Monthly Cash Flow</h3>\n"
"                            <p>Income: $${monthlyRent.toLocaleString()}</p>\n"
"                            <p>Expenses: $${estimatedExpenses.toLocaleString()}</p>\n"
"                            <p>Net: $${monthlyProfit.toLocaleString()}</p>\n"
"                        </div>\n"
"                        <div class=\"card\">\n"
"                            <h3>Annual Profit/Loss</h3>\n"
"                            <p>$${annualProfit.toLocaleString()}</p>\n"
"                            <p>Based on current monthly performance</p>\n"
"                        </div>\n"
"                    </div>\n"
"                </div>\n"
"            `;\n"
"        }\n"
"        function handleLogin(event) {\n"
"            event.preventDefault();\n"
"            const username = document.getElementById('backend').value;\n"
"            const password = document.getElementById('backend123').value;\n"
"            \n"
"            const user = data.users.find(u => u.username === username && u.password === password);\n"
"            if (user) {\n"
"                currentUser = user;\n"
"                currentPage = user.role === 'tenant' ? 'tenant-portal' : \n"
"                            user.role === 'admin' ? 'user-management' :\n"
"                            user.role === 'investment_analyst' ? 'investment' : 'dashboard';\n"
"                render();\n"
"            } else {\n"
"                document.getElementById('loginError').textContent = 'Invalid credentials';\n"
"            }\n"
"        }\n"
"\n"
"        function handleSignup(event) {\n"
"            event.preventDefault();\n"
"            const username = document.getElementById('newUsername').value;\n"
"            const password = document.getElementById('newPassword').value;\n"
"            const userType = document.getElementById('userType').value;\n"
"            \n"
"            alert(`Account created successfully as ${userType}!`);\n"
"            showLogin();\n"
"        }\n"
"\n"
"        function handleLogout() {\n"
"            currentUser = null;\n"
"            currentPage = 'dashboard';\n"
"            isSignup = false;\n"
"            render();\n"
"        }\n"
"\n"
"        function showSignup() {\n"
"            isSignup = true;\n"
"            render();\n"
"        }\n"
"\n"
"        function showLogin() {\n"
"            isSignup = false;\n"
"            render();\n"
"        }\n"
"\n"
"        function changePage(page) {\n"
"            currentPage = page;\n"
"            render();\n"
"        }\n"
"\n"
"        function render() {\n"
"            const app = document.getElementById('app');\n"
"            if (!currentUser) {\n"
"                app.innerHTML = isSignup ? renderSignup() : renderLogin();\n"
"                return;\n"
"            }\n"
"\n"
"            let content = '';\n"
"            switch (currentPage) {\n"
"                case 'dashboard':\n"
"                    content = renderDashboard();\n"
"                    break;\n"
"                case 'properties':\n"
"                    content = renderProperties();\n"
"                    break;\n"
"                case 'tenants':\n"
"                    content = renderTenants();\n"
"                    break;\n"
"                case 'maintenance':\n"
"                    content = renderMaintenance();\n"
"                    break;\n"
"                case 'investment':\n"
"                    content = renderInvestment();\n"
"                    break;\n"
"                case 'tenant-portal':\n"
"                    content = renderTenantPortal();\n"
"                    break;\n"
"                case 'user-management':\n"
"                    content = renderUserManagement();\n"
"                    break;\n"
"                default:\n"
"                    content = currentUser.role === 'tenant' ? renderTenantPortal() :\n"
"                             currentUser.role === 'admin' ? renderUserManagement() :\n"
"                             currentUser.role === 'investment_analyst' ? renderInvestment() :\n"
"                             renderDashboard();\n"
"            }\n"
"            \n"
"            app.innerHTML = renderNavigation() + content;\n"
"        }\n"
"\n"
"        render();\n"
"    </script>\n"
"</body>\n"
"</html>\n";

// Now close the if statement and continue with the rest of the handle_request function
}
    else if (strstr(buffer, "POST /login")) {
        // Extract username and password from POST data
        std::string postData = request.substr(request.find("\r\n\r\n") + 4);
        size_t userPos = postData.find("username=") + 9;
        size_t passPos = postData.find("password=") + 9;
        size_t userEnd = postData.find("&", userPos);
        std::string username = postData.substr(userPos, userEnd - userPos);
        std::string password = postData.substr(passPos);

        bool success = pms.userLogin(username, password);

        response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Type: text/html\r\n";
        response += "Connection: close\r\n\r\n";
        response += "<html><body>";
        response += success ? "<h1>Login Successful!</h1>" : "<h1>Login Failed!</h1>";
        response += "<a href='/'>Back to Home</a>";
        response += "</body></html>";
    }
    else if (strstr(buffer, "POST /maintenance")) {
        // Extract maintenance request data
        std::string postData = request.substr(request.find("\r\n\r\n") + 4);
        size_t idPos = postData.find("tenant_id=") + 10;
        size_t descPos = postData.find("description=") + 12;
        size_t idEnd = postData.find("&", idPos);
        int tenantId = std::stoi(postData.substr(idPos, idEnd - idPos));
        std::string description = postData.substr(descPos);

        pms.submitMaintenanceRequest(tenantId, description);

        response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Type: text/html\r\n";
        response += "Connection: close\r\n\r\n";
        response += "<html><body>";
        response += "<h1>Maintenance Request Submitted!</h1>";
        response += "<a href='/'>Back to Home</a>";
        response += "</body></html>";
    }
    else {
        response = "HTTP/1.1 404 Not Found\r\n";
        response += "Content-Type: text/html\r\n";
        response += "Connection: close\r\n\r\n";
        response += "<html><body><h1>404 Not Found</h1></body></html>";
    }

    send(client_socket, response.c_str(), response.size(), 0);
    close(client_socket);
}

int main() {
    int server_socket, client_socket;
    struct sockaddr_in server_addr;  // Add missing semicolon here
    socklen_t client_len;
    struct sockaddr_in client_addr;  // Add missing semicolon here

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        std::cerr << "Failed to create socket." << std::endl;
        return 1;
    }

    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::cerr << "Failed to set socket options." << std::endl;
        close(server_socket);
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (::bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Failed to bind to port." << std::endl;
        close(server_socket);
        return 1;
    }

    if (listen(server_socket, BACKLOG) < 0) {
        std::cerr << "Listen failed." << std::endl;
        close(server_socket);
        return 1;
    }

    std::cout << "Server running on port " << PORT << "..." << std::endl;

    client_len = sizeof(client_addr);
    while (true) {
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket < 0) {
            std::cerr << "Failed to accept connection." << std::endl;
            continue;
        }

        handle_request(client_socket);
    }

    close(server_socket);
    return 0;
}
