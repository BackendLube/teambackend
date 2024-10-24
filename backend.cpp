#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <crow.h> // Lightweight C++ web framework
#include <crow/json.h>
#include <ctime>

// Structure definitions matching frontend needs
struct Property {
    int id;
    std::string description;
    std::vector<std::string> photos;
    double performance_metric;
    std::string address;
    double value;
};

struct Tenant {
    int id;
    std::string name;
    int property_id;
    std::string lease_start;
    std::string lease_end;
    double rent_amount;
};

struct MaintenanceRequest {
    int id;
    int property_id;
    std::string description;
    std::string status;
    std::string created_at;
};

struct DashboardMetrics {
    int total_properties;
    double occupancy_rate;
    double monthly_income;
};

// Mock database
class Database {
private:
    std::vector<Property> properties;
    std::vector<Tenant> tenants;
    std::vector<MaintenanceRequest> maintenance_requests;
    
public:
    Database() {
        // Initialize with mock data
        properties = {
            {1, "Modern Apartment Complex", {"photo1.jpg"}, 85.5, "123 Main St", 1200000},
            {2, "Commercial Building", {"photo2.jpg"}, 92.0, "456 Business Ave", 2500000},
            {3, "Residential House", {"photo3.jpg"}, 78.3, "789 Oak Rd", 450000}
        };
        
        tenants = {
            {1, "John Doe", 1, "2024-01-01", "2024-12-31", 1500},
            {2, "Jane Smith", 1, "2024-02-01", "2024-12-31", 1600},
            {3, "Bob Johnson", 2, "2024-01-15", "2024-12-31", 2500}
        };
        
        maintenance_requests = {
            {1, 1, "Leaking faucet in unit 101", "Open", "2024-03-15"},
            {2, 2, "HVAC maintenance needed", "In Progress", "2024-03-10"},
            {3, 1, "Broken window", "Resolved", "2024-03-01"}
        };
    }

    // Database access methods
    std::vector<Property>& get_properties() { return properties; }
    std::vector<Tenant>& get_tenants() { return tenants; }
    std::vector<MaintenanceRequest>& get_maintenance_requests() { return maintenance_requests; }
    
    DashboardMetrics get_dashboard_metrics() {
        double total_income = 0;
        for (const auto& tenant : tenants) {
            total_income += tenant.rent_amount;
        }
        
        return {
            static_cast<int>(properties.size()),
            85.5, // Mock occupancy rate
            total_income
        };
    }
};

int main() {
    // Initialize crow application
    crow::SimpleApp app;
    
    // Initialize database
    Database db;

    // CORS middleware
    struct CORSMiddleware {
        struct context {};
        
        void before_handle(crow::request& req, crow::response& res, context& ctx) {
            res.add_header("Access-Control-Allow-Origin", "*");
            res.add_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
            res.add_header("Access-Control-Allow-Headers", "Content-Type");
        }
        
        void after_handle(crow::request& req, crow::response& res, context& ctx) {
            // Nothing to do
        }
    };

    // Add CORS middleware to app
    app.use<CORSMiddleware>();

    // Authentication endpoint
    CROW_ROUTE(app, "/api/login")
        .methods("POST"_method)
        ([](const crow::request& req) {
            auto x = crow::json::load(req.body);
            if (!x) {
                return crow::response(400, "Invalid JSON");
            }
            
            std::string username = x["username"].s();
            std::string password = x["password"].s();
            
            // Check hardcoded credentials
            if (username == "backend" && password == "team101") {
                crow::json::wvalue response;
                response["success"] = true;
                response["token"] = "mock_token_123"; // In real app, generate JWT
                return crow::response(200, response);
            }
            
            return crow::response(401, "Invalid credentials");
        });

    // Dashboard metrics endpoint
    CROW_ROUTE(app, "/api/dashboard")
        .methods("GET"_method)
        ([&db](const crow::request& req) {
            auto metrics = db.get_dashboard_metrics();
            crow::json::wvalue response;
            response["totalProperties"] = metrics.total_properties;
            response["occupancyRate"] = metrics.occupancy_rate;
            response["monthlyIncome"] = metrics.monthly_income;
            return crow::response(200, response);
        });

    // Properties endpoint
    CROW_ROUTE(app, "/api/properties")
        .methods("GET"_method)
        ([&db](const crow::request& req) {
            auto& properties = db.get_properties();
            crow::json::wvalue response;
            std::vector<crow::json::wvalue> props;
            
            for (const auto& prop : properties) {
                crow::json::wvalue p;
                p["id"] = prop.id;
                p["description"] = prop.description;
                p["photos"] = prop.photos;
                p["performance_metric"] = prop.performance_metric;
                p["address"] = prop.address;
                p["value"] = prop.value;
                props.push_back(std::move(p));
            }
            
            response["properties"] = std::move(props);
            return crow::response(200, response);
        });

    // Tenants endpoint
    CROW_ROUTE(app, "/api/tenants")
        .methods("GET"_method)
        ([&db](const crow::request& req) {
            auto& tenants = db.get_tenants();
            crow::json::wvalue response;
            std::vector<crow::json::wvalue> t;
            
            for (const auto& tenant : tenants) {
                crow::json::wvalue ten;
                ten["id"] = tenant.id;
                ten["name"] = tenant.name;
                ten["property_id"] = tenant.property_id;
                ten["lease_start"] = tenant.lease_start;
                ten["lease_end"] = tenant.lease_end;
                ten["rent_amount"] = tenant.rent_amount;
                t.push_back(std::move(ten));
            }
            
            response["tenants"] = std::move(t);
            return crow::response(200, response);
        });

    // Maintenance requests endpoint
    CROW_ROUTE(app, "/api/maintenance")
        .methods("GET"_method)
        ([&db](const crow::request& req) {
            auto& requests = db.get_maintenance_requests();
            crow::json::wvalue response;
            std::vector<crow::json::wvalue> reqs;
            
            for (const auto& req : requests) {
                crow::json::wvalue r;
                r["id"] = req.id;
                r["property_id"] = req.property_id;
                r["description"] = req.description;
                r["status"] = req.status;
                r["created_at"] = req.created_at;
                reqs.push_back(std::move(r));
            }
            
            response["maintenance_requests"] = std::move(reqs);
            return crow::response(200, response);
        });

    // Start server
    app.port(3000).multithreaded().run();
    
    return 0;
}
