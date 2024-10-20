// Step 1: Install dependencies
// You'll need a C++ compiler (like g++), CMake, and Boost libraries
// On Ubuntu or Debian:
// sudo apt-get update
// sudo apt-get install g++ cmake libboost-all-dev

// Step 2: Install Crow
// Crow is header-only, so you can just download the header file:
// wget https://github.com/CrowCpp/Crow/releases/download/v1.0%2B5/crow_all.h

// Step 3: Create a new C++ file, e.g., main.cpp
#include "crow_all.h"

int main()
{
    crow::SimpleApp app;

    CROW_ROUTE(app, "/")([](){
        return "Hello, World!";
    });

    CROW_ROUTE(app, "/json")([](){
        crow::json::wvalue x;
        x["message"] = "Hello, World!";
        return x;
    });

    app.port(18080).multithreaded().run();
    return 0;
}

// Step 4: Compile the code
// g++ -std=c++14 main.cpp -o crow_app -lboost_system -lpthread

// Step 5: Run the server
// ./crow_app

// Now your server should be running on http://localhost:18080

