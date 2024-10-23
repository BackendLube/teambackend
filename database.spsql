-- Users table: Stores user information for the system, covering all roles like Real Estate Owners, Property Managers, Tenants, etc.
CREATE TABLE Users (
    user_id INT PRIMARY KEY AUTO_INCREMENT, 
    username VARCHAR(50) UNIQUE NOT NULL, 
    password_hash VARCHAR(255) NOT NULL, 
    user_type ENUM(
        'RealEstateOwner', 'PropertyManagerOwner', 'PropertyManagerEmployee', 'PropertyManagerAdmin', 'RealEstateAgent', 'Tenant', 'SoftwareDeveloper', 'LeasingAgent', 'Accountant', 'FinancialAdvisor', 'Lender', 'PortfolioAnalyst', 'ITSupport'
        ) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL, 
    phone VARCHAR(20), 
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP -- Timestamp when the user account was created
);

-- Properties table: Stores details about properties such as address, type, and ownership.
CREATE TABLE Properties (
    property_id INT PRIMARY KEY AUTO_INCREMENT, 
    owner_id INT, 
    address VARCHAR(255) NOT NULL, 
    description TEXT, 
    property_type VARCHAR(50), 
    value DECIMAL(15, 2), 
    FOREIGN KEY (owner_id) REFERENCES Users(user_id) -- Links the owner of the property to the Users table
);

-- Property Photos table: Contains the URLs of photos associated with each property.
CREATE TABLE PropertyPhotos (
    photo_id INT PRIMARY KEY AUTO_INCREMENT, 
    property_id INT, 
    photo_url VARCHAR(255) NOT NULL, 
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
    FOREIGN KEY (property_id) REFERENCES Properties(property_id) -- Links the photo to the corresponding property
);

-- Tenants table: Stores tenant details and their lease agreements for properties.
CREATE TABLE Tenants (
    tenant_id INT PRIMARY KEY AUTO_INCREMENT, 
    user_id INT, 
    property_id INT, 
    lease_start_date DATE, 
    lease_end_date DATE, 
    rent_amount DECIMAL(10, 2), 
    FOREIGN KEY (user_id) REFERENCES Users(user_id), -- Links the tenant to the Users table
    FOREIGN KEY (property_id) REFERENCES Properties(property_id) -- Links the lease to the specific property
);

-- Maintenance Requests table: Tracks requests for property maintenance reported by tenants.
CREATE TABLE MaintenanceRequests (
    request_id INT PRIMARY KEY AUTO_INCREMENT, 
    property_id INT, 
    tenant_id INT, 
    description TEXT, 
    status ENUM('Open', 'In Progress', 'Resolved') DEFAULT 'Open', 
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
    resolved_at TIMESTAMP, 
    FOREIGN KEY (property_id) REFERENCES Properties(property_id), -- Links the request to the corresponding property
    FOREIGN KEY (tenant_id) REFERENCES Tenants(tenant_id) -- Links the request to the tenant who made it
);

-- Vendors table: Stores information about service vendors who provide maintenance and repairs.
CREATE TABLE Vendors (
    vendor_id INT PRIMARY KEY AUTO_INCREMENT, 
    name VARCHAR(100) NOT NULL, 
    service_type VARCHAR(50), 
    contact_email VARCHAR(100), 
    contact_phone VARCHAR(20) 
);

-- Property-Vendor Assignments table: Assigns vendors to properties for services and maintenance.
CREATE TABLE PropertyVendorAssignments (
    assignment_id INT PRIMARY KEY AUTO_INCREMENT, 
    property_id INT, 
    vendor_id INT, 
    start_date DATE, 
    end_date DATE, 
    FOREIGN KEY (property_id) REFERENCES Properties(property_id), -- Links the assignment to a specific property
    FOREIGN KEY (vendor_id) REFERENCES Vendors(vendor_id) -- Links the assignment to a specific vendor
);

-- Financial Transactions table: Tracks all financial transactions for properties.
CREATE TABLE FinancialTransactions (
    transaction_id INT PRIMARY KEY AUTO_INCREMENT, 
    property_id INT, 
    transaction_type ENUM('Income', 'Expense') NOT NULL, 
    amount DECIMAL(15, 2) NOT NULL, 
    description TEXT, 
    date DATE, 
    FOREIGN KEY (property_id) REFERENCES Properties(property_id) -- Links the transaction to the corresponding property
);

-- Property Performance Metrics table: Stores performance metrics like income, expenses, and occupancy rate for properties.
CREATE TABLE PropertyPerformanceMetrics (
    metric_id INT PRIMARY KEY AUTO_INCREMENT, 
    property_id INT, 
    occupancy_rate DECIMAL(5, 2), 
    monthly_income DECIMAL(15, 2), 
    monthly_expenses DECIMAL(15, 2), 
    net_operating_income DECIMAL(15, 2), 
    cap_rate DECIMAL(5, 2), 
    date DATE, 
    FOREIGN KEY (property_id) REFERENCES Properties(property_id) -- Links the metrics to the corresponding property
);

-- Communications table: Tracks messages exchanged between users of the system.
CREATE TABLE Communications (
    communication_id INT PRIMARY KEY AUTO_INCREMENT, 
    sender_id INT, 
    receiver_id INT, 
    message TEXT, 
    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
    read_at TIMESTAMP, 
    FOREIGN KEY (sender_id) REFERENCES Users(user_id), -- Links the message to the sender's user account
    FOREIGN KEY (receiver_id) REFERENCES Users(user_id) -- Links the message to the receiver's user account
);

-- Investment Analysis table: Stores analyses related to the return on investment (ROI) and other financial metrics for properties.
CREATE TABLE InvestmentAnalysis (
    analysis_id INT PRIMARY KEY AUTO_INCREMENT, 
    property_id INT, 
    analyst_id INT, 
    roi DECIMAL(5, 2), 
    irr DECIMAL(5, 2), 
    payback_period INT, 
    analysis_date DATE, 
    FOREIGN KEY (property_id) REFERENCES Properties(property_id), -- Links the analysis to the corresponding property
    FOREIGN KEY (analyst_id) REFERENCES Users(user_id) -- Links the analysis to the performing analyst
);

-- Risk Assessments table: Stores risk assessments for properties, analyzing risk levels and descriptions.
CREATE TABLE RiskAssessments (
    assessment_id INT PRIMARY KEY AUTO_INCREMENT, 
    property_id INT, 
    assessor_id INT, 
    risk_level ENUM('Low', 'Medium', 'High') NOT NULL, 
    description TEXT, 
    assessment_date DATE, 
    FOREIGN KEY (property_id) REFERENCES Properties(property_id), -- Links the assessment to the corresponding property
    FOREIGN KEY (assessor_id) REFERENCES Users(user_id) -- Links the assessment to the performing assessor
);

-- Cash Flow Forecasts table: Stores forecasts of cash flow for properties over a specified period.
CREATE TABLE CashFlowForecasts (
    forecast_id INT PRIMARY KEY AUTO_INCREMENT, 
    property_id INT, 
    forecaster_id INT, 


