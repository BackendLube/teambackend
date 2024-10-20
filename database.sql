-- Users table
CREATE TABLE Users (
    user_id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    user_type ENUM('RealEstateOwner', 'PropertyManagerOwner', 'PropertyManagerEmployee', 'PropertyManagerAdmin', 'RealEstateAgent', 'Tenant', 'SoftwareDeveloper', 'LeasingAgent', 'Accountant', 'FinancialAdvisor', 'Lender', 'PortfolioAnalyst', 'ITSupport') NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    phone VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Properties table
CREATE TABLE Properties (
    property_id INT PRIMARY KEY AUTO_INCREMENT,
    owner_id INT,
    address VARCHAR(255) NOT NULL,
    description TEXT,
    property_type VARCHAR(50),
    value DECIMAL(15, 2),
    FOREIGN KEY (owner_id) REFERENCES Users(user_id)
);

-- Property Photos table
CREATE TABLE PropertyPhotos (
    photo_id INT PRIMARY KEY AUTO_INCREMENT,
    property_id INT,
    photo_url VARCHAR(255) NOT NULL,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (property_id) REFERENCES Properties(property_id)
);

-- Tenants table
CREATE TABLE Tenants (
    tenant_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    property_id INT,
    lease_start_date DATE,
    lease_end_date DATE,
    rent_amount DECIMAL(10, 2),
    FOREIGN KEY (user_id) REFERENCES Users(user_id),
    FOREIGN KEY (property_id) REFERENCES Properties(property_id)
);

-- Maintenance Requests table
CREATE TABLE MaintenanceRequests (
    request_id INT PRIMARY KEY AUTO_INCREMENT,
    property_id INT,
    tenant_id INT,
    description TEXT,
    status ENUM('Open', 'In Progress', 'Resolved') DEFAULT 'Open',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP,
    FOREIGN KEY (property_id) REFERENCES Properties(property_id),
    FOREIGN KEY (tenant_id) REFERENCES Tenants(tenant_id)
);

-- Vendors table
CREATE TABLE Vendors (
    vendor_id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    service_type VARCHAR(50),
    contact_email VARCHAR(100),
    contact_phone VARCHAR(20)
);

-- Property-Vendor Assignments table
CREATE TABLE PropertyVendorAssignments (
    assignment_id INT PRIMARY KEY AUTO_INCREMENT,
    property_id INT,
    vendor_id INT,
    start_date DATE,
    end_date DATE,
    FOREIGN KEY (property_id) REFERENCES Properties(property_id),
    FOREIGN KEY (vendor_id) REFERENCES Vendors(vendor_id)
);

-- Financial Transactions table
CREATE TABLE FinancialTransactions (
    transaction_id INT PRIMARY KEY AUTO_INCREMENT,
    property_id INT,
    transaction_type ENUM('Income', 'Expense') NOT NULL,
    amount DECIMAL(15, 2) NOT NULL,
    description TEXT,
    date DATE,
    FOREIGN KEY (property_id) REFERENCES Properties(property_id)
);

-- Property Performance Metrics table
CREATE TABLE PropertyPerformanceMetrics (
    metric_id INT PRIMARY KEY AUTO_INCREMENT,
    property_id INT,
    occupancy_rate DECIMAL(5, 2),
    monthly_income DECIMAL(15, 2),
    monthly_expenses DECIMAL(15, 2),
    net_operating_income DECIMAL(15, 2),
    cap_rate DECIMAL(5, 2),
    date DATE,
    FOREIGN KEY (property_id) REFERENCES Properties(property_id)
);

-- Communications table
CREATE TABLE Communications (
    communication_id INT PRIMARY KEY AUTO_INCREMENT,
    sender_id INT,
    receiver_id INT,
    message TEXT,
    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    read_at TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES Users(user_id),
    FOREIGN KEY (receiver_id) REFERENCES Users(user_id)
);

-- Investment Analysis table
CREATE TABLE InvestmentAnalysis (
    analysis_id INT PRIMARY KEY AUTO_INCREMENT,
    property_id INT,
    analyst_id INT,
    roi DECIMAL(5, 2),
    irr DECIMAL(5, 2),
    payback_period INT,
    analysis_date DATE,
    FOREIGN KEY (property_id) REFERENCES Properties(property_id),
    FOREIGN KEY (analyst_id) REFERENCES Users(user_id)
);

-- Risk Assessments table
CREATE TABLE RiskAssessments (
    assessment_id INT PRIMARY KEY AUTO_INCREMENT,
    property_id INT,
    assessor_id INT,
    risk_level ENUM('Low', 'Medium', 'High') NOT NULL,
    description TEXT,
    assessment_date DATE,
    FOREIGN KEY (property_id) REFERENCES Properties(property_id),
    FOREIGN KEY (assessor_id) REFERENCES Users(user_id)
);

-- Cash Flow Forecasts table
CREATE TABLE CashFlowForecasts (
    forecast_id INT PRIMARY KEY AUTO_INCREMENT,
    property_id INT,
    forecaster_id INT,
    forecast_period INT,  -- in months
    total_income DECIMAL(15, 2),
    total_expenses DECIMAL(15, 2),
    net_cash_flow DECIMAL(15, 2),
    forecast_date DATE,
    FOREIGN KEY (property_id) REFERENCES Properties(property_id),
    FOREIGN KEY (forecaster_id) REFERENCES Users(user_id)
);

