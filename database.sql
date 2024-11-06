-- Roles table to define user roles
CREATE TABLE roles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT
);

-- Permissions table to define permissions
CREATE TABLE permissions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT
);

-- Users table to store user information, including hashed passwords and related data
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,  -- Store hashed password
    role_id INT,
    is_locked BOOLEAN DEFAULT FALSE,      -- Whether the account is locked
    failed_login_attempts INT DEFAULT 0,  -- Count of failed login attempts
    last_failed_login DATETIME,          -- Time of last failed login attempt
    last_login DATETIME,                 -- Time of last successful login
    is_active BOOLEAN DEFAULT TRUE,      -- Whether the user is active
    FOREIGN KEY (role_id) REFERENCES roles(id)
);

-- User Permissions table to assign permissions to users
CREATE TABLE user_permissions (
    user_id INT,
    permission_id INT,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (permission_id) REFERENCES permissions(id),
    PRIMARY KEY (user_id, permission_id)
);

-- Audit Logs table to store audit events
CREATE TABLE audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    event_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    event_type VARCHAR(255),
    event_description TEXT,
    user_id INT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Two-Factor Authentication (2FA) table
CREATE TABLE two_factor_auth (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    secret_key VARCHAR(255),    -- Store secret key for 2FA
    is_enabled BOOLEAN DEFAULT FALSE,   -- Whether 2FA is enabled
    last_verified DATETIME,            -- Timestamp of the last successful 2FA verification
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Session Timeouts table to track session activity and timeouts
CREATE TABLE session_timeouts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    session_start DATETIME,
    session_end DATETIME,
    session_duration INT,   -- Session duration in seconds
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Table for failed login attempts (for brute force detection)
CREATE TABLE failed_logins (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255),
    attempt_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(255),
    status VARCHAR(50)      -- Failed, blocked, etc.
);

-- Table for whitelisted IP addresses for additional security
CREATE TABLE whitelisted_ips (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(255) NOT NULL UNIQUE,
    added_on DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- File Uploads table to log file uploads and their validation status
CREATE TABLE file_uploads (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    file_name VARCHAR(255),
    upload_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50),   -- Pending, validated, rejected, etc.
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Properties table to store property details
CREATE TABLE properties (
    id INT AUTO_INCREMENT PRIMARY KEY,
    address VARCHAR(255),
    description TEXT,
    value DECIMAL(15, 2),
    performance DECIMAL(5, 2),
    owner_id INT,
    FOREIGN KEY (owner_id) REFERENCES users(id)
);

-- Property Photos table to store photos for each property
CREATE TABLE property_photos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    property_id INT,
    photo_url VARCHAR(255),
    photo_description TEXT,
    FOREIGN KEY (property_id) REFERENCES properties(id)
);

-- Property Documents table for storing documents related to properties
CREATE TABLE property_documents (
    id INT AUTO_INCREMENT PRIMARY KEY,
    property_id INT,
    document_type VARCHAR(255),
    document_url VARCHAR(255),
    FOREIGN KEY (property_id) REFERENCES properties(id)
);

-- Property Financials table to track financial performance of each property
CREATE TABLE property_financials (
    id INT AUTO_INCREMENT PRIMARY KEY,
    property_id INT,
    rent_income DECIMAL(15, 2),
    operating_expenses DECIMAL(15, 2),
    capital_expenses DECIMAL(15, 2),
    mortgage_balance DECIMAL(15, 2),
    FOREIGN KEY (property_id) REFERENCES properties(id)
);

-- Table for managing tenant information
CREATE TABLE tenants (
    id INT AUTO_INCREMENT PRIMARY KEY,
    property_id INT,
    name VARCHAR(255),
    contact_info VARCHAR(255),
    lease_start DATE,
    lease_end DATE,
    rent_amount DECIMAL(15, 2),
    FOREIGN KEY (property_id) REFERENCES properties(id)
);

-- Backups table to track database backups (for backup feature)
CREATE TABLE backups (
    id INT AUTO_INCREMENT PRIMARY KEY,
    backup_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    backup_status VARCHAR(50), -- Successful, failed, pending, etc.
    initiated_by INT,
    FOREIGN KEY (initiated_by) REFERENCES users(id)
);

-- Password Resets table to manage password reset requests
CREATE TABLE password_resets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    reset_token VARCHAR(255) NOT NULL,
    expiration_time DATETIME NOT NULL,  -- Token expiration time
    is_used BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Table to track changes made to user accounts (for security purposes)
CREATE TABLE user_account_changes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    change_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    change_description TEXT,
    changed_by INT,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (changed_by) REFERENCES users(id)
);

