-- =============================================================
-- Cloud Security Monitor - MySQL Database Schema
-- =============================================================
-- This script creates the complete database schema for the
-- AI-Powered Cloud Security Monitoring & Risk Assessment Platform.
--
-- Usage:
--   mysql -u root -p < schema.sql
-- =============================================================

-- Create database
CREATE DATABASE IF NOT EXISTS cloud_security_db
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE cloud_security_db;

-- -----------------------------------------------------------
-- Users Table
-- Stores registered user accounts with hashed passwords
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    name            VARCHAR(100) NOT NULL,
    email           VARCHAR(120) NOT NULL UNIQUE,
    password        VARCHAR(256) NOT NULL,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_users_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------
-- Servers Table
-- Stores server information registered by users for monitoring
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS servers (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    server_name     VARCHAR(100) NOT NULL,
    ip_address      VARCHAR(45) NOT NULL,
    provider        VARCHAR(50) NOT NULL,
    user_id         INT NOT NULL,
    date_added      DATETIME DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_servers_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE,

    INDEX idx_servers_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------
-- Scan Sessions Table
-- Groups individual port scan results into logical sessions
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_sessions (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    server_id       INT NOT NULL,
    risk_score      INT DEFAULT 0,
    risk_level      VARCHAR(20) DEFAULT 'Low',
    scan_time       DATETIME DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_sessions_server
        FOREIGN KEY (server_id) REFERENCES servers(id)
        ON DELETE CASCADE,

    INDEX idx_sessions_server (server_id),
    INDEX idx_sessions_time (scan_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------
-- Scan Results Table
-- Stores individual port scan results per scan session
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_results (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    session_id      INT NOT NULL,
    server_id       INT NOT NULL,
    port            INT NOT NULL,
    status          VARCHAR(20) NOT NULL,       -- 'open' or 'closed'
    risk_level      VARCHAR(20) DEFAULT 'Low',  -- Low, Medium, High, Critical
    scan_time       DATETIME DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_results_session
        FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_results_server
        FOREIGN KEY (server_id) REFERENCES servers(id)
        ON DELETE CASCADE,

    INDEX idx_results_session (session_id),
    INDEX idx_results_server (server_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------
-- Recommendations Table
-- Stores auto-generated security recommendations per session
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS recommendations (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    session_id      INT NOT NULL,
    recommendation  TEXT NOT NULL,
    severity        VARCHAR(20) DEFAULT 'Info',
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_recommendations_session
        FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
        ON DELETE CASCADE,

    INDEX idx_recommendations_session (session_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
