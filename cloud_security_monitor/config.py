"""
Configuration Module for Cloud Security Monitor
-------------------------------------------------
Provides Flask application configuration including:
- Database connection settings (MySQL primary, SQLite fallback)
- Secret key for session management
- Google Cloud deployment settings
"""

import os

# Base directory of the application
BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    """Base configuration class."""

    # Secret key for session management and CSRF protection
    SECRET_KEY = os.environ.get('SECRET_KEY', 'cloud-security-monitor-secret-key-change-in-production')

    # Database Configuration
    # Use MySQL if DATABASE_URL is set, otherwise fall back to SQLite for local dev
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        f'sqlite:///{os.path.join(BASE_DIR, "database", "app.db")}'
    )

    # Example MySQL URI: mysql+pymysql://user:password@localhost/cloud_security_db
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Session configuration
    SESSION_TYPE = 'filesystem'
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour

    # Scanner configuration
    SCAN_TIMEOUT = 2  # Timeout in seconds for port scanning
    SCAN_PORTS = [22, 80, 443, 3306, 5432, 8080]

    # Reports directory
    REPORTS_DIR = os.path.join(BASE_DIR, 'reports')


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True


class ProductionConfig(Config):
    """Production configuration for Google Cloud deployment."""
    DEBUG = False
    SECRET_KEY = os.environ.get('SECRET_KEY')  # Must be set in production


class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'


# Configuration dictionary for easy access
config_by_name = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig
}
