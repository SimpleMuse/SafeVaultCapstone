-- database.sql
CREATE DATABASE IF NOT EXISTS SafeVault;
USE SafeVault;

CREATE TABLE IF NOT EXISTS Users (
    UserID INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    Username VARCHAR(100) NOT NULL,
    Email VARCHAR(100) NOT NULL,
    PasswordHash VARCHAR(255) NOT NULL,
    Role VARCHAR(20) NOT NULL DEFAULT 'user',
    UNIQUE KEY UX_Users_Username (Username)
);

CREATE TABLE IF NOT EXISTS RefreshTokens (
    TokenHash CHAR(64) NOT NULL PRIMARY KEY,
    FamilyId CHAR(32) NOT NULL,
    UserID INT NOT NULL,
    CreatedAtUtc DATETIME(6) NOT NULL,
    ExpiresAtUtc DATETIME(6) NOT NULL,
    RevokedAtUtc DATETIME(6) NULL,
    ReplacedByTokenHash CHAR(64) NULL,
    INDEX IX_RefreshTokens_FamilyId (FamilyId),
    CONSTRAINT FK_RefreshTokens_Users
        FOREIGN KEY (UserID) REFERENCES Users (UserID) ON DELETE CASCADE
);