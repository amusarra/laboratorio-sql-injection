package com.sqllib.repositories;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import com.sqllib.utils.DatabaseConnection;

public class UserRepository {
    
    /**
     * SQL Injection safe: uses PreparedStatement
     */
    public String getUserById(String id) throws SQLException {
        // Safe: treat id as integer; if not numeric, return null
        try {
            int idInt = Integer.parseInt(id);
            String query = "SELECT username FROM users WHERE id = ?";
            StringBuilder result = new StringBuilder();
            try (Connection conn = DatabaseConnection.getConnection();
                 PreparedStatement ps = conn.prepareStatement(query)) {
                ps.setInt(1, idInt);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        if (result.length() > 0) result.append(", ");
                        result.append(rs.getString("username"));
                    }
                }
            }
            return result.length() > 0 ? result.toString() : null;
        } catch (NumberFormatException e) {
            // Non-numeric id -> treat as invalid input (avoid injection)
            return null;
        }
    }
    
    /**
     * SQL Injection safe: uses PreparedStatement
     * Returns the ID of the newly created user for Second Order SQL Injection demonstration
     */
    public int createUser(String username, String password, String email) throws SQLException {
        String sql = "INSERT INTO users (username, password, email) VALUES (?, ?, ?)";
        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, username);
            ps.setString(2, password);
            ps.setString(3, email);
            ps.executeUpdate();

            // Try to get generated key first
            try (ResultSet keys = ps.getGeneratedKeys()) {
                if (keys != null && keys.next()) {
                    return keys.getInt(1);
                }
            }
            // Fallback for SQLite
            try (ResultSet rs = conn.createStatement().executeQuery("SELECT last_insert_rowid()")) {
                if (rs.next()) {
                    return rs.getInt(1);
                }
            }
        }
        return -1;
    }
    
    /**
     * SQL Injection safe: uses PreparedStatement
     * VULNERABLE: Authentication bypass
     */
    public boolean authenticate(String username, String password) throws SQLException {
        String query = "SELECT 1 FROM users WHERE username = ? AND password = ? LIMIT 1";
        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(query)) {
            ps.setString(1, username);
            ps.setString(2, password);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }
    
    /**
     * SQL Injection safe: uses PreparedStatement
     * VULNERABLE: Second Order SQL Injection - Step 2
     * Retrieves user by ID, then uses stored username in a second vulnerable query
     */
    public String getUserProfile(int userId) throws SQLException {
        String getUserQuery = "SELECT username FROM users WHERE id = ?";
        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(getUserQuery)) {
            ps.setInt(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    String storedUsername = rs.getString("username");

                    // Safe: use PreparedStatement for the second query as well
                    String profileQuery = "SELECT email FROM users WHERE username = ?";
                    try (PreparedStatement ps2 = conn.prepareStatement(profileQuery)) {
                        ps2.setString(1, storedUsername);
                        try (ResultSet rs2 = ps2.executeQuery()) {
                            StringBuilder emails = new StringBuilder();
                            while (rs2.next()) {
                                if (emails.length() > 0) emails.append(", ");
                                emails.append(rs2.getString("email"));
                            }
                            return emails.length() > 0 ? emails.toString() : null;
                        }
                    }
                }
            }
        }
        return null;
    }
    
    /**
     * SQL Injection safe: uses PreparedStatement
     * VULNERABLE: Boolean-based Blind SQL Injection
     * Returns different responses based on query result (true/false)
     * Attacker can extract data bit by bit by observing behavior
     */
    public boolean checkUserExists(String username) throws SQLException {
        String query = "SELECT COUNT(*) as count FROM users WHERE username = ?";
        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(query)) {
            ps.setString(1, username);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return rs.getInt("count") > 0;
                }
            }
        }
        return false;
    }
    
    /**
     * SQL Injection safe: uses PreparedStatement
     * VULNERABLE: Time-based Blind SQL Injection
     * Returns same response but with time delay if condition is true
     * Attacker extracts data by measuring response time
     */
    public String getUserEmail(String userId) throws SQLException {
        // Require numeric id to prevent injection-based payloads (e.g., SLEEP(...))
        try {
            int idInt = Integer.parseInt(userId);
            String query = "SELECT email FROM users WHERE id = ?";
            try (Connection conn = DatabaseConnection.getConnection();
                 PreparedStatement ps = conn.prepareStatement(query)) {
                ps.setInt(1, idInt);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        return rs.getString("email");
                    }
                }
            }
            return "User not found";
        } catch (NumberFormatException e) {
            // Invalid id -> do not execute any injected SQL
            return "User not found";
        }
    }
    
    /**
     * SQL Injection safe: uses PreparedStatement
     * VULNERABLE: UNION-based SQL Injection
     * Allows attacker to extract data from other tables by injecting UNION queries
     * The application expects to return username, but attacker can extract sensitive data
     */
    public String searchUserByName(String username) throws SQLException {
        String query = "SELECT username FROM users WHERE username LIKE ?";
        StringBuilder results = new StringBuilder();
        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(query)) {
            ps.setString(1, "%" + username + "%");
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    if (results.length() > 0) results.append(", ");
                    results.append(rs.getString("username"));
                }
            }
        }
        return results.length() > 0 ? results.toString() : "No users found";
    }
    
    /**
     * SQL Injection safe: uses PreparedStatement
     * VULNERABLE: Error-Based SQL Injection
     * Exposes database errors that reveal structure and data
     * Example attack: id = "1 AND 1=CAST((SELECT password FROM users WHERE id=1) AS INT)"
     * 
     * CRITICAL VULNERABILITY: Returns SQL error messages to user!
     * This allows attackers to extract sensitive data through error messages.
     */
    public String getUserPassword(String userId) throws SQLException {
        // Use numeric id parsing and PreparedStatement; do NOT expose SQL errors
        try {
            int idInt = Integer.parseInt(userId);
            String query = "SELECT password FROM users WHERE id = ?";
            try (Connection conn = DatabaseConnection.getConnection();
                 PreparedStatement ps = conn.prepareStatement(query)) {
                ps.setInt(1, idInt);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        return rs.getString("password");
                    }
                }
            }
        } catch (NumberFormatException e) {
            // invalid id -> treat as not found
            return null;
        } catch (SQLException e) {
            // Log internally if needed, but do NOT return SQL error details to caller
            System.err.println("Database error (hidden from user): " + e.getMessage());
            return null;
        }
        return null;
    }
}