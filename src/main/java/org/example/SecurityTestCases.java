package org.example;

import java.sql.*;
import java.io.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.MessageDigest;
import java.util.Random;

/**
 * SECURITY WARNING: This file contains intentionally vulnerable code for testing purposes.
 * These patterns are designed to be detected by CodeQL security analysis.
 */
public class SecurityTestCases {
    
    // 1. SQL Injection - String concatenation
    public void sqlInjectionVulnerability(String userId) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test");
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query);
    }
    
    // 2. Hard-coded credentials
    public void hardCodedCredentials() {
        String dbPassword = "admin123";
        String apiKey = "sk-1234567890abcdef1234567890abcdef";
        String secret = "MySecretPassword123!";
        
        // Use credentials
        System.setProperty("db.password", dbPassword);
        System.setProperty("api.key", apiKey);
    }
    
    // 3. Cross-Site Scripting (XSS)
    public void xssVulnerability(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("comment");
        PrintWriter out = response.getWriter();
        out.println("<div>User comment: " + userInput + "</div>");
    }
    
    // 4. Path Traversal
    public void pathTraversalVulnerability(String filename) throws IOException {
        File file = new File("/uploads/" + filename);
        FileInputStream fis = new FileInputStream(file);
        // Read file content
    }
    
    // 5. Command Injection
    public void commandInjectionVulnerability(String userInput) throws IOException {
        Runtime runtime = Runtime.getRuntime();
        String command = "ping " + userInput;
        Process process = runtime.exec(command);
    }
    
    // 6. Weak cryptography - MD5
    public String weakCryptography(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(input.getBytes());
        return new String(hash);
    }
    
    // 7. Insecure random number generation
    public int insecureRandom() {
        Random random = new Random();
        return random.nextInt();
    }
    
    // 8. Information disclosure in error messages
    public void informationDisclosure(String userId) {
        try {
            // Some database operation
            throw new SQLException("Database connection failed for user: " + userId);
        } catch (SQLException e) {
            System.out.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    // 9. LDAP Injection
    public void ldapInjectionVulnerability(String username) {
        String filter = "(uid=" + username + ")";
        // LDAP search would use this filter
        System.out.println("LDAP Filter: " + filter);
    }
    
    // 10. Sensitive data in logs
    public void sensitiveDataInLogs(String password, String creditCard) {
        System.out.println("User login attempt with password: " + password);
        System.out.println("Processing payment for card: " + creditCard);
        
        // Also log to file
        try {
            FileWriter fw = new FileWriter("app.log", true);
            fw.write("Password attempt: " + password + "\n");
            fw.write("Credit card: " + creditCard + "\n");
            fw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
