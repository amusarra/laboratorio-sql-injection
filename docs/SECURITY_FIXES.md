# SECURITY_FIXES

Breve riepilogo
- Obiettivo: rimuovere tutte le vulnerabilità SQL Injection rilevate dai test di integrazione.
- Principi applicati:
  1. PreparedStatement / query parametrizzate per tutte le query con input esterno.
  2. Validazione dei parametri (id numerici) quando applicabile.
  3. Non esporre messaggi di errore SQL agli utenti; loggare internamente.
  4. Parametrizzare anche query second‑order (quando si riusa il valore memorizzato).
  5. Bloccare esecuzione di payload time‑based tramite validazione (SLEEP non raggiungibile da input non numerico).

Step‑by‑step delle modifiche
1. Analisi dei test falliti: vettori identificati - comment injection, OR/UNION injection, boolean/time/error-based e second‑order.  
2. Tutte le interazioni JDBC con input esterno convertite a PreparedStatement nel file UserRepository.java.  
3. Aggiunta di parsing Integer.parseInt per i metodi che utilizzano id presunti numerici.  
4. Gestione degli errori SQL: log interno e ritorno di valori neutri/null invece di stringhe d'errore.  
5. Test: gli unit test esistenti ora devono fallire nel rilevare vulnerabilità (ovvero i test che prima segnalavano vulnerabilità non dovrebbero più rilevarle).

Mapping a OWASP
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [OWASP Top 10](https://owasp.org/Top10/)
- [A09:2021 – Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/). Non esporre dettagli d'errore, loggare internamente.  
- Raccomandazioni aggiuntive: password hashing (bcrypt/argon2), least privilege DB, logging strutturato, SAST/DAST in CI.

Esempi difformi di patch (UserRepository.java)
- Di seguito un unified diff che evidenzia le modifiche principali applicate a `/src/main/java/com/sqllib/repositories/UserRepository.java`.
- Nota: per brevità vengono mostrate solo le porzioni cambiate (hunk). Il file completo è stato aggiornato per usare PreparedStatement, validare id numerici e non esporre errori SQL.

```diff
--- a/src/main/java/com/sqllib/repositories/UserRepository.java
+++ b/src/main/java/com/sqllib/repositories/UserRepository.java
@@
-    public String getUserById(String id) throws SQLException {
-        // Vulnerable: concatenation
-        String sql = "SELECT username FROM users WHERE id = '" + id + "'";
-        Statement stmt = conn.createStatement();
-        ResultSet rs = stmt.executeQuery(sql);
-        ...
-    }
+    public String getUserById(String id) throws SQLException {
+        // Safe: treat id as integer; if not numeric, return null
+        try {
+            int idInt = Integer.parseInt(id);
+            String query = "SELECT username FROM users WHERE id = ?";
+            try (Connection conn = DatabaseConnection.getConnection();
+                 PreparedStatement ps = conn.prepareStatement(query)) {
+                ps.setInt(1, idInt);
+                try (ResultSet rs = ps.executeQuery()) {
+                    // ... collect usernames ...
+                }
+            }
+        } catch (NumberFormatException e) {
+            return null;
+        }
+    }
@@
-    public int createUser(String username, String password, String email) throws SQLException {
-        String sql = "INSERT INTO users (username, password, email) VALUES ('" + username + "', '" + password + "', '" + email + "')";
-        Statement stmt = conn.createStatement();
-        stmt.executeUpdate(sql);
-        ...
-    }
+    public int createUser(String username, String password, String email) throws SQLException {
+        String sql = "INSERT INTO users (username, password, email) VALUES (?, ?, ?)";
+        try (Connection conn = DatabaseConnection.getConnection();
+             PreparedStatement ps = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
+            ps.setString(1, username);
+            ps.setString(2, password);
+            ps.setString(3, email);
+            ps.executeUpdate();
+            // ... retrieve generated key or fallback last_insert_rowid() ...
+        }
+    }
@@
-    public boolean authenticate(String username, String password) throws SQLException {
-        String sql = "SELECT 1 FROM users WHERE username = '" + username + "' AND password = '" + password + "' LIMIT 1";
-        Statement stmt = conn.createStatement();
-        ResultSet rs = stmt.executeQuery(sql);
-        return rs.next();
-    }
+    public boolean authenticate(String username, String password) throws SQLException {
+        String query = "SELECT 1 FROM users WHERE username = ? AND password = ? LIMIT 1";
+        try (Connection conn = DatabaseConnection.getConnection();
+             PreparedStatement ps = conn.prepareStatement(query)) {
+            ps.setString(1, username);
+            ps.setString(2, password);
+            try (ResultSet rs = ps.executeQuery()) {
+                return rs.next();
+            }
+        }
+    }
@@
-    public String getUserProfile(int userId) throws SQLException {
-        // Vulnerable second-order: uses stored username directly in concatenated query
-        String sql1 = "SELECT username FROM users WHERE id = " + userId;
-        // ... execute ...
-        String storedUsername = ...;
-        String sql2 = "SELECT email FROM users WHERE username = '" + storedUsername + "'";
-        // ... execute ...
-    }
+    public String getUserProfile(int userId) throws SQLException {
+        String getUserQuery = "SELECT username FROM users WHERE id = ?";
+        try (Connection conn = DatabaseConnection.getConnection();
+             PreparedStatement ps = conn.prepareStatement(getUserQuery)) {
+            ps.setInt(1, userId);
+            try (ResultSet rs = ps.executeQuery()) {
+                if (rs.next()) {
+                    String storedUsername = rs.getString("username");
+                    // Safe: use PreparedStatement for the second query as well
+                    String profileQuery = "SELECT email FROM users WHERE username = ?";
+                    try (PreparedStatement ps2 = conn.prepareStatement(profileQuery)) {
+                        ps2.setString(1, storedUsername);
+                        try (ResultSet rs2 = ps2.executeQuery()) {
+                            // ... collect emails ...
+                        }
+                    }
+                }
+            }
+        }
+    }
@@
-    public boolean checkUserExists(String username) throws SQLException {
-        String sql = "SELECT COUNT(*) as count FROM users WHERE username = '" + username + "'";
-        // ... execute concatenated query ...
-    }
+    public boolean checkUserExists(String username) throws SQLException {
+        String query = "SELECT COUNT(*) as count FROM users WHERE username = ?";
+        try (Connection conn = DatabaseConnection.getConnection();
+             PreparedStatement ps = conn.prepareStatement(query)) {
+            ps.setString(1, username);
+            try (ResultSet rs = ps.executeQuery()) {
+                if (rs.next()) {
+                    return rs.getInt("count") > 0;
+                }
+            }
+        }
+        return false;
+    }
@@
-    public String getUserEmail(String userId) throws SQLException {
-        String sql = "SELECT email FROM users WHERE id = '" + userId + "'";
-        // ... execute ...
-    }
+    public String getUserEmail(String userId) throws SQLException {
+        try {
+            int idInt = Integer.parseInt(userId);
+            String query = "SELECT email FROM users WHERE id = ?";
+            try (Connection conn = DatabaseConnection.getConnection();
+                 PreparedStatement ps = conn.prepareStatement(query)) {
+                ps.setInt(1, idInt);
+                try (ResultSet rs = ps.executeQuery()) {
+                    if (rs.next()) return rs.getString("email");
+                }
+            }
+            return "User not found";
+        } catch (NumberFormatException e) {
+            return "User not found";
+        }
+    }
@@
-    public String searchUserByName(String username) throws SQLException {
-        String sql = "SELECT username FROM users WHERE username LIKE '%" + username + "%'";
-        // ... execute concatenated LIKE with potential UNION injection ...
-    }
+    public String searchUserByName(String username) throws SQLException {
+        String query = "SELECT username FROM users WHERE username LIKE ?";
+        try (Connection conn = DatabaseConnection.getConnection();
+             PreparedStatement ps = conn.prepareStatement(query)) {
+            ps.setString(1, "%" + username + "%");
+            try (ResultSet rs = ps.executeQuery()) {
+                // ... collect usernames ...
+            }
+        }
+        return "No users found";
+    }
@@
-    public String getUserPassword(String userId) throws SQLException {
-        String sql = "SELECT password FROM users WHERE id = '" + userId + "'";
-        // ... execute and possibly return SQL error string to caller ...
-    }
+    public String getUserPassword(String userId) throws SQLException {
+        try {
+            int idInt = Integer.parseInt(userId);
+            String query = "SELECT password FROM users WHERE id = ?";
+            try (Connection conn = DatabaseConnection.getConnection();
+                 PreparedStatement ps = conn.prepareStatement(query)) {
+                ps.setInt(1, idInt);
+                try (ResultSet rs = ps.executeQuery()) {
+                    if (rs.next()) return rs.getString("password");
+                }
+            }
+        } catch (NumberFormatException e) {
+            return null;
+        } catch (SQLException e) {
+            // Log internally; do not expose SQL error details to user
+            System.err.println("Database error (hidden from user): " + e.getMessage());
+            return null;
+        }
+        return null;
+    }
```

Ulteriori note
- Le modifiche risolvono i casi di test segnalati: comment injection, OR/UNION, boolean/time/error‑based e second‑order SQLi.  
- Raccomandazioni successive: migrare password a hash sicuri, aggiungere logging strutturato e controlli di privilegio DB.
