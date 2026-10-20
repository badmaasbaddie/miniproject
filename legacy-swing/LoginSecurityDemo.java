package passwordsecurity;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * Module 7: Login Security Demo
 * Demonstrates secure password authentication using salted PBKDF2WithHmacSHA256,
 * progressive failure tracking, 3-attempt account lockout, and password policy enforcement.
 * Plaintext passwords are NEVER stored in accounts; only cryptographic salt + PBKDF2 digest.
 */
public class LoginSecurityDemo extends JPanel {

    private final SessionStats sessionStats;

    // Model for a secure local user account
    public static class UserAccount {
        final String username;
        final String saltHex;
        final String pbkdf2HashHex;
        int failedAttempts = 0;
        boolean isLocked = false;
        long lockExpiry = 0;

        public UserAccount(String username, String saltHex, String pbkdf2HashHex) {
            this.username = username;
            this.saltHex = saltHex;
            this.pbkdf2HashHex = pbkdf2HashHex;
        }
    }

    private final Map<String, UserAccount> accountDatabase = new HashMap<>();
    private final SecureRandom secureRandom = new SecureRandom();

    // UI Components
    private JComboBox<String> userSelectCombo;
    private JTextField usernameField;
    private JPasswordField passwordField;
    private JCheckBox showPasswordCheck;
    private JButton loginBtn;
    private JButton resetAttemptsBtn;

    private JLabel attemptsBadge;
    private JLabel lockoutTimerLabel;
    private JProgressBar lockoutProgressBar;
    private JTextArea authLogArea;

    // Cooldown Timer
    private Timer cooldownSwingTimer;
    private int cooldownSecondsRemaining = 0;

    public LoginSecurityDemo(SessionStats stats) {
        this.sessionStats = stats;

        setLayout(new BorderLayout());
        setBackground(UITheme.CONTENT_BG);
        setBorder(new EmptyBorder(20, 24, 20, 24));

        initPredefinedAccounts();
        initUI();
    }

    private void initPredefinedAccounts() {
        // Pre-create salted PBKDF2 accounts
        registerAccount("alice_student", "Study#Hard2026!");
        registerAccount("bob_admin", "Secur1ty#P@ss");
        registerAccount("charlie_guest", "Guest$Login77");
    }

    private void registerAccount(String username, String plaintextPassword) {
        byte[] salt = new byte[16];
        secureRandom.nextBytes(salt);
        String saltHex = bytesToHex(salt);
        String hashHex = computePBKDF2(plaintextPassword.toCharArray(), salt);
        accountDatabase.put(username, new UserAccount(username, saltHex, hashHex));
    }

    private void initUI() {
        // Header
        JPanel headerPanel = UITheme.createHeader(
                "Module 7: Login Security & Defense Mechanisms",
                "Explore salted PBKDF2 verification, rate-limiting, and 3-attempt lockout defense"
        );
        add(headerPanel, BorderLayout.NORTH);

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setOpaque(false);

        // 1. Two-Column Card: Login Form on Left, Credentials & Policy on Right
        mainPanel.add(createLoginFormCard());
        mainPanel.add(Box.createVerticalStrut(16));

        // 2. Authentication Activity Log Card
        mainPanel.add(createAuditLogCard());
        mainPanel.add(Box.createVerticalStrut(16));

        // 3. Defense Concepts Card
        mainPanel.add(createConceptsCard());

        JScrollPane scrollPane = new JScrollPane(mainPanel);
        scrollPane.setBorder(null);
        scrollPane.setOpaque(false);
        scrollPane.getViewport().setOpaque(false);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);

        add(scrollPane, BorderLayout.CENTER);
    }

    private JPanel createLoginFormCard() {
        JPanel card = UITheme.createCard();
        card.setLayout(new GridLayout(1, 2, 24, 0));

        // Left Side: Login Interactive Form
        JPanel form = new JPanel();
        form.setLayout(new BoxLayout(form, BoxLayout.Y_AXIS));
        form.setOpaque(false);

        JLabel formTitle = new JLabel("Simulated Secure Login Screen");
        formTitle.setFont(UITheme.FONT_SECTION);
        formTitle.setForeground(UITheme.TEXT_PRIMARY);

        form.add(formTitle);
        form.add(Box.createVerticalStrut(12));

        // Account Quick Preset
        JLabel chooseLbl = new JLabel("Select Predefined Demo Account:");
        chooseLbl.setFont(UITheme.FONT_BODY_BOLD);
        userSelectCombo = new JComboBox<>(new String[]{"alice_student", "bob_admin", "charlie_guest"});
        userSelectCombo.setFont(UITheme.FONT_BODY);
        userSelectCombo.addActionListener(e -> {
            String selected = (String) userSelectCombo.getSelectedItem();
            if (selected != null) {
                usernameField.setText(selected);
                passwordField.setText("");
                updateLockoutStateForUser(selected);
            }
        });

        form.add(chooseLbl);
        form.add(userSelectCombo);
        form.add(Box.createVerticalStrut(10));

        // Username
        JLabel uLbl = new JLabel("Username:");
        uLbl.setFont(UITheme.FONT_BODY_BOLD);
        usernameField = new JTextField("alice_student");
        usernameField.setFont(UITheme.FONT_MONO);

        form.add(uLbl);
        form.add(usernameField);
        form.add(Box.createVerticalStrut(10));

        // Password
        JLabel pLbl = new JLabel("Password:");
        pLbl.setFont(UITheme.FONT_BODY_BOLD);
        passwordField = new JPasswordField();
        passwordField.setFont(UITheme.FONT_MONO);

        showPasswordCheck = new JCheckBox("Show Password");
        showPasswordCheck.setFont(UITheme.FONT_SMALL);
        showPasswordCheck.setOpaque(false);
        showPasswordCheck.addActionListener(e -> {
            passwordField.setEchoChar(showPasswordCheck.isSelected() ? (char) 0 : '•');
        });

        JPanel pwdRow = new JPanel(new BorderLayout());
        pwdRow.setOpaque(false);
        pwdRow.add(passwordField, BorderLayout.CENTER);
        pwdRow.add(showPasswordCheck, BorderLayout.EAST);

        form.add(pLbl);
        form.add(pwdRow);
        form.add(Box.createVerticalStrut(12));

        // Attempts & Lockout Display
        JPanel statusRow = new JPanel(new BorderLayout());
        statusRow.setOpaque(false);

        attemptsBadge = UITheme.createBadge("Remaining Attempts: 3 / 3", UITheme.SUCCESS_GREEN);
        lockoutTimerLabel = new JLabel("Account Status: Active");
        lockoutTimerLabel.setFont(UITheme.FONT_BODY_BOLD);
        lockoutTimerLabel.setForeground(UITheme.TEXT_PRIMARY);

        statusRow.add(attemptsBadge, BorderLayout.WEST);
        statusRow.add(lockoutTimerLabel, BorderLayout.EAST);

        lockoutProgressBar = new JProgressBar(0, 15);
        lockoutProgressBar.setValue(0);
        lockoutProgressBar.setVisible(false);

        form.add(statusRow);
        form.add(Box.createVerticalStrut(8));
        form.add(lockoutProgressBar);
        form.add(Box.createVerticalStrut(14));

        // Buttons
        JPanel actionRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        actionRow.setOpaque(false);

        loginBtn = UITheme.createButton("Log In", UITheme.PRIMARY_BLUE, Color.WHITE);
        loginBtn.addActionListener(e -> attemptLogin());

        resetAttemptsBtn = UITheme.createButton("Emergency Reset", UITheme.SIDEBAR_HOVER, Color.WHITE);
        resetAttemptsBtn.setFont(UITheme.FONT_SMALL);
        resetAttemptsBtn.addActionListener(e -> emergencyResetAccount());

        actionRow.add(loginBtn);
        actionRow.add(resetAttemptsBtn);

        form.add(actionRow);

        // Right Side: Educational Credentials & Password Policy
        JPanel rightCol = new JPanel();
        rightCol.setLayout(new BoxLayout(rightCol, BoxLayout.Y_AXIS));
        rightCol.setOpaque(false);

        JLabel credTitle = new JLabel("Test Credentials & Security Rules");
        credTitle.setFont(UITheme.FONT_SECTION);
        credTitle.setForeground(UITheme.TEXT_PRIMARY);
        rightCol.add(credTitle);
        rightCol.add(Box.createVerticalStrut(10));

        JTextArea credTable = new JTextArea();
        credTable.setFont(UITheme.FONT_MONO);
        credTable.setEditable(false);
        credTable.setOpaque(false);
        credTable.setText(
                "PREDEFINED TEST ACCOUNTS:\n" +
                "-------------------------------------------\n" +
                "1. User: alice_student\n" +
                "   Password: Study#Hard2026!\n\n" +
                "2. User: bob_admin\n" +
                "   Password: Secur1ty#P@ss\n\n" +
                "3. User: charlie_guest\n" +
                "   Password: Guest$Login77\n" +
                "-------------------------------------------\n" +
                "PASSWORD POLICY REQUIREMENTS:\n" +
                "• Minimum 8 characters\n" +
                "• At least one uppercase letter (A-Z)\n" +
                "• At least one lowercase letter (a-z)\n" +
                "• At least one digit (0-9)\n" +
                "• At least one special symbol (!@#$%...)"
        );
        rightCol.add(credTable);

        card.add(form);
        card.add(rightCol);

        return card;
    }

    private JPanel createAuditLogCard() {
        JPanel card = UITheme.createCard();
        card.setLayout(new BorderLayout(0, 8));

        JLabel title = new JLabel("Authentication Audit Trail (Console)");
        title.setFont(UITheme.FONT_SECTION);
        title.setForeground(UITheme.TEXT_PRIMARY);

        authLogArea = new JTextArea(6, 40);
        authLogArea.setFont(new Font("Consolas", Font.PLAIN, 12));
        authLogArea.setEditable(false);
        authLogArea.setBackground(new Color(248, 250, 252));
        authLogArea.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(UITheme.CARD_BORDER, 1),
                new EmptyBorder(8, 10, 8, 10)
        ));

        JScrollPane logScroll = new JScrollPane(authLogArea);

        card.add(title, BorderLayout.NORTH);
        card.add(logScroll, BorderLayout.CENTER);

        logMessage("System initialized. Salted PBKDF2 key-derivation engine active.");
        return card;
    }

    private JPanel createConceptsCard() {
        JPanel card = UITheme.createCard();
        card.setLayout(new BorderLayout(0, 8));

        JLabel title = new JLabel("Security Insights: Account Lockouts vs Denial-of-Service (DoS)");
        title.setFont(UITheme.FONT_SECTION);
        title.setForeground(UITheme.TEXT_PRIMARY);

        JTextArea text = new JTextArea();
        text.setFont(UITheme.FONT_BODY);
        text.setEditable(false);
        text.setLineWrap(true);
        text.setWrapStyleWord(true);
        text.setOpaque(false);
        text.setText(
                "• Why Lock Accounts After 3 Failed Attempts?\n" +
                "  Without rate-limiting, an online attacker can test thousands of guesses. By locking the account, automated brute-force is completely halted.\n\n" +
                "• The Architectural Dilemma (Account Lockout DoS):\n" +
                "  If an attacker deliberately inputs 3 wrong passwords for a known target (e.g. 'ceo@company.com'), they can lock legitimate users out of their accounts. This is called an Account Lockout Denial-of-Service.\n\n" +
                "• Modern Industry Countermeasures:\n" +
                "  1. Exponential Backoff: Instead of permanent lock, delay attempts (1s, 2s, 4s, 8s, 16s).\n" +
                "  2. IP Reputation & CAPTCHA: Challenge users with reCAPTCHA after 2 failed tries.\n" +
                "  3. Risk-Based Authentication: Send a confirmation email or SMS if login originates from an unrecognized device."
        );

        card.add(title, BorderLayout.NORTH);
        card.add(text, BorderLayout.CENTER);
        return card;
    }

    private void attemptLogin() {
        String username = usernameField.getText().trim();
        char[] passwordChars = passwordField.getPassword();

        if (username.isEmpty() || passwordChars.length == 0) {
            JOptionPane.showMessageDialog(this, "Please enter both username and password.", "Missing Fields", JOptionPane.WARNING_MESSAGE);
            return;
        }

        UserAccount account = accountDatabase.get(username);
        if (account == null) {
            // Security best practice: Avoid revealing whether the username exists!
            logMessage("[FAILED] Login attempt for unknown user: '" + username + "'");
            JOptionPane.showMessageDialog(this, "Invalid username or password.", "Authentication Failed", JOptionPane.ERROR_MESSAGE);
            sessionStats.recordLoginAttempt(false);
            return;
        }

        // Check if currently locked
        long now = System.currentTimeMillis();
        if (account.isLocked && now < account.lockExpiry) {
            long remainingSec = (account.lockExpiry - now) / 1000 + 1;
            logMessage("[BLOCKED] Login attempt rejected: Account '" + username + "' is currently LOCKED (" + remainingSec + "s remaining).");
            JOptionPane.showMessageDialog(this,
                    "Account is locked due to 3 consecutive failed login attempts.\n" +
                    "Please wait " + remainingSec + " seconds or click 'Emergency Reset'.",
                    "Account Locked", JOptionPane.WARNING_MESSAGE);
            sessionStats.recordLoginAttempt(true);
            return;
        } else if (account.isLocked && now >= account.lockExpiry) {
            // Cooldown has expired, auto-unlock
            account.isLocked = false;
            account.failedAttempts = 0;
            logMessage("[INFO] Cooldown period expired for account: '" + username + "'. Lockout lifted.");
        }

        // Verify password using PBKDF2 with salt
        byte[] salt = hexToBytes(account.saltHex);
        String calculatedHash = computePBKDF2(passwordChars, salt);

        // Clear password chars from memory
        java.util.Arrays.fill(passwordChars, '0');

        if (calculatedHash.equals(account.pbkdf2HashHex)) {
            // SUCCESS
            account.failedAttempts = 0;
            updateLockoutStateForUser(username);
            logMessage("[SUCCESS] User '" + username + "' authenticated successfully via PBKDF2!");
            sessionStats.recordLoginAttempt(false);

            JOptionPane.showMessageDialog(this,
                    "Login Successful!\n\nWelcome back, " + username + "!\n" +
                    "Authentication verified against salted PBKDF2 hash.",
                    "Access Granted", JOptionPane.INFORMATION_MESSAGE);
        } else {
            // FAILURE
            account.failedAttempts++;
            logMessage("[FAILED] Incorrect password for user: '" + username + "'. Consecutive failures: " + account.failedAttempts + "/3");

            if (account.failedAttempts >= 3) {
                // Lock account for 15 seconds
                account.isLocked = true;
                account.lockExpiry = System.currentTimeMillis() + 15_000;
                logMessage("[ALERT] Account '" + username + "' has been LOCKED for 15 seconds!");
                sessionStats.recordLoginAttempt(true);
                startCooldownTimer(15);
                updateLockoutStateForUser(username);

                JOptionPane.showMessageDialog(this,
                        "ACCOUNT LOCKED!\n\nThree consecutive failed login attempts detected.\n" +
                        "For security, this demo account has been locked for a 15-second cooldown.",
                        "Lockout Activated", JOptionPane.ERROR_MESSAGE);
            } else {
                updateLockoutStateForUser(username);
                sessionStats.recordLoginAttempt(false);
                JOptionPane.showMessageDialog(this,
                        "Invalid username or password.\nRemaining attempts before lockout: " + (3 - account.failedAttempts),
                        "Authentication Failed", JOptionPane.WARNING_MESSAGE);
            }
        }
    }

    private void updateLockoutStateForUser(String username) {
        UserAccount acc = accountDatabase.get(username);
        if (acc == null) return;

        int remaining = Math.max(0, 3 - acc.failedAttempts);
        attemptsBadge.setText("Remaining Attempts: " + remaining + " / 3");

        if (acc.isLocked) {
            attemptsBadge.setBackground(UITheme.DANGER_RED);
            lockoutTimerLabel.setText("Account Status: LOCKED");
            lockoutTimerLabel.setForeground(UITheme.DANGER_RED);
            loginBtn.setEnabled(false);
        } else {
            loginBtn.setEnabled(true);
            if (remaining == 3) {
                attemptsBadge.setBackground(UITheme.SUCCESS_GREEN);
            } else {
                attemptsBadge.setBackground(UITheme.WARNING_AMBER);
            }
            lockoutTimerLabel.setText("Account Status: Active");
            lockoutTimerLabel.setForeground(UITheme.TEXT_PRIMARY);
        }
    }

    private void startCooldownTimer(int seconds) {
        cooldownSecondsRemaining = seconds;
        lockoutProgressBar.setMaximum(seconds);
        lockoutProgressBar.setValue(seconds);
        lockoutProgressBar.setVisible(true);

        if (cooldownSwingTimer != null && cooldownSwingTimer.isRunning()) {
            cooldownSwingTimer.stop();
        }

        cooldownSwingTimer = new Timer(1000, e -> {
            cooldownSecondsRemaining--;
            lockoutProgressBar.setValue(cooldownSecondsRemaining);
            lockoutTimerLabel.setText("Account Status: LOCKED (Cooldown: " + cooldownSecondsRemaining + "s)");

            if (cooldownSecondsRemaining <= 0) {
                cooldownSwingTimer.stop();
                lockoutProgressBar.setVisible(false);
                String user = usernameField.getText().trim();
                UserAccount acc = accountDatabase.get(user);
                if (acc != null) {
                    acc.isLocked = false;
                    acc.failedAttempts = 0;
                    updateLockoutStateForUser(user);
                }
                logMessage("[INFO] Cooldown timer finished. Account '" + user + "' unlocked.");
            }
        });
        cooldownSwingTimer.start();
    }

    private void emergencyResetAccount() {
        String username = usernameField.getText().trim();
        UserAccount acc = accountDatabase.get(username);
        if (acc != null) {
            acc.failedAttempts = 0;
            acc.isLocked = false;
            acc.lockExpiry = 0;
            if (cooldownSwingTimer != null) cooldownSwingTimer.stop();
            lockoutProgressBar.setVisible(false);
            updateLockoutStateForUser(username);
            logMessage("[ADMIN RESET] Manually unlocked account and reset failed attempts counter for: '" + username + "'");
            JOptionPane.showMessageDialog(this, "Account '" + username + "' reset to active state.", "Reset Complete", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void logMessage(String msg) {
        String timestamp = new java.text.SimpleDateFormat("HH:mm:ss").format(new java.util.Date());
        authLogArea.append("[" + timestamp + "] " + msg + "\n");
        authLogArea.setCaretPosition(authLogArea.getDocument().getLength());
    }

    /**
     * Derives a cryptographic PBKDF2 hash using PBKDF2WithHmacSHA256, 10,000 iterations, 256-bit key.
     */
    public static String computePBKDF2(char[] password, byte[] salt) {
        try {
            int iterations = 10_000;
            int keyLength = 256;
            KeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = factory.generateSecret(spec).getEncoded();
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("PBKDF2WithHmacSHA256 algorithm failure", e);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static byte[] hexToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}
