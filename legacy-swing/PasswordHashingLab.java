package passwordsecurity;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Module 5: Password Hashing Lab
 * Demonstrates one-way cryptographic hashing using Java's MessageDigest (SHA-256).
 * Illustrates determinism, the avalanche effect, salting, and explains why raw SHA-256
 * must NOT be used alone for password storage in production.
 */
public class PasswordHashingLab extends JPanel {

    private final SessionStats sessionStats;

    // UI Components
    private JTextField inputField;
    private JTextField hashOutputField;
    private JLabel hashDetailsLabel;
    private JTextArea demonstrationLogArea;

    public PasswordHashingLab(SessionStats stats) {
        this.sessionStats = stats;

        setLayout(new BorderLayout());
        setBackground(UITheme.CONTENT_BG);
        setBorder(new EmptyBorder(20, 24, 20, 24));

        initUI();
    }

    private void initUI() {
        // Header
        JPanel headerPanel = UITheme.createHeader(
                "Module 5: Password Hashing Lab",
                "Explore one-way hashing with SHA-256, determinism, the avalanche effect, and salting"
        );
        add(headerPanel, BorderLayout.NORTH);

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setOpaque(false);

        // 1. Live Hash Calculator Card
        mainPanel.add(createHashCalculatorCard());
        mainPanel.add(Box.createVerticalStrut(16));

        // 2. Interactive Demonstrations Card (Determinism & Avalanche)
        mainPanel.add(createDemonstrationsCard());
        mainPanel.add(Box.createVerticalStrut(16));

        // 3. Cryptography Guide Card (SHA-256 vs Argon2/bcrypt)
        mainPanel.add(createEducationCard());

        JScrollPane scrollPane = new JScrollPane(mainPanel);
        scrollPane.setBorder(null);
        scrollPane.setOpaque(false);
        scrollPane.getViewport().setOpaque(false);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);

        add(scrollPane, BorderLayout.CENTER);

        // Initial default hash
        computeHash();
    }

    private JPanel createHashCalculatorCard() {
        JPanel card = UITheme.createCard();
        card.setLayout(new BorderLayout(0, 12));

        JLabel title = new JLabel("Live SHA-256 Digest Generator");
        title.setFont(UITheme.FONT_SECTION);
        title.setForeground(UITheme.TEXT_PRIMARY);

        JPanel form = new JPanel(new GridLayout(2, 1, 0, 10));
        form.setOpaque(false);

        // Input row
        JPanel inputRow = new JPanel(new BorderLayout(10, 0));
        inputRow.setOpaque(false);
        JLabel inputLbl = new JLabel("Input String: ");
        inputLbl.setFont(UITheme.FONT_BODY_BOLD);

        inputField = new JTextField("SuperSecretPassword2026");
        inputField.setFont(UITheme.FONT_MONO);

        JButton hashBtn = UITheme.createButton("Compute Digest", UITheme.PRIMARY_BLUE, Color.WHITE);
        hashBtn.addActionListener(e -> computeHash());

        inputRow.add(inputLbl, BorderLayout.WEST);
        inputRow.add(inputField, BorderLayout.CENTER);
        inputRow.add(hashBtn, BorderLayout.EAST);

        // Output row
        JPanel outputRow = new JPanel(new BorderLayout(10, 0));
        outputRow.setOpaque(false);
        JLabel outputLbl = new JLabel("SHA-256 Hash:");
        outputLbl.setFont(UITheme.FONT_BODY_BOLD);

        hashOutputField = new JTextField();
        hashOutputField.setFont(new Font("Consolas", Font.BOLD, 12));
        hashOutputField.setEditable(false);
        hashOutputField.setBackground(new Color(241, 245, 249));

        JButton copyBtn = UITheme.createButton("📋 Copy", UITheme.SIDEBAR_BG, Color.WHITE);
        copyBtn.setFont(UITheme.FONT_SMALL);
        copyBtn.addActionListener(e -> {
            String text = hashOutputField.getText();
            if (!text.isEmpty()) {
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
                JOptionPane.showMessageDialog(this, "SHA-256 hash copied to clipboard.");
            }
        });

        outputRow.add(outputLbl, BorderLayout.WEST);
        outputRow.add(hashOutputField, BorderLayout.CENTER);
        outputRow.add(copyBtn, BorderLayout.EAST);

        form.add(inputRow);
        form.add(outputRow);

        // Details summary
        hashDetailsLabel = new JLabel("Length: 64 hexadecimal characters (256 bits / 32 bytes) | Algorithm: SHA-256");
        hashDetailsLabel.setFont(UITheme.FONT_SMALL);
        hashDetailsLabel.setForeground(UITheme.TEXT_SECONDARY);

        card.add(title, BorderLayout.NORTH);
        card.add(form, BorderLayout.CENTER);
        card.add(hashDetailsLabel, BorderLayout.SOUTH);

        return card;
    }

    private JPanel createDemonstrationsCard() {
        JPanel card = UITheme.createCard();
        card.setLayout(new BorderLayout(0, 12));

        JLabel title = new JLabel("Interactive Hashing Experiments");
        title.setFont(UITheme.FONT_SECTION);
        title.setForeground(UITheme.TEXT_PRIMARY);

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        btnRow.setOpaque(false);

        JButton determinismBtn = UITheme.createButton("1. Test Determinism", UITheme.SIDEBAR_HOVER, Color.WHITE);
        determinismBtn.setFont(UITheme.FONT_SMALL);
        determinismBtn.addActionListener(e -> runDeterminismDemo());

        JButton avalancheBtn = UITheme.createButton("2. Test Avalanche Effect", UITheme.PURPLE_ACCENT, Color.WHITE);
        avalancheBtn.setFont(UITheme.FONT_SMALL);
        avalancheBtn.addActionListener(e -> runAvalancheDemo());

        JButton saltBtn = UITheme.createButton("3. Test Random Salt Effect", UITheme.SUCCESS_GREEN, Color.WHITE);
        saltBtn.setFont(UITheme.FONT_SMALL);
        saltBtn.addActionListener(e -> runSaltDemo());

        JButton clearBtn = UITheme.createButton("Clear Log", UITheme.CARD_BORDER, UITheme.TEXT_PRIMARY);
        clearBtn.setFont(UITheme.FONT_SMALL);
        clearBtn.addActionListener(e -> demonstrationLogArea.setText(""));

        btnRow.add(determinismBtn);
        btnRow.add(avalancheBtn);
        btnRow.add(saltBtn);
        btnRow.add(clearBtn);

        demonstrationLogArea = new JTextArea(8, 50);
        demonstrationLogArea.setFont(new Font("Consolas", Font.PLAIN, 12));
        demonstrationLogArea.setEditable(false);
        demonstrationLogArea.setBackground(new Color(248, 250, 252));
        demonstrationLogArea.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(UITheme.CARD_BORDER, 1),
                new EmptyBorder(8, 10, 8, 10)
        ));

        JScrollPane logScroll = new JScrollPane(demonstrationLogArea);

        card.add(title, BorderLayout.NORTH);
        card.add(btnRow, BorderLayout.CENTER);
        card.add(logScroll, BorderLayout.SOUTH);

        return card;
    }

    private JPanel createEducationCard() {
        JPanel card = UITheme.createCard();
        card.setLayout(new BorderLayout(0, 8));

        JLabel title = new JLabel("CRITICAL LESSON: Why Raw SHA-256 Must NOT Be Used for Passwords");
        title.setFont(UITheme.FONT_SECTION);
        title.setForeground(UITheme.DANGER_RED);

        JTextArea info = new JTextArea();
        info.setFont(UITheme.FONT_BODY);
        info.setEditable(false);
        info.setLineWrap(true);
        info.setWrapStyleWord(true);
        info.setOpaque(false);
        info.setText(
                "• SHA-256 was engineered to be FAST:\n" +
                "  SHA-256 is intended for file integrity verification, digital signatures, and blockchain validation. Modern consumer GPUs (like an RTX 4090) can compute over 10 Billion SHA-256 hashes per second!\n\n" +
                "• The Vulnerability of Fast Hashes:\n" +
                "  Because SHA-256 takes negligible compute power, an attacker who steals a database of unsalted SHA-256 hashes can crack billions of passwords via rainbow tables or brute-force in a matter of hours.\n\n" +
                "• The Industry Standard Solution:\n" +
                "  1. Unique Cryptographic Salt: Prevents precomputed rainbow table attacks.\n" +
                "  2. Heavy Cost Parameters: Use dedicated password key-derivation algorithms such as Argon2id (modern winner of Password Hashing Competition), bcrypt, or PBKDF2WithHmacSHA256 with 600,000+ iterations."
        );

        card.add(title, BorderLayout.NORTH);
        card.add(info, BorderLayout.CENTER);
        return card;
    }

    private void computeHash() {
        String input = inputField.getText();
        String hexHash = calculateSHA256(input);
        hashOutputField.setText(hexHash);
        sessionStats.recordHashingTest();
    }

    /**
     * Computes the SHA-256 hex digest using standard MessageDigest.
     */
    public static String calculateSHA256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available in Java runtime", e);
        }
    }

    private void runDeterminismDemo() {
        String input = inputField.getText();
        if (input.isEmpty()) input = "SampleSecret";

        StringBuilder sb = new StringBuilder();
        sb.append("=== DEMO 1: DETERMINISM PROPERTY ===\n");
        sb.append("Property: For any given input X, hash(X) will ALWAYS yield the exact same digest.\n");
        sb.append("Input string: '").append(input).append("'\n\n");

        for (int i = 1; i <= 4; i++) {
            String digest = calculateSHA256(input);
            sb.append(" Run #").append(i).append(": ").append(digest).append("\n");
        }
        sb.append("\nResult: All digests are 100% identical. The hash function has zero randomness on its own.\n\n");

        demonstrationLogArea.setText(sb.toString());
        demonstrationLogArea.setCaretPosition(0);
        sessionStats.recordHashingTest();
    }

    private void runAvalancheDemo() {
        String s1 = "Password123";
        String s2 = "password123"; // 1 character case change
        String s3 = "Password124"; // 1 digit change

        String h1 = calculateSHA256(s1);
        String h2 = calculateSHA256(s2);
        String h3 = calculateSHA256(s3);

        StringBuilder sb = new StringBuilder();
        sb.append("=== DEMO 2: AVALANCHE EFFECT (Strict Avalanche Criterion) ===\n");
        sb.append("A good cryptographic hash ensures that changing just 1 bit in the input causes\n");
        sb.append("approximately 50% of the output bits to change unpredictably.\n\n");

        sb.append("1. Input '").append(s1).append("':\n   -> ").append(h1).append("\n\n");
        sb.append("2. Input '").append(s2).append("' (Changed 'P' to 'p'):\n   -> ").append(h2).append("\n\n");
        sb.append("3. Input '").append(s3).append("' (Changed '3' to '4'):\n   -> ").append(h3).append("\n\n");
        sb.append("Takeaway: There is no correlation between the inputs and outputs; small changes scramble the digest.\n\n");

        demonstrationLogArea.setText(sb.toString());
        demonstrationLogArea.setCaretPosition(0);
        sessionStats.recordHashingTest();
    }

    private void runSaltDemo() {
        String pwd = "password123";
        SecureRandom random = new SecureRandom();

        byte[] salt1 = new byte[8];
        byte[] salt2 = new byte[8];
        random.nextBytes(salt1);
        random.nextBytes(salt2);

        String hexSalt1 = bytesToHex(salt1);
        String hexSalt2 = bytesToHex(salt2);

        String salted1 = calculateSHA256(hexSalt1 + pwd);
        String salted2 = calculateSHA256(hexSalt2 + pwd);
        String unsalted = calculateSHA256(pwd);

        StringBuilder sb = new StringBuilder();
        sb.append("=== DEMO 3: HOW SALTING PREVENTS RAINBOW TABLES ===\n");
        sb.append("Password: '").append(pwd).append("'\n\n");
        sb.append("• Unsalted SHA-256:\n  -> ").append(unsalted).append(" (Found in precomputed tables!)\n\n");
        sb.append("• User Alice (Salt: ").append(hexSalt1).append("):\n  -> ").append(salted1).append("\n\n");
        sb.append("• User Bob   (Salt: ").append(hexSalt2).append("):\n  -> ").append(salted2).append("\n\n");
        sb.append("Takeaway: Even though Alice and Bob have the EXACT SAME password, their stored hashes\n");
        sb.append("are completely different! Attackers cannot crack them both simultaneously in a batch.\n\n");

        demonstrationLogArea.setText(sb.toString());
        demonstrationLogArea.setCaretPosition(0);
        sessionStats.recordHashingTest();
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
