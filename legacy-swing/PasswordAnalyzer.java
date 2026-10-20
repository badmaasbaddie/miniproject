package passwordsecurity;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Module 1: Password Strength Analyzer
 * Evaluates password strength based on length, character set diversity, entropy,
 * and common weak patterns (sequential characters, repetition, dictionary words).
 * 
 * IMPORTANT: Passwords are never logged, stored, or transmitted.
 */
public class PasswordAnalyzer extends JPanel {

    private final SessionStats sessionStats;

    // UI Components
    private JPasswordField passwordField;
    private JCheckBox showPasswordCheckBox;
    private JLabel scoreLabel;
    private JProgressBar scoreProgressBar;
    private JLabel strengthBadge;
    private JLabel entropyLabel;
    private JLabel crackTimeLabel;

    // Checklist Labels
    private JLabel lengthCheckLabel;
    private JLabel upperCheckLabel;
    private JLabel lowerCheckLabel;
    private JLabel digitCheckLabel;
    private JLabel symbolCheckLabel;

    // Pattern Warnings Area
    private JTextArea patternWarningsArea;

    // Sample weak words for quick pattern matching
    private static final String[] COMMON_PATTERNS = {
            "password", "123456", "admin", "welcome", "qwerty", "login",
            "football", "dragon", "master", "monkey", "letmein", "princess",
            "sunshine", "shadow", "computer", "iloveyou"
    };

    public PasswordAnalyzer(SessionStats stats) {
        this.sessionStats = stats;

        setLayout(new BorderLayout());
        setBackground(UITheme.CONTENT_BG);
        setBorder(new EmptyBorder(20, 24, 20, 24));

        initUI();
    }

    private void initUI() {
        // Header
        JPanel headerPanel = UITheme.createHeader(
                "Module 1: Password Strength Analyzer",
                "Inspect length, character variety, information entropy, and vulnerable patterns"
        );
        add(headerPanel, BorderLayout.NORTH);

        // Content Area (Scrollable)
        JPanel contentPanel = new JPanel();
        contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.Y_AXIS));
        contentPanel.setOpaque(false);

        // 1. Input Card
        contentPanel.add(createInputCard());
        contentPanel.add(Box.createVerticalStrut(16));

        // 2. Results Summary Card
        contentPanel.add(createResultsCard());
        contentPanel.add(Box.createVerticalStrut(16));

        // 3. Detailed Criteria & Warnings Card
        contentPanel.add(createDetailsCard());
        contentPanel.add(Box.createVerticalStrut(16));

        // 4. Academic Disclaimer Card
        contentPanel.add(createDisclaimerCard());

        JScrollPane scrollPane = new JScrollPane(contentPanel);
        scrollPane.setBorder(null);
        scrollPane.setOpaque(false);
        scrollPane.getViewport().setOpaque(false);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);

        add(scrollPane, BorderLayout.CENTER);
    }

    private JPanel createInputCard() {
        JPanel card = UITheme.createCard();
        card.setLayout(new BorderLayout(0, 12));

        JLabel titleLbl = new JLabel("Enter a Password to Analyze");
        titleLbl.setFont(UITheme.FONT_SECTION);
        titleLbl.setForeground(UITheme.TEXT_PRIMARY);

        JPanel inputRow = new JPanel(new BorderLayout(10, 0));
        inputRow.setOpaque(false);

        passwordField = new JPasswordField();
        passwordField.setFont(UITheme.FONT_MONO);
        passwordField.setPreferredSize(new Dimension(350, 36));

        showPasswordCheckBox = new JCheckBox("Show Password");
        showPasswordCheckBox.setFont(UITheme.FONT_BODY);
        showPasswordCheckBox.setOpaque(false);
        showPasswordCheckBox.addActionListener(e -> {
            if (showPasswordCheckBox.isSelected()) {
                passwordField.setEchoChar((char) 0);
            } else {
                passwordField.setEchoChar('•');
            }
        });

        JButton analyzeBtn = UITheme.createButton("Analyze Password", UITheme.PRIMARY_BLUE, Color.WHITE);
        analyzeBtn.addActionListener(e -> analyzeCurrentPassword());

        JButton clearBtn = UITheme.createButton("Clear", UITheme.SIDEBAR_HOVER, Color.WHITE);
        clearBtn.addActionListener(e -> clearFields());

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        btnPanel.setOpaque(false);
        btnPanel.add(analyzeBtn);
        btnPanel.add(clearBtn);
        btnPanel.add(showPasswordCheckBox);

        inputRow.add(passwordField, BorderLayout.CENTER);
        inputRow.add(btnPanel, BorderLayout.EAST);

        // Enter key shortcut in password field
        passwordField.addActionListener(e -> analyzeCurrentPassword());

        card.add(titleLbl, BorderLayout.NORTH);
        card.add(inputRow, BorderLayout.CENTER);

        return card;
    }

    private JPanel createResultsCard() {
        JPanel card = UITheme.createCard();
        card.setLayout(new GridLayout(1, 4, 16, 0));

        // Score
        scoreLabel = new JLabel("0 / 100");
        JPanel scorePanel = createMetricBox("Numerical Score", scoreLabel);

        scoreProgressBar = new JProgressBar(0, 100);
        scoreProgressBar.setValue(0);
        scoreProgressBar.setStringPainted(true);
        scoreProgressBar.setPreferredSize(new Dimension(100, 18));
        scorePanel.add(scoreProgressBar);

        // Strength Classification
        strengthBadge = new JLabel("Awaiting Input");
        JPanel strengthPanel = createMetricBox("Strength Rating", strengthBadge);

        // Entropy
        entropyLabel = new JLabel("0.0 bits");
        JPanel entropyPanel = createMetricBox("Estimated Entropy", entropyLabel);

        // Crack Time Approximation
        crackTimeLabel = new JLabel("Instant (< 1 ms)");
        JPanel crackPanel = createMetricBox("Approx. Crack Time", crackTimeLabel);

        card.add(scorePanel);
        card.add(strengthPanel);
        card.add(entropyPanel);
        card.add(crackPanel);

        return card;
    }

    private JPanel createMetricBox(String title, JLabel valLbl) {
        JPanel box = new JPanel();
        box.setLayout(new BoxLayout(box, BoxLayout.Y_AXIS));
        box.setOpaque(false);

        JLabel titleLbl = new JLabel(title);
        titleLbl.setFont(UITheme.FONT_SMALL);
        titleLbl.setForeground(UITheme.TEXT_SECONDARY);

        valLbl.setFont(UITheme.FONT_SECTION);
        valLbl.setForeground(UITheme.TEXT_PRIMARY);

        box.add(titleLbl);
        box.add(Box.createVerticalStrut(4));
        box.add(valLbl);
        return box;
    }

    private JPanel createDetailsCard() {
        JPanel card = UITheme.createCard();
        card.setLayout(new GridLayout(1, 2, 24, 0));

        // Left column: Character Checklist
        JPanel checkListPanel = new JPanel();
        checkListPanel.setLayout(new BoxLayout(checkListPanel, BoxLayout.Y_AXIS));
        checkListPanel.setOpaque(false);

        JLabel checkListTitle = new JLabel("Character Composition Checklist");
        checkListTitle.setFont(UITheme.FONT_SECTION);
        checkListTitle.setForeground(UITheme.TEXT_PRIMARY);
        checkListPanel.add(checkListTitle);
        checkListPanel.add(Box.createVerticalStrut(10));

        lengthCheckLabel = createCheckItem("Length: 0 characters");
        upperCheckLabel = createCheckItem("Uppercase Letters (A-Z): No");
        lowerCheckLabel = createCheckItem("Lowercase Letters (a-z): No");
        digitCheckLabel = createCheckItem("Digits (0-9): No");
        symbolCheckLabel = createCheckItem("Special Characters (!@#...): No");

        checkListPanel.add(lengthCheckLabel);
        checkListPanel.add(Box.createVerticalStrut(6));
        checkListPanel.add(upperCheckLabel);
        checkListPanel.add(Box.createVerticalStrut(6));
        checkListPanel.add(lowerCheckLabel);
        checkListPanel.add(Box.createVerticalStrut(6));
        checkListPanel.add(digitCheckLabel);
        checkListPanel.add(Box.createVerticalStrut(6));
        checkListPanel.add(symbolCheckLabel);

        // Right column: Pattern Weakness Warnings
        JPanel warningsPanel = new JPanel(new BorderLayout(0, 8));
        warningsPanel.setOpaque(false);

        JLabel warningsTitle = new JLabel("Vulnerability & Pattern Analysis");
        warningsTitle.setFont(UITheme.FONT_SECTION);
        warningsTitle.setForeground(UITheme.TEXT_PRIMARY);

        patternWarningsArea = new JTextArea("Enter a password and click 'Analyze Password' to inspect vulnerabilities.");
        patternWarningsArea.setFont(UITheme.FONT_BODY);
        patternWarningsArea.setEditable(false);
        patternWarningsArea.setLineWrap(true);
        patternWarningsArea.setWrapStyleWord(true);
        patternWarningsArea.setBackground(new Color(248, 250, 252));
        patternWarningsArea.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(UITheme.CARD_BORDER, 1),
                new EmptyBorder(8, 8, 8, 8)
        ));

        warningsPanel.add(warningsTitle, BorderLayout.NORTH);
        warningsPanel.add(new JScrollPane(patternWarningsArea), BorderLayout.CENTER);

        card.add(checkListPanel);
        card.add(warningsPanel);

        return card;
    }

    private JLabel createCheckItem(String text) {
        JLabel lbl = new JLabel("• " + text);
        lbl.setFont(UITheme.FONT_BODY);
        lbl.setForeground(UITheme.TEXT_SECONDARY);
        return lbl;
    }

    private JPanel createDisclaimerCard() {
        JPanel card = UITheme.createCard();
        card.setLayout(new BorderLayout());
        card.setBackground(new Color(254, 242, 242)); // Soft red/pink
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(254, 202, 202), 1),
                new EmptyBorder(8, 12, 8, 12)
        ));

        JLabel discLabel = new JLabel("<html><b>Security Disclaimer:</b> Crack-time estimates assume a theoretical brute-force scenario attacking raw hashes at 10 Billion guesses/second. Real cracking times depend heavily on password hashing functions (like Argon2 or bcrypt with work factors), attacker hardware, and targeted wordlists. Never reuse passwords across sites.</html>");
        discLabel.setFont(UITheme.FONT_SMALL);
        discLabel.setForeground(new Color(153, 27, 27));

        card.add(discLabel, BorderLayout.CENTER);
        return card;
    }

    /**
     * Main analysis method: Evaluates the password without saving or logging it.
     */
    public void analyzeCurrentPassword() {
        char[] passwordChars = passwordField.getPassword();
        String password = new String(passwordChars);

        // Security practice: clear password array from memory when done with analysis
        java.util.Arrays.fill(passwordChars, '0');

        if (password.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter a password to analyze.", "Input Empty", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // 1. Analyze composition
        int length = password.length();
        boolean hasUpper = false;
        boolean hasLower = false;
        boolean hasDigit = false;
        boolean hasSymbol = false;

        for (int i = 0; i < length; i++) {
            char c = password.charAt(i);
            if (Character.isUpperCase(c)) hasUpper = true;
            else if (Character.isLowerCase(c)) hasLower = true;
            else if (Character.isDigit(c)) hasDigit = true;
            else hasSymbol = true; // punctuation, symbols, whitespace
        }

        // 2. Character Pool Size (R)
        int poolSize = 0;
        if (hasLower) poolSize += 26;
        if (hasUpper) poolSize += 26;
        if (hasDigit) poolSize += 10;
        if (hasSymbol) poolSize += 33; // standard ASCII printable symbols

        // 3. Entropy calculation in bits: E = L * log2(R)
        double entropy = 0.0;
        if (poolSize > 0) {
            entropy = length * (Math.log(poolSize) / Math.log(2));
        }

        // 4. Pattern vulnerability checks
        List<String> warnings = new ArrayList<>();
        String lowerPwd = password.toLowerCase();

        // Check common dictionary patterns
        for (String pattern : COMMON_PATTERNS) {
            if (lowerPwd.contains(pattern)) {
                warnings.add("Contains common weak pattern/word: '" + pattern + "'");
            }
        }

        // Check repeated consecutive characters (e.g. 'aaa', '111')
        boolean hasRepeats = false;
        for (int i = 0; i < length - 2; i++) {
            if (password.charAt(i) == password.charAt(i + 1) && password.charAt(i) == password.charAt(i + 2)) {
                hasRepeats = true;
                break;
            }
        }
        if (hasRepeats) {
            warnings.add("Contains 3 or more repeated identical characters in sequence.");
        }

        // Check sequential characters (e.g. '123', 'abc', 'cba')
        boolean hasSequential = false;
        for (int i = 0; i < length - 2; i++) {
            char c1 = password.charAt(i);
            char c2 = password.charAt(i + 1);
            char c3 = password.charAt(i + 2);
            if ((c2 == c1 + 1 && c3 == c2 + 1) || (c2 == c1 - 1 && c3 == c2 - 1)) {
                hasSequential = true;
                break;
            }
        }
        if (hasSequential) {
            warnings.add("Contains predictable sequential characters (e.g. 123, abc).");
        }

        // Check length warnings
        if (length < 8) {
            warnings.add("Password length is less than recommended minimum (8 characters).");
        }

        // 5. Numerical Score calculation (0 - 100)
        int score = 0;

        // Base points from length
        if (length >= 16) score += 40;
        else if (length >= 12) score += 30;
        else if (length >= 8) score += 20;
        else if (length >= 6) score += 10;
        else score += 2; // under 6 is very weak

        // Points for character diversity
        int varietyCount = (hasLower ? 1 : 0) + (hasUpper ? 1 : 0) + (hasDigit ? 1 : 0) + (hasSymbol ? 1 : 0);
        score += varietyCount * 10; // up to 40 points

        // Bonus for combining symbols, digits, and mixed case
        if (varietyCount >= 4 && length >= 12) {
            score += 20; // 40 + 40 + 20 = 100
        } else if (varietyCount >= 3 && length >= 10) {
            score += 10;
        }

        // Deductions for weak patterns
        if (!warnings.isEmpty()) {
            score -= (warnings.size() * 12);
        }

        // Clamp score between 0 and 100
        score = Math.max(0, Math.min(100, score));

        // 6. Classification
        String category;
        Color badgeColor;
        if (score >= 75) {
            category = "Strong";
            badgeColor = UITheme.SUCCESS_GREEN;
        } else if (score >= 45) {
            category = "Medium";
            badgeColor = UITheme.WARNING_AMBER;
        } else {
            category = "Weak";
            badgeColor = UITheme.DANGER_RED;
        }

        // 7. Theoretical combinations and Crack-Time Estimation (at 10 Billion guesses/sec)
        // N = poolSize ^ length
        String crackTimeEstimate = calculateCrackTime(poolSize, length);

        // 8. Update UI
        scoreLabel.setText(score + " / 100");
        scoreProgressBar.setValue(score);
        scoreProgressBar.setForeground(badgeColor);

        strengthBadge.setText(category);
        strengthBadge.setForeground(badgeColor);

        entropyLabel.setText(String.format("%.1f bits", entropy));
        crackTimeLabel.setText(crackTimeEstimate);

        lengthCheckLabel.setText("• Length: " + length + " characters " + (length >= 12 ? "(Excellent)" : (length >= 8 ? "(Acceptable)" : "(Too short)")));
        upperCheckLabel.setText("• Uppercase Letters (A-Z): " + (hasUpper ? "Yes (+26 pool)" : "No"));
        lowerCheckLabel.setText("• Lowercase Letters (a-z): " + (hasLower ? "Yes (+26 pool)" : "No"));
        digitCheckLabel.setText("• Digits (0-9): " + (hasDigit ? "Yes (+10 pool)" : "No"));
        symbolCheckLabel.setText("• Special Characters: " + (hasSymbol ? "Yes (+33 pool)" : "No"));

        if (warnings.isEmpty()) {
            patternWarningsArea.setText("✓ Excellent! No common weak patterns detected.\n✓ Strong character diversity and length resistance.");
            patternWarningsArea.setForeground(new Color(22, 101, 52)); // Dark green
        } else {
            StringBuilder sb = new StringBuilder();
            sb.append("⚠️ Vulnerabilities Found (").append(warnings.size()).append("):\n");
            for (String w : warnings) {
                sb.append(" • ").append(w).append("\n");
            }
            sb.append("\nTip: Make passwords longer (12+ characters) and avoid familiar words or sequences.");
            patternWarningsArea.setText(sb.toString());
            patternWarningsArea.setForeground(new Color(153, 27, 27)); // Dark red
        }

        // 9. Record non-sensitive metadata in SessionStats
        sessionStats.recordAnalysis(score, category, entropy, crackTimeEstimate);
    }

    /**
     * Calculates human-readable cracking time assuming 10,000,000,000 (10 Billion) guesses per second.
     * Uses BigInteger to prevent integer overflow.
     */
    private String calculateCrackTime(int poolSize, int length) {
        if (poolSize <= 0 || length <= 0) return "Instant";

        try {
            BigInteger pool = BigInteger.valueOf(poolSize);
            BigInteger combinations = pool.pow(length);

            // 10 Billion guesses / sec = 10^10
            BigInteger rate = BigInteger.valueOf(10_000_000_000L);
            BigInteger seconds = combinations.divide(rate);

            if (seconds.compareTo(BigInteger.ZERO) == 0) {
                return "< 1 millisecond";
            } else if (seconds.compareTo(BigInteger.valueOf(60)) < 0) {
                return seconds + " seconds";
            } else if (seconds.compareTo(BigInteger.valueOf(3600)) < 0) {
                long minutes = seconds.longValue() / 60;
                return minutes + " minutes";
            } else if (seconds.compareTo(BigInteger.valueOf(86400)) < 0) {
                long hours = seconds.longValue() / 3600;
                return hours + " hours";
            } else if (seconds.compareTo(BigInteger.valueOf(31536000L)) < 0) {
                long days = seconds.longValue() / 86400;
                return days + " days";
            } else {
                BigInteger years = seconds.divide(BigInteger.valueOf(31536000L));
                if (years.compareTo(BigInteger.valueOf(1000)) < 0) {
                    return years + " years";
                } else if (years.compareTo(BigInteger.valueOf(1_000_000)) < 0) {
                    return years.divide(BigInteger.valueOf(1000)) + " thousand years";
                } else if (years.compareTo(BigInteger.valueOf(1_000_000_000)) < 0) {
                    return years.divide(BigInteger.valueOf(1_000_000)) + " million years";
                } else {
                    return "> 1 billion years";
                }
            }
        } catch (ArithmeticException e) {
            return "Indefinite (> 10^100 years)";
        }
    }

    private void clearFields() {
        passwordField.setText("");
        scoreLabel.setText("0 / 100");
        scoreProgressBar.setValue(0);
        strengthBadge.setText("Awaiting Input");
        strengthBadge.setForeground(UITheme.TEXT_PRIMARY);
        entropyLabel.setText("0.0 bits");
        crackTimeLabel.setText("Instant (< 1 ms)");

        lengthCheckLabel.setText("• Length: 0 characters");
        upperCheckLabel.setText("• Uppercase Letters (A-Z): No");
        lowerCheckLabel.setText("• Lowercase Letters (a-z): No");
        digitCheckLabel.setText("• Digits (0-9): No");
        symbolCheckLabel.setText("• Special Characters: No");

        patternWarningsArea.setText("Enter a password and click 'Analyze Password' to inspect vulnerabilities.");
        patternWarningsArea.setForeground(UITheme.TEXT_SECONDARY);
    }
}
