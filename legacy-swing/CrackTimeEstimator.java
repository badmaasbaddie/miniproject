package passwordsecurity;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.math.BigInteger;

/**
 * Module 9: Password Crack-Time Estimator
 * Compares the theoretical search space and estimated brute-force times
 * between different passwords across configurable hypothetical guessing rates.
 * Uses BigInteger to prevent integer overflow for astronomically large keyspaces.
 */
public class CrackTimeEstimator extends JPanel {

    // Guessing rate presets (guesses per second)
    private static final String[] RATE_NAMES = {
            "Online Web Service (Rate Limited: 10 guesses/sec)",
            "Standard Single CPU Script (100,000 guesses/sec)",
            "Fast GPU Rig - MD5/SHA256 (10 Billion guesses/sec)",
            "Massive GPU Cluster (1 Trillion guesses/sec)",
            "Heavy KDF - Argon2id / bcrypt (1,000 guesses/sec)"
    };

    private static final BigInteger[] RATE_VALUES = {
            BigInteger.valueOf(10L),
            BigInteger.valueOf(100_000L),
            BigInteger.valueOf(10_000_000_000L),
            BigInteger.valueOf(1_000_000_000_000L),
            BigInteger.valueOf(1_000L)
    };

    // UI Components
    private JTextField password1Field;
    private JTextField password2Field;
    private JComboBox<String> rateComboBox;

    // Password 1 outputs
    private JLabel p1LengthLabel;
    private JLabel p1PoolLabel;
    private JLabel p1CombinationsLabel;
    private JLabel p1AvgTimeLabel;
    private JLabel p1MaxTimeLabel;

    // Password 2 outputs
    private JLabel p2LengthLabel;
    private JLabel p2PoolLabel;
    private JLabel p2CombinationsLabel;
    private JLabel p2AvgTimeLabel;
    private JLabel p2MaxTimeLabel;

    // Multiplier comparison summary
    private JLabel comparisonSummaryLabel;

    public CrackTimeEstimator() {
        setLayout(new BorderLayout());
        setBackground(UITheme.CONTENT_BG);
        setBorder(new EmptyBorder(20, 24, 20, 24));

        initUI();
    }

    private void initUI() {
        // Header
        JPanel headerPanel = UITheme.createHeader(
                "Module 9: Password Crack-Time Estimator",
                "Compare theoretical search spaces and hypothetical brute-force cracking times side-by-side"
        );
        add(headerPanel, BorderLayout.NORTH);

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setOpaque(false);

        // 1. Inputs & Configuration Card
        mainPanel.add(createInputCard());
        mainPanel.add(Box.createVerticalStrut(16));

        // 2. Side-by-Side Comparison Card
        mainPanel.add(createComparisonCard());
        mainPanel.add(Box.createVerticalStrut(16));

        // 3. Educational Explanation Card
        mainPanel.add(createExplanationCard());

        JScrollPane scrollPane = new JScrollPane(mainPanel);
        scrollPane.setBorder(null);
        scrollPane.setOpaque(false);
        scrollPane.getViewport().setOpaque(false);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);

        add(scrollPane, BorderLayout.CENTER);

        // Initial calculation
        calculateComparison();
    }

    private JPanel createInputCard() {
        JPanel card = UITheme.createCard();
        card.setLayout(new BorderLayout(0, 12));

        JLabel titleLbl = new JLabel("Configure Passwords and Attack Hardware");
        titleLbl.setFont(UITheme.FONT_SECTION);
        titleLbl.setForeground(UITheme.TEXT_PRIMARY);

        JPanel formGrid = new JPanel(new GridLayout(3, 2, 16, 10));
        formGrid.setOpaque(false);

        // Password 1
        JLabel p1Lbl = new JLabel("Sample Password 1 (e.g. Standard):");
        p1Lbl.setFont(UITheme.FONT_BODY_BOLD);
        password1Field = new JTextField("student2024");
        password1Field.setFont(UITheme.FONT_MONO);

        // Password 2
        JLabel p2Lbl = new JLabel("Sample Password 2 (e.g. Robust):");
        p2Lbl.setFont(UITheme.FONT_BODY_BOLD);
        password2Field = new JTextField("Falcon#98!Galaxy");
        password2Field.setFont(UITheme.FONT_MONO);

        // Guessing Rate
        JLabel rateLbl = new JLabel("Hypothetical Guessing Speed:");
        rateLbl.setFont(UITheme.FONT_BODY_BOLD);
        rateComboBox = new JComboBox<>(RATE_NAMES);
        rateComboBox.setFont(UITheme.FONT_BODY);
        rateComboBox.setSelectedIndex(2); // Fast GPU Rig default

        formGrid.add(p1Lbl);
        formGrid.add(password1Field);
        formGrid.add(p2Lbl);
        formGrid.add(password2Field);
        formGrid.add(rateLbl);
        formGrid.add(rateComboBox);

        // Action Row
        JPanel actionRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        actionRow.setOpaque(false);

        JButton calcBtn = UITheme.createButton("Calculate & Compare", UITheme.PRIMARY_BLUE, Color.WHITE);
        calcBtn.addActionListener(e -> calculateComparison());

        JButton preset1Btn = UITheme.createButton("Preset: 8-char vs 12-char", UITheme.SIDEBAR_HOVER, Color.WHITE);
        preset1Btn.setFont(UITheme.FONT_SMALL);
        preset1Btn.addActionListener(e -> {
            password1Field.setText("summer99");
            password2Field.setText("Summer#99!Peak");
            calculateComparison();
        });

        JButton preset2Btn = UITheme.createButton("Preset: PIN vs Diceware", UITheme.SIDEBAR_HOVER, Color.WHITE);
        preset2Btn.setFont(UITheme.FONT_SMALL);
        preset2Btn.addActionListener(e -> {
            password1Field.setText("482910");
            password2Field.setText("correct-horse-battery-staple");
            calculateComparison();
        });

        actionRow.add(calcBtn);
        actionRow.add(preset1Btn);
        actionRow.add(preset2Btn);

        card.add(titleLbl, BorderLayout.NORTH);
        card.add(formGrid, BorderLayout.CENTER);
        card.add(actionRow, BorderLayout.SOUTH);

        return card;
    }

    private JPanel createComparisonCard() {
        JPanel card = UITheme.createCard();
        card.setLayout(new BorderLayout(0, 14));

        JLabel title = new JLabel("Side-by-Side Mathematical Comparison");
        title.setFont(UITheme.FONT_SECTION);
        title.setForeground(UITheme.TEXT_PRIMARY);

        JPanel grid = new JPanel(new GridLayout(1, 2, 20, 0));
        grid.setOpaque(false);

        // Column 1: Password 1
        JPanel col1 = createColumnCard("Password 1 Results", new Color(239, 246, 255));
        p1LengthLabel = createMetricLabel("Length: -");
        p1PoolLabel = createMetricLabel("Character Pool Size (R): -");
        p1CombinationsLabel = createMetricLabel("Total Combinations (R^L): -");
        p1AvgTimeLabel = createMetricLabel("Avg Crack Time (50%): -");
        p1MaxTimeLabel = createMetricLabel("Worst-Case Time (100%): -");

        addMetricsToColumn(col1, p1LengthLabel, p1PoolLabel, p1CombinationsLabel, p1AvgTimeLabel, p1MaxTimeLabel);

        // Column 2: Password 2
        JPanel col2 = createColumnCard("Password 2 Results", new Color(240, 253, 244));
        p2LengthLabel = createMetricLabel("Length: -");
        p2PoolLabel = createMetricLabel("Character Pool Size (R): -");
        p2CombinationsLabel = createMetricLabel("Total Combinations (R^L): -");
        p2AvgTimeLabel = createMetricLabel("Avg Crack Time (50%): -");
        p2MaxTimeLabel = createMetricLabel("Worst-Case Time (100%): -");

        addMetricsToColumn(col2, p2LengthLabel, p2PoolLabel, p2CombinationsLabel, p2AvgTimeLabel, p2MaxTimeLabel);

        grid.add(col1);
        grid.add(col2);

        // Summary Banner
        JPanel summaryPanel = new JPanel(new BorderLayout());
        summaryPanel.setBackground(new Color(241, 245, 249));
        summaryPanel.setBorder(new EmptyBorder(10, 14, 10, 14));

        comparisonSummaryLabel = new JLabel("Calculating comparative strength...");
        comparisonSummaryLabel.setFont(UITheme.FONT_BODY_BOLD);
        comparisonSummaryLabel.setForeground(UITheme.PRIMARY_BLUE);
        summaryPanel.add(comparisonSummaryLabel, BorderLayout.CENTER);

        card.add(title, BorderLayout.NORTH);
        card.add(grid, BorderLayout.CENTER);
        card.add(summaryPanel, BorderLayout.SOUTH);

        return card;
    }

    private JPanel createColumnCard(String title, Color bgColor) {
        JPanel col = new JPanel();
        col.setLayout(new BoxLayout(col, BoxLayout.Y_AXIS));
        col.setBackground(bgColor);
        col.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(UITheme.CARD_BORDER, 1),
                new EmptyBorder(12, 14, 12, 14)
        ));

        JLabel titleLbl = new JLabel(title);
        titleLbl.setFont(UITheme.FONT_BODY_BOLD);
        titleLbl.setForeground(UITheme.TEXT_PRIMARY);

        col.add(titleLbl);
        col.add(Box.createVerticalStrut(8));
        return col;
    }

    private void addMetricsToColumn(JPanel col, JLabel... labels) {
        for (JLabel lbl : labels) {
            col.add(lbl);
            col.add(Box.createVerticalStrut(6));
        }
    }

    private JLabel createMetricLabel(String text) {
        JLabel lbl = new JLabel(text);
        lbl.setFont(UITheme.FONT_BODY);
        lbl.setForeground(UITheme.TEXT_PRIMARY);
        return lbl;
    }

    private JPanel createExplanationCard() {
        JPanel card = UITheme.createCard();
        card.setLayout(new BorderLayout(0, 8));

        JLabel title = new JLabel("Key Real-World Principles & Educational Assumptions");
        title.setFont(UITheme.FONT_SECTION);
        title.setForeground(UITheme.TEXT_PRIMARY);

        JTextArea explanationText = new JTextArea();
        explanationText.setFont(UITheme.FONT_BODY);
        explanationText.setEditable(false);
        explanationText.setLineWrap(true);
        explanationText.setWrapStyleWord(true);
        explanationText.setOpaque(false);
        explanationText.setText(
                "1. Theoretical Keyspace (R^L):\n" +
                "   Pure mathematical brute force assumes testing every combination sequentially. Adding characters causes exponential growth (O(R^L)), whereas expanding the character set causes polynomial growth.\n\n" +
                "2. Why Real Attacks Are Often Faster:\n" +
                "   Attackers do NOT test combinations at random. They use dictionary attacks, Markov chain models, mask attacks, and leaked password patterns (e.g. capital first letter + year at the end).\n\n" +
                "3. Why Proper Password Hashing Protects Users:\n" +
                "   Fast general-purpose hashes like MD5 and SHA-256 can be tested at 10+ Billion guesses/second on modern GPUs. Modern key-derivation functions (Argon2id, bcrypt, PBKDF2) intentionally consume heavy memory and CPU cycles, cutting guessing speeds down to under 1,000 attempts/second per GPU."
        );

        card.add(title, BorderLayout.NORTH);
        card.add(explanationText, BorderLayout.CENTER);
        return card;
    }

    /**
     * Executes comparative calculation using BigInteger.
     */
    public void calculateComparison() {
        String p1 = password1Field.getText();
        String p2 = password2Field.getText();

        if (p1 == null) p1 = "";
        if (p2 == null) p2 = "";

        int rateIndex = rateComboBox.getSelectedIndex();
        if (rateIndex < 0 || rateIndex >= RATE_VALUES.length) rateIndex = 2;
        BigInteger rate = RATE_VALUES[rateIndex];

        // Analyze P1
        AnalysisResult r1 = evaluatePassword(p1, rate);
        p1LengthLabel.setText("• Length: " + r1.length + " characters");
        p1PoolLabel.setText("• Character Pool Size (R): " + r1.poolSize + " chars");
        p1CombinationsLabel.setText("• Combinations (R^L): " + formatBigInteger(r1.combinations));
        p1AvgTimeLabel.setText("• Average Time (50%): " + r1.avgTimeStr);
        p1MaxTimeLabel.setText("• Worst-Case Time (100%): " + r1.maxTimeStr);

        // Analyze P2
        AnalysisResult r2 = evaluatePassword(p2, rate);
        p2LengthLabel.setText("• Length: " + r2.length + " characters");
        p2PoolLabel.setText("• Character Pool Size (R): " + r2.poolSize + " chars");
        p2CombinationsLabel.setText("• Combinations (R^L): " + formatBigInteger(r2.combinations));
        p2AvgTimeLabel.setText("• Average Time (50%): " + r2.avgTimeStr);
        p2MaxTimeLabel.setText("• Worst-Case Time (100%): " + r2.maxTimeStr);

        // Compute multiplier comparison
        if (r1.combinations.compareTo(BigInteger.ZERO) > 0 && r2.combinations.compareTo(BigInteger.ZERO) > 0) {
            if (r2.combinations.compareTo(r1.combinations) >= 0) {
                BigInteger diff = r2.combinations.divide(r1.combinations);
                comparisonSummaryLabel.setText("💡 Insight: Password 2 has ~" + formatBigInteger(diff) + " times more combinations than Password 1.");
            } else {
                BigInteger diff = r1.combinations.divide(r2.combinations);
                comparisonSummaryLabel.setText("💡 Insight: Password 1 has ~" + formatBigInteger(diff) + " times more combinations than Password 2.");
            }
        } else {
            comparisonSummaryLabel.setText("💡 Insight: Enter passwords in both fields to compare mathematical resilience.");
        }
    }

    private static class AnalysisResult {
        int length;
        int poolSize;
        BigInteger combinations;
        String avgTimeStr;
        String maxTimeStr;
    }

    private AnalysisResult evaluatePassword(String pwd, BigInteger rate) {
        AnalysisResult res = new AnalysisResult();
        res.length = pwd.length();

        if (res.length == 0) {
            res.poolSize = 0;
            res.combinations = BigInteger.ZERO;
            res.avgTimeStr = "Instant (0 s)";
            res.maxTimeStr = "Instant (0 s)";
            return res;
        }

        boolean hasLower = false, hasUpper = false, hasDigit = false, hasSymbol = false;
        for (int i = 0; i < pwd.length(); i++) {
            char c = pwd.charAt(i);
            if (Character.isLowerCase(c)) hasLower = true;
            else if (Character.isUpperCase(c)) hasUpper = true;
            else if (Character.isDigit(c)) hasDigit = true;
            else hasSymbol = true;
        }

        int pool = 0;
        if (hasLower) pool += 26;
        if (hasUpper) pool += 26;
        if (hasDigit) pool += 10;
        if (hasSymbol) pool += 33;
        res.poolSize = pool;

        try {
            res.combinations = BigInteger.valueOf(pool).pow(res.length);

            // Worst-case seconds = combinations / rate
            BigInteger maxSeconds = res.combinations.divide(rate);
            // Average-case seconds = (combinations / 2) / rate
            BigInteger avgSeconds = res.combinations.divide(BigInteger.valueOf(2)).divide(rate);

            res.avgTimeStr = formatDuration(avgSeconds);
            res.maxTimeStr = formatDuration(maxSeconds);
        } catch (Exception e) {
            res.combinations = BigInteger.valueOf(Long.MAX_VALUE);
            res.avgTimeStr = "> 1 Trillion Years";
            res.maxTimeStr = "> 1 Trillion Years";
        }

        return res;
    }

    private String formatDuration(BigInteger seconds) {
        if (seconds.compareTo(BigInteger.ZERO) == 0) {
            return "< 1 millisecond";
        }
        if (seconds.compareTo(BigInteger.valueOf(60)) < 0) {
            return seconds + " seconds";
        }
        if (seconds.compareTo(BigInteger.valueOf(3600)) < 0) {
            return seconds.divide(BigInteger.valueOf(60)) + " minutes";
        }
        if (seconds.compareTo(BigInteger.valueOf(86400)) < 0) {
            return seconds.divide(BigInteger.valueOf(3600)) + " hours";
        }
        if (seconds.compareTo(BigInteger.valueOf(31536000L)) < 0) {
            return seconds.divide(BigInteger.valueOf(86400)) + " days";
        }

        BigInteger years = seconds.divide(BigInteger.valueOf(31536000L));
        if (years.compareTo(BigInteger.valueOf(1000)) < 0) {
            return years + " years";
        }
        if (years.compareTo(BigInteger.valueOf(1_000_000)) < 0) {
            return years.divide(BigInteger.valueOf(1000)) + " thousand years";
        }
        if (years.compareTo(BigInteger.valueOf(1_000_000_000)) < 0) {
            return years.divide(BigInteger.valueOf(1_000_000)) + " million years";
        }
        if (years.compareTo(BigInteger.valueOf(1_000_000_000_000L)) < 0) {
            return years.divide(BigInteger.valueOf(1_000_000_000L)) + " billion years";
        }
        return "> 1 trillion years";
    }

    private String formatBigInteger(BigInteger val) {
        String s = val.toString();
        if (s.length() <= 12) {
            return String.format("%,d", val);
        }
        // Scientific notation for enormous numbers
        char first = s.charAt(0);
        String decimals = s.substring(1, Math.min(4, s.length()));
        int exponent = s.length() - 1;
        return first + "." + decimals + " × 10^" + exponent;
    }
}
