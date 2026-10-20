package passwordsecurity;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.math.BigInteger;

/**
 * Module 3: Brute Force Simulation
 * Educational demonstration showing combinatorial explosion as password length
 * and character variety increase. Runs safely in local memory with a background SwingWorker.
 */
public class BruteForceSimulator extends JPanel {

    private final SessionStats sessionStats;

    // UI Inputs
    private JTextField targetField;
    private JComboBox<String> presetCombo;
    private JCheckBox checkDigits;
    private JCheckBox checkLower;
    private JCheckBox checkUpper;
    private JCheckBox checkSymbols;

    // Metrics Display
    private JLabel poolSizeLabel;
    private JLabel combinationsLabel;
    private JLabel simulatedAttemptsLabel;
    private JLabel liveCandidateLabel;
    private JLabel elapsedTimerLabel;
    private JLabel theoreticalEstimateLabel;
    private JProgressBar progressBar;

    // Control Buttons
    private JButton startBtn;
    private JButton stopBtn;
    private JButton resetBtn;

    // Simulation Worker
    private SwingWorker<Void, SimulationUpdate> activeWorker;
    private volatile boolean isRunning = false;

    // Character Sets
    private static final String DIGITS = "0123456789";
    private static final String LOWER = "abcdefghijklmnopqrstuvwxyz";
    private static final String UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String SYMBOLS = "!@#$%^&*";

    public BruteForceSimulator(SessionStats stats) {
        this.sessionStats = stats;

        setLayout(new BorderLayout());
        setBackground(UITheme.CONTENT_BG);
        setBorder(new EmptyBorder(20, 24, 20, 24));

        initUI();
    }

    private void initUI() {
        // Header
        JPanel headerPanel = UITheme.createHeader(
                "Module 3: Educational Brute Force Simulation",
                "Observe how search space scales exponentially with password length and character pool"
        );
        add(headerPanel, BorderLayout.NORTH);

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setOpaque(false);

        // 1. Setup & Config Card
        mainPanel.add(createConfigCard());
        mainPanel.add(Box.createVerticalStrut(16));

        // 2. Live Simulation Progress Card
        mainPanel.add(createProgressCard());
        mainPanel.add(Box.createVerticalStrut(16));

        // 3. Comparison & Teaching Card
        mainPanel.add(createComparisonCard());

        JScrollPane scrollPane = new JScrollPane(mainPanel);
        scrollPane.setBorder(null);
        scrollPane.setOpaque(false);
        scrollPane.getViewport().setOpaque(false);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);

        add(scrollPane, BorderLayout.CENTER);

        updateTheoreticalCombinations();
    }

    private JPanel createConfigCard() {
        JPanel card = UITheme.createCard();
        card.setLayout(new BorderLayout(0, 12));

        JLabel title = new JLabel("Simulation Target & Character Pool");
        title.setFont(UITheme.FONT_SECTION);
        title.setForeground(UITheme.TEXT_PRIMARY);

        JPanel formGrid = new JPanel(new GridLayout(2, 2, 16, 10));
        formGrid.setOpaque(false);

        // Presets
        JLabel presetLbl = new JLabel("Select Predefined Educational Example:");
        presetLbl.setFont(UITheme.FONT_BODY_BOLD);
        presetCombo = new JComboBox<>(new String[]{
                "PIN (3 Digits) -> '429'",
                "Short Word (3 Lowercase) -> 'cat'",
                "Alphanumeric (3 Chars) -> 'A9z'",
                "Word (4 Lowercase) -> 'code'",
                "Custom Input..."
        });
        presetCombo.setFont(UITheme.FONT_BODY);
        presetCombo.addActionListener(e -> onPresetSelected());

        // Target Password
        JLabel targetLbl = new JLabel("Target String (Safe Demo: 1-4 chars):");
        targetLbl.setFont(UITheme.FONT_BODY_BOLD);
        targetField = new JTextField("429");
        targetField.setFont(UITheme.FONT_MONO);
        targetField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { updateTheoreticalCombinations(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { updateTheoreticalCombinations(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { updateTheoreticalCombinations(); }
        });

        formGrid.add(presetLbl);
        formGrid.add(presetCombo);
        formGrid.add(targetLbl);
        formGrid.add(targetField);

        // Checkboxes for pool
        JPanel checkPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 16, 0));
        checkPanel.setOpaque(false);
        checkDigits = new JCheckBox("Digits 0-9 (10)", true);
        checkLower = new JCheckBox("Lowercase a-z (26)", false);
        checkUpper = new JCheckBox("Uppercase A-Z (26)", false);
        checkSymbols = new JCheckBox("Special Symbols (8)", false);

        checkDigits.addActionListener(e -> updateTheoreticalCombinations());
        checkLower.addActionListener(e -> updateTheoreticalCombinations());
        checkUpper.addActionListener(e -> updateTheoreticalCombinations());
        checkSymbols.addActionListener(e -> updateTheoreticalCombinations());

        checkPanel.add(checkDigits);
        checkPanel.add(checkLower);
        checkPanel.add(checkUpper);
        checkPanel.add(checkSymbols);

        // Buttons
        JPanel actionRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        actionRow.setOpaque(false);

        startBtn = UITheme.createButton("▶ Start Simulation", UITheme.PRIMARY_BLUE, Color.WHITE);
        startBtn.addActionListener(e -> startSimulation());

        stopBtn = UITheme.createButton("⏹ Stop", UITheme.DANGER_RED, Color.WHITE);
        stopBtn.setEnabled(false);
        stopBtn.addActionListener(e -> stopSimulation());

        resetBtn = UITheme.createButton("Reset", UITheme.SIDEBAR_HOVER, Color.WHITE);
        resetBtn.addActionListener(e -> resetSimulation());

        actionRow.add(startBtn);
        actionRow.add(stopBtn);
        actionRow.add(resetBtn);

        JPanel centerContainer = new JPanel(new BorderLayout(0, 10));
        centerContainer.setOpaque(false);
        centerContainer.add(formGrid, BorderLayout.NORTH);
        centerContainer.add(checkPanel, BorderLayout.SOUTH);

        card.add(title, BorderLayout.NORTH);
        card.add(centerContainer, BorderLayout.CENTER);
        card.add(actionRow, BorderLayout.SOUTH);

        return card;
    }

    private JPanel createProgressCard() {
        JPanel card = UITheme.createCard();
        card.setLayout(new BorderLayout(0, 12));

        JLabel title = new JLabel("Live Simulation Monitor");
        title.setFont(UITheme.FONT_SECTION);
        title.setForeground(UITheme.TEXT_PRIMARY);

        GridLayout metricsGrid = new GridLayout(2, 3, 16, 12);
        JPanel gridPanel = new JPanel(metricsGrid);
        gridPanel.setOpaque(false);

        poolSizeLabel = new JLabel("Pool Size (R): 10");
        poolSizeLabel.setFont(UITheme.FONT_BODY_BOLD);

        combinationsLabel = new JLabel("Combinations: 1,000");
        combinationsLabel.setFont(UITheme.FONT_BODY_BOLD);

        theoreticalEstimateLabel = new JLabel("Est. at 10M/s: < 1 ms");
        theoreticalEstimateLabel.setFont(UITheme.FONT_BODY);

        simulatedAttemptsLabel = new JLabel("Attempts Tested: 0");
        simulatedAttemptsLabel.setFont(UITheme.FONT_BODY_BOLD);
        simulatedAttemptsLabel.setForeground(UITheme.PRIMARY_BLUE);

        liveCandidateLabel = new JLabel("Testing: [Waiting]");
        liveCandidateLabel.setFont(UITheme.FONT_MONO_BOLD);
        liveCandidateLabel.setForeground(UITheme.PURPLE_ACCENT);

        elapsedTimerLabel = new JLabel("Elapsed: 0.00 s");
        elapsedTimerLabel.setFont(UITheme.FONT_BODY);

        gridPanel.add(poolSizeLabel);
        gridPanel.add(combinationsLabel);
        gridPanel.add(theoreticalEstimateLabel);
        gridPanel.add(simulatedAttemptsLabel);
        gridPanel.add(liveCandidateLabel);
        gridPanel.add(elapsedTimerLabel);

        // Progress bar
        progressBar = new JProgressBar(0, 100);
        progressBar.setValue(0);
        progressBar.setStringPainted(true);
        progressBar.setPreferredSize(new Dimension(100, 22));

        card.add(title, BorderLayout.NORTH);
        card.add(gridPanel, BorderLayout.CENTER);
        card.add(progressBar, BorderLayout.SOUTH);

        return card;
    }

    private JPanel createComparisonCard() {
        JPanel card = UITheme.createCard();
        card.setLayout(new BorderLayout(0, 8));

        JLabel title = new JLabel("Why Brute Force Fails Against Strong Passwords");
        title.setFont(UITheme.FONT_SECTION);
        title.setForeground(UITheme.TEXT_PRIMARY);

        JTextArea explanation = new JTextArea();
        explanation.setFont(UITheme.FONT_BODY);
        explanation.setEditable(false);
        explanation.setLineWrap(true);
        explanation.setWrapStyleWord(true);
        explanation.setOpaque(false);
        explanation.setText(
                "• 3-character PIN ('429'):\n" +
                "  Pool = 10 digits. Total combinations = 10^3 = 1,000 attempts.\n" +
                "  Can be broken in less than 0.001 seconds on any basic laptop.\n\n" +
                "• 4-character word ('code'):\n" +
                "  Pool = 26 lowercase letters. Total combinations = 26^4 = 456,976 attempts.\n" +
                "  Takes a few seconds on a CPU, or a fraction of a millisecond on a GPU.\n\n" +
                "• 8-character mixed ('Summer99'):\n" +
                "  Pool = 62 (lower + upper + digits). Total combinations = 62^8 ≈ 218 Trillion combinations.\n" +
                "  Takes hours to days on high-end hardware.\n\n" +
                "• 12-character strong ('S#99!Peak&Fox'):\n" +
                "  Pool = 95 printable characters. Total combinations = 95^12 ≈ 5.4 × 10^23 combinations.\n" +
                "  Takes over 1.7 Million years even on clusters testing 10 Billion guesses per second!"
        );

        card.add(title, BorderLayout.NORTH);
        card.add(explanation, BorderLayout.CENTER);
        return card;
    }

    private void onPresetSelected() {
        int idx = presetCombo.getSelectedIndex();
        if (idx == 0) { // 3 digits
            targetField.setText("429");
            checkDigits.setSelected(true);
            checkLower.setSelected(false);
            checkUpper.setSelected(false);
            checkSymbols.setSelected(false);
        } else if (idx == 1) { // 3 lower
            targetField.setText("cat");
            checkDigits.setSelected(false);
            checkLower.setSelected(true);
            checkUpper.setSelected(false);
            checkSymbols.setSelected(false);
        } else if (idx == 2) { // 3 alphanumeric
            targetField.setText("A9z");
            checkDigits.setSelected(true);
            checkLower.setSelected(true);
            checkUpper.setSelected(true);
            checkSymbols.setSelected(false);
        } else if (idx == 3) { // 4 lower
            targetField.setText("code");
            checkDigits.setSelected(false);
            checkLower.setSelected(true);
            checkUpper.setSelected(false);
            checkSymbols.setSelected(false);
        }
        updateTheoreticalCombinations();
    }

    private String buildActivePool() {
        StringBuilder sb = new StringBuilder();
        if (checkDigits.isSelected()) sb.append(DIGITS);
        if (checkLower.isSelected()) sb.append(LOWER);
        if (checkUpper.isSelected()) sb.append(UPPER);
        if (checkSymbols.isSelected()) sb.append(SYMBOLS);
        return sb.toString();
    }

    private void updateTheoreticalCombinations() {
        String target = targetField.getText();
        String pool = buildActivePool();
        int poolSize = pool.length();
        int length = target.length();

        poolSizeLabel.setText("Pool Size (R): " + poolSize + " chars");

        if (poolSize == 0 || length == 0) {
            combinationsLabel.setText("Combinations: 0");
            theoreticalEstimateLabel.setText("Est. at 10M/s: Instant");
            return;
        }

        try {
            BigInteger poolBig = BigInteger.valueOf(poolSize);
            BigInteger totalCombos = poolBig.pow(length);

            combinationsLabel.setText("Combinations: " + formatBigInt(totalCombos));

            // Estimate at 10,000,000/sec
            BigInteger rate = BigInteger.valueOf(10_000_000L);
            BigInteger seconds = totalCombos.divide(rate);
            if (seconds.compareTo(BigInteger.ZERO) == 0) {
                theoreticalEstimateLabel.setText("Est. at 10M/s: < 1 ms");
            } else if (seconds.compareTo(BigInteger.valueOf(60)) < 0) {
                theoreticalEstimateLabel.setText("Est. at 10M/s: " + seconds + " sec");
            } else if (seconds.compareTo(BigInteger.valueOf(3600)) < 0) {
                theoreticalEstimateLabel.setText("Est. at 10M/s: " + seconds.divide(BigInteger.valueOf(60)) + " min");
            } else {
                theoreticalEstimateLabel.setText("Est. at 10M/s: > 1 hour");
            }
        } catch (Exception e) {
            combinationsLabel.setText("Combinations: Overflow");
            theoreticalEstimateLabel.setText("Est. at 10M/s: > Century");
        }
    }

    private String formatBigInt(BigInteger val) {
        String s = val.toString();
        if (s.length() <= 9) {
            return String.format("%,d", val);
        }
        return s.charAt(0) + "." + s.substring(1, Math.min(4, s.length())) + " × 10^" + (s.length() - 1);
    }

    private void startSimulation() {
        final String target = targetField.getText();
        final String pool = buildActivePool();

        if (target.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter a target string for the simulation.", "Missing Target", JOptionPane.WARNING_MESSAGE);
            return;
        }
        if (pool.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please select at least one character set in the pool.", "Missing Pool", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Validate that target characters exist in active pool
        for (int i = 0; i < target.length(); i++) {
            char c = target.charAt(i);
            if (pool.indexOf(c) == -1) {
                JOptionPane.showMessageDialog(this,
                        "Target character '" + c + "' is not present in the selected character pool.\n" +
                        "Please enable the appropriate checkbox (Digits, Lowercase, Uppercase, or Symbols).",
                        "Character Pool Mismatch", JOptionPane.WARNING_MESSAGE);
                return;
            }
        }

        if (target.length() > 5) {
            int resp = JOptionPane.showConfirmDialog(this,
                    "Target is " + target.length() + " characters long. Pure brute force on this laptop will take millions of cycles.\n" +
                    "Do you wish to run a capped demonstration (up to 50,000 attempts)?",
                    "Large Search Space Notice", JOptionPane.YES_NO_OPTION);
            if (resp != JOptionPane.YES_OPTION) return;
        }

        isRunning = true;
        startBtn.setEnabled(false);
        stopBtn.setEnabled(true);
        resetBtn.setEnabled(false);
        progressBar.setValue(0);

        final long startTime = System.currentTimeMillis();

        activeWorker = new SwingWorker<Void, SimulationUpdate>() {
            private boolean matchFound = false;
            private long attempts = 0;
            private final long maxAttempts = (target.length() > 4) ? 50_000 : 500_000;

            @Override
            protected Void doInBackground() throws Exception {
                // Brute force permutations generator up to target length
                int targetLen = target.length();
                char[] current = new char[targetLen];

                generateRecursive(current, 0, pool, target);
                return null;
            }

            private boolean generateRecursive(char[] current, int pos, String pool, String target) {
                if (!isRunning || matchFound || attempts >= maxAttempts) {
                    return true;
                }

                if (pos == current.length) {
                    attempts++;
                    String candidate = new String(current);

                    if (candidate.equals(target)) {
                        matchFound = true;
                        publish(new SimulationUpdate(attempts, candidate, true));
                        return true;
                    }

                    // Throttle GUI updates every 150 attempts to maintain smooth 60fps rendering
                    if (attempts % 150 == 0) {
                        publish(new SimulationUpdate(attempts, candidate, false));
                        // Yield small slice so UI remains interactive
                        try { Thread.sleep(1); } catch (InterruptedException ignored) {}
                    }
                    return false;
                }

                for (int i = 0; i < pool.length(); i++) {
                    if (!isRunning || matchFound || attempts >= maxAttempts) return true;
                    current[pos] = pool.charAt(i);
                    if (generateRecursive(current, pos + 1, pool, target)) {
                        return true;
                    }
                }
                return false;
            }

            @Override
            protected void process(java.util.List<SimulationUpdate> chunks) {
                if (chunks.isEmpty()) return;
                SimulationUpdate latest = chunks.get(chunks.size() - 1);

                simulatedAttemptsLabel.setText("Attempts Tested: " + String.format("%,d", latest.attempts));
                liveCandidateLabel.setText("Testing: '" + latest.candidate + "'");

                double elapsedSec = (System.currentTimeMillis() - startTime) / 1000.0;
                elapsedTimerLabel.setText(String.format("Elapsed: %.2f s", elapsedSec));

                // Rough progress calculation
                BigInteger totalCombos = BigInteger.valueOf(pool.length()).pow(target.length());
                if (totalCombos.compareTo(BigInteger.ZERO) > 0) {
                    double pct = (double) latest.attempts / totalCombos.doubleValue() * 100.0;
                    progressBar.setValue((int) Math.min(100, pct));
                }
            }

            @Override
            protected void done() {
                isRunning = false;
                startBtn.setEnabled(true);
                stopBtn.setEnabled(false);
                resetBtn.setEnabled(true);

                double elapsedSec = (System.currentTimeMillis() - startTime) / 1000.0;
                elapsedTimerLabel.setText(String.format("Elapsed: %.2f s", elapsedSec));

                sessionStats.recordBruteForceSimulation();

                if (matchFound) {
                    progressBar.setValue(100);
                    liveCandidateLabel.setText("MATCH FOUND: '" + target + "'!");
                    liveCandidateLabel.setForeground(UITheme.SUCCESS_GREEN);
                    JOptionPane.showMessageDialog(BruteForceSimulator.this,
                            "Simulation Complete!\n\nTarget password '" + target + "' found after " +
                            String.format("%,d", attempts) + " attempts in " + String.format("%.2f", elapsedSec) + " seconds.",
                            "Match Found", JOptionPane.INFORMATION_MESSAGE);
                } else if (attempts >= maxAttempts) {
                    JOptionPane.showMessageDialog(BruteForceSimulator.this,
                            "Simulation capped at " + String.format("%,d", maxAttempts) + " attempts.\n" +
                            "This demonstrates why longer passwords are mathematically resilient to brute-force guessing.",
                            "Simulation Limit Reached", JOptionPane.WARNING_MESSAGE);
                }
            }
        };

        activeWorker.execute();
    }

    private void stopSimulation() {
        isRunning = false;
        if (activeWorker != null && !activeWorker.isDone()) {
            activeWorker.cancel(true);
        }
        startBtn.setEnabled(true);
        stopBtn.setEnabled(false);
        resetBtn.setEnabled(true);
        liveCandidateLabel.setText("Testing: [Stopped by User]");
    }

    private void resetSimulation() {
        stopSimulation();
        simulatedAttemptsLabel.setText("Attempts Tested: 0");
        liveCandidateLabel.setText("Testing: [Waiting]");
        liveCandidateLabel.setForeground(UITheme.PURPLE_ACCENT);
        elapsedTimerLabel.setText("Elapsed: 0.00 s");
        progressBar.setValue(0);
        updateTheoreticalCombinations();
    }

    private static class SimulationUpdate {
        final long attempts;
        final String candidate;
        final boolean matched;

        SimulationUpdate(long attempts, String candidate, boolean matched) {
            this.attempts = attempts;
            this.candidate = candidate;
            this.matched = matched;
        }
    }
}
