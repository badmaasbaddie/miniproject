package passwordsecurity;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

/**
 * Module 6: Educational Hash Matching Demo
 * Demonstrates how offline hash cracking works by pre-computing candidate hashes
 * and matching against target digests. Emphasizes that hashes are one-way functions,
 * and matching is forward-guessing rather than mathematical reversal.
 */
public class HashMatchingDemo extends JPanel {

    private final SessionStats sessionStats;

    // Predefined Educational Target Hashes (Stored strictly as digests, simulating a leaked database)
    private static class SampleTarget {
        final String label;
        final String sha256Hex;
        final String note;

        SampleTarget(String label, String sha256Hex, String note) {
            this.label = label;
            this.sha256Hex = sha256Hex;
            this.note = note;
        }

        @Override
        public String toString() {
            return label + " (" + sha256Hex.substring(0, 12) + "...)";
        }
    }

    private final List<SampleTarget> sampleTargets = new ArrayList<>();
    private final List<String> candidateDictionary = new ArrayList<>();

    // UI Components
    private JComboBox<SampleTarget> targetSelectorCombo;
    private JTextField targetHashField;
    private JTextField candidateWordField;
    private JTextField candidateHashField;
    private JLabel attemptsCounterLabel;
    private JLabel statusBannerLabel;
    private JProgressBar progressBar;

    private JButton startBtn;
    private JButton stopBtn;
    private JButton resetBtn;

    // Background Worker
    private SwingWorker<Void, HashMatchStep> activeWorker;
    private volatile boolean isRunning = false;

    public HashMatchingDemo(SessionStats stats) {
        this.sessionStats = stats;

        setLayout(new BorderLayout());
        setBackground(UITheme.CONTENT_BG);
        setBorder(new EmptyBorder(20, 24, 20, 24));

        initSamples();
        initUI();
    }

    private void initSamples() {
        // Built-in candidate dictionary
        String[] words = {
                "admin", "welcome", "123456", "password", "qwerty", "football",
                "dragon", "master", "monkey", "shadow", "sunshine", "letmein",
                "princess", "superman", "computer", "matrix", "falcon", "rocket",
                "winter", "summer", "ocean", "cookie", "diamond", "freedom"
        };
        for (String w : words) {
            candidateDictionary.add(w);
        }

        // Educational target hashes
        sampleTargets.add(new SampleTarget(
                "Leaked Target 1 ('password')",
                PasswordHashingLab.calculateSHA256("password"),
                "Common default password"
        ));
        sampleTargets.add(new SampleTarget(
                "Leaked Target 2 ('matrix')",
                PasswordHashingLab.calculateSHA256("matrix"),
                "Pop culture dictionary word"
        ));
        sampleTargets.add(new SampleTarget(
                "Leaked Target 3 ('cookie')",
                PasswordHashingLab.calculateSHA256("cookie"),
                "Everyday English noun"
        ));
        sampleTargets.add(new SampleTarget(
                "Leaked Target 4 ('Falcon#2026!Z')",
                PasswordHashingLab.calculateSHA256("Falcon#2026!Z"),
                "High-entropy password (NOT in sample dictionary)"
        ));
    }

    private void initUI() {
        // Header
        JPanel headerPanel = UITheme.createHeader(
                "Module 6: Educational Hash Matching Demo",
                "Observe how attackers perform forward-hash matching against stored digest tables"
        );
        add(headerPanel, BorderLayout.NORTH);

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setOpaque(false);

        // 1. Target Hash Selection Card
        mainPanel.add(createTargetSelectionCard());
        mainPanel.add(Box.createVerticalStrut(16));

        // 2. Live Matching Process Monitor
        mainPanel.add(createMonitorCard());
        mainPanel.add(Box.createVerticalStrut(16));

        // 3. Cryptographic Teaching Card
        mainPanel.add(createEducationalCard());

        JScrollPane scrollPane = new JScrollPane(mainPanel);
        scrollPane.setBorder(null);
        scrollPane.setOpaque(false);
        scrollPane.getViewport().setOpaque(false);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);

        add(scrollPane, BorderLayout.CENTER);
    }

    private JPanel createTargetSelectionCard() {
        JPanel card = UITheme.createCard();
        card.setLayout(new BorderLayout(0, 12));

        JLabel title = new JLabel("1. Select Stored Target Hash (Simulating Stolen Hash Database)");
        title.setFont(UITheme.FONT_SECTION);
        title.setForeground(UITheme.TEXT_PRIMARY);

        JPanel form = new JPanel(new GridLayout(2, 1, 0, 10));
        form.setOpaque(false);

        // Preset selector
        JPanel row1 = new JPanel(new BorderLayout(10, 0));
        row1.setOpaque(false);
        JLabel presetLbl = new JLabel("Sample Hash Target:");
        presetLbl.setFont(UITheme.FONT_BODY_BOLD);

        targetSelectorCombo = new JComboBox<>(sampleTargets.toArray(new SampleTarget[0]));
        targetSelectorCombo.setFont(UITheme.FONT_BODY);
        targetSelectorCombo.addActionListener(e -> {
            SampleTarget st = (SampleTarget) targetSelectorCombo.getSelectedItem();
            if (st != null) {
                targetHashField.setText(st.sha256Hex);
            }
        });

        row1.add(presetLbl, BorderLayout.WEST);
        row1.add(targetSelectorCombo, BorderLayout.CENTER);

        // Hash display row
        JPanel row2 = new JPanel(new BorderLayout(10, 0));
        row2.setOpaque(false);
        JLabel hashLbl = new JLabel("Target SHA-256: ");
        hashLbl.setFont(UITheme.FONT_BODY_BOLD);

        targetHashField = new JTextField(sampleTargets.get(0).sha256Hex);
        targetHashField.setFont(UITheme.FONT_MONO);

        JButton customHashBtn = UITheme.createButton("Hash Custom Input", UITheme.SIDEBAR_HOVER, Color.WHITE);
        customHashBtn.setFont(UITheme.FONT_SMALL);
        customHashBtn.addActionListener(e -> {
            String word = JOptionPane.showInputDialog(this, "Enter a sample word to hash into the target field:", "Custom Hash Target", JOptionPane.QUESTION_MESSAGE);
            if (word != null && !word.trim().isEmpty()) {
                targetHashField.setText(PasswordHashingLab.calculateSHA256(word.trim()));
            }
        });

        row2.add(hashLbl, BorderLayout.WEST);
        row2.add(targetHashField, BorderLayout.CENTER);
        row2.add(customHashBtn, BorderLayout.EAST);

        form.add(row1);
        form.add(row2);

        card.add(title, BorderLayout.NORTH);
        card.add(form, BorderLayout.CENTER);

        return card;
    }

    private JPanel createMonitorCard() {
        JPanel card = UITheme.createCard();
        card.setLayout(new BorderLayout(0, 12));

        JLabel title = new JLabel("2. Forward-Hash Matching Engine");
        title.setFont(UITheme.FONT_SECTION);
        title.setForeground(UITheme.TEXT_PRIMARY);

        JPanel monitorGrid = new JPanel(new GridLayout(3, 1, 0, 8));
        monitorGrid.setOpaque(false);

        // Candidate word row
        JPanel r1 = new JPanel(new BorderLayout(10, 0));
        r1.setOpaque(false);
        JLabel cWordLbl = new JLabel("Candidate Guess: ");
        cWordLbl.setFont(UITheme.FONT_BODY_BOLD);
        candidateWordField = new JTextField("[Awaiting Start]");
        candidateWordField.setFont(UITheme.FONT_MONO_BOLD);
        candidateWordField.setEditable(false);
        r1.add(cWordLbl, BorderLayout.WEST);
        r1.add(candidateWordField, BorderLayout.CENTER);

        // Candidate computed hash row
        JPanel r2 = new JPanel(new BorderLayout(10, 0));
        r2.setOpaque(false);
        JLabel cHashLbl = new JLabel("Computed Digest:");
        cHashLbl.setFont(UITheme.FONT_BODY_BOLD);
        candidateHashField = new JTextField("[None]");
        candidateHashField.setFont(new Font("Consolas", Font.PLAIN, 11));
        candidateHashField.setEditable(false);
        r2.add(cHashLbl, BorderLayout.WEST);
        r2.add(candidateHashField, BorderLayout.CENTER);

        // Stats row
        JPanel r3 = new JPanel(new BorderLayout());
        r3.setOpaque(false);
        attemptsCounterLabel = new JLabel("Candidates Tested: 0 / " + candidateDictionary.size());
        attemptsCounterLabel.setFont(UITheme.FONT_BODY_BOLD);

        statusBannerLabel = new JLabel("Status: Ready");
        statusBannerLabel.setFont(UITheme.FONT_BODY_BOLD);
        statusBannerLabel.setForeground(UITheme.TEXT_SECONDARY);

        r3.add(attemptsCounterLabel, BorderLayout.WEST);
        r3.add(statusBannerLabel, BorderLayout.EAST);

        monitorGrid.add(r1);
        monitorGrid.add(r2);
        monitorGrid.add(r3);

        // Progress bar
        progressBar = new JProgressBar(0, 100);
        progressBar.setValue(0);
        progressBar.setStringPainted(true);

        // Control Buttons
        JPanel actionRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        actionRow.setOpaque(false);

        startBtn = UITheme.createButton("▶ Run Hash Matcher", UITheme.PRIMARY_BLUE, Color.WHITE);
        startBtn.addActionListener(e -> startMatching());

        stopBtn = UITheme.createButton("⏹ Stop", UITheme.DANGER_RED, Color.WHITE);
        stopBtn.setEnabled(false);
        stopBtn.addActionListener(e -> stopMatching());

        resetBtn = UITheme.createButton("Reset", UITheme.SIDEBAR_HOVER, Color.WHITE);
        resetBtn.addActionListener(e -> resetMonitor());

        actionRow.add(startBtn);
        actionRow.add(stopBtn);
        actionRow.add(resetBtn);

        JPanel centerPanel = new JPanel(new BorderLayout(0, 10));
        centerPanel.setOpaque(false);
        centerPanel.add(monitorGrid, BorderLayout.CENTER);
        centerPanel.add(progressBar, BorderLayout.SOUTH);

        card.add(title, BorderLayout.NORTH);
        card.add(centerPanel, BorderLayout.CENTER);
        card.add(actionRow, BorderLayout.SOUTH);

        return card;
    }

    private JPanel createEducationalCard() {
        JPanel card = UITheme.createCard();
        card.setLayout(new BorderLayout(0, 8));

        JLabel title = new JLabel("Understanding One-Way Hashes: Forward Guessing vs Reversal");
        title.setFont(UITheme.FONT_SECTION);
        title.setForeground(UITheme.TEXT_PRIMARY);

        JTextArea info = new JTextArea();
        info.setFont(UITheme.FONT_BODY);
        info.setEditable(false);
        info.setLineWrap(true);
        info.setWrapStyleWord(true);
        info.setOpaque(false);
        info.setText(
                "• Common Misconception: 'The hash was decrypted or reversed.'\n" +
                "  FALSE! Cryptographic hash functions (like SHA-256) discard input information. They are mathematically strictly one-way. There is no decryption key, formula, or algorithm to 'un-hash' a digest.\n\n" +
                "• What Actually Happened in this Demo:\n" +
                "  The system performed 'forward guessing':\n" +
                "  1. It took a candidate word 'password'\n" +
                "  2. It computed SHA-256('password') -> 5e884898da2804...\n" +
                "  3. It compared the result with the target hash.\n" +
                "  Since both hexadecimal strings matched, we discovered the original plaintext that generated the digest!\n\n" +
                "• Why This Matters for Security:\n" +
                "  If your password is in a wordlist, an attacker doesn't need to 'break' cryptography—they just test common words until a hash matches."
        );

        card.add(title, BorderLayout.NORTH);
        card.add(info, BorderLayout.CENTER);
        return card;
    }

    private void startMatching() {
        final String targetHash = targetHashField.getText().trim().toLowerCase();
        if (targetHash.length() != 64) {
            JOptionPane.showMessageDialog(this,
                    "Target hash must be a 64-character hexadecimal SHA-256 digest.",
                    "Invalid Hash Length", JOptionPane.WARNING_MESSAGE);
            return;
        }

        isRunning = true;
        startBtn.setEnabled(false);
        stopBtn.setEnabled(true);
        resetBtn.setEnabled(false);
        statusBannerLabel.setText("Status: Scanning dictionary...");
        statusBannerLabel.setForeground(UITheme.PRIMARY_BLUE);

        final int totalCandidates = candidateDictionary.size();

        activeWorker = new SwingWorker<Void, HashMatchStep>() {
            private boolean matchFound = false;
            private String matchedWord = "";
            private int matchedIdx = 0;

            @Override
            protected Void doInBackground() throws Exception {
                for (int i = 0; i < totalCandidates; i++) {
                    if (!isRunning) break;

                    String candidate = candidateDictionary.get(i);
                    String candidateHash = PasswordHashingLab.calculateSHA256(candidate).toLowerCase();
                    boolean match = candidateHash.equals(targetHash);

                    publish(new HashMatchStep(i + 1, totalCandidates, candidate, candidateHash, match));

                    if (match) {
                        matchFound = true;
                        matchedWord = candidate;
                        matchedIdx = i + 1;
                        break;
                    }

                    // Gentle delay so user sees matching in action
                    Thread.sleep(80);
                }
                return null;
            }

            @Override
            protected void process(List<HashMatchStep> chunks) {
                if (chunks.isEmpty()) return;
                HashMatchStep step = chunks.get(chunks.size() - 1);

                candidateWordField.setText(step.candidate);
                candidateHashField.setText(step.hash);
                attemptsCounterLabel.setText("Candidates Tested: " + step.index + " / " + step.total);

                int pct = (int) (((double) step.index / step.total) * 100);
                progressBar.setValue(pct);
            }

            @Override
            protected void done() {
                isRunning = false;
                startBtn.setEnabled(true);
                stopBtn.setEnabled(false);
                resetBtn.setEnabled(true);

                sessionStats.recordHashingTest();

                if (matchFound) {
                    progressBar.setValue(100);
                    statusBannerLabel.setText("MATCH FOUND! Plaintext: '" + matchedWord + "'");
                    statusBannerLabel.setForeground(UITheme.SUCCESS_GREEN);
                    candidateWordField.setText(matchedWord + " (MATCH!)");
                    candidateWordField.setForeground(UITheme.SUCCESS_GREEN);

                    JOptionPane.showMessageDialog(HashMatchingDemo.this,
                            "Pre-image Discovered!\n\nTarget digest matches candidate word: '" + matchedWord + "'\n" +
                            "Found at attempt #" + matchedIdx + " of " + totalCandidates + ".\n\n" +
                            "Remember: The hash was NOT reversed; the matching candidate word produced the same digest.",
                            "Hash Match Found", JOptionPane.INFORMATION_MESSAGE);
                } else {
                    statusBannerLabel.setText("Exhausted: No match in sample dictionary");
                    statusBannerLabel.setForeground(UITheme.DANGER_RED);
                    candidateWordField.setText("[No Match Found]");
                    candidateWordField.setForeground(UITheme.TEXT_SECONDARY);

                    JOptionPane.showMessageDialog(HashMatchingDemo.this,
                            "Search Complete: None of the " + totalCandidates + " candidates in our educational dictionary\n" +
                            "matched the target hash.\n\n" +
                            "Takeaway: Unique, non-dictionary passwords protect against offline dictionary matching.",
                            "No Match Found", JOptionPane.INFORMATION_MESSAGE);
                }
            }
        };

        activeWorker.execute();
    }

    private void stopMatching() {
        isRunning = false;
        if (activeWorker != null && !activeWorker.isDone()) {
            activeWorker.cancel(true);
        }
        startBtn.setEnabled(true);
        stopBtn.setEnabled(false);
        resetBtn.setEnabled(true);
        statusBannerLabel.setText("Status: Stopped by user");
        statusBannerLabel.setForeground(UITheme.WARNING_AMBER);
    }

    private void resetMonitor() {
        stopMatching();
        candidateWordField.setText("[Awaiting Start]");
        candidateWordField.setForeground(UITheme.TEXT_PRIMARY);
        candidateHashField.setText("[None]");
        attemptsCounterLabel.setText("Candidates Tested: 0 / " + candidateDictionary.size());
        statusBannerLabel.setText("Status: Ready");
        statusBannerLabel.setForeground(UITheme.TEXT_SECONDARY);
        progressBar.setValue(0);
    }

    private static class HashMatchStep {
        final int index;
        final int total;
        final String candidate;
        final String hash;
        final boolean matched;

        HashMatchStep(int index, int total, String candidate, String hash, boolean matched) {
            this.index = index;
            this.total = total;
            this.candidate = candidate;
            this.hash = hash;
            this.matched = matched;
        }
    }
}
