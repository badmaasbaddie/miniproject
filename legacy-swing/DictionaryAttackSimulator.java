package passwordsecurity;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Module 4: Educational Dictionary Attack Simulation
 * Demonstrates how attackers use precompiled lists of common words to rapidly
 * test candidate passwords. Runs strictly in local memory using educational test data.
 */
public class DictionaryAttackSimulator extends JPanel {

    private final SessionStats sessionStats;

    // Wordlist
    private final DefaultListModel<String> wordListModel = new DefaultListModel<>();
    private JList<String> wordJList;

    // Inputs & Controls
    private JTextField targetWordField;
    private JComboBox<String> presetTargetCombo;
    private JComboBox<String> speedCombo;
    private JButton startBtn;
    private JButton stopBtn;
    private JButton resetBtn;
    private JButton addWordBtn;

    // Monitor Display
    private JLabel currentAttemptLabel;
    private JLabel candidateDisplayLabel;
    private JLabel resultStatusLabel;
    private JProgressBar progressBar;

    // Simulation Worker
    private SwingWorker<Void, DictionaryStep> activeWorker;
    private volatile boolean isRunning = false;

    // Built-in fallback word list
    private static final String[] DEFAULT_WORDS = {
            "password", "123456", "12345678", "qwerty", "admin", "welcome",
            "login", "football", "dragon", "sunshine", "master", "shadow",
            "secret", "letmein", "monkey", "princess", "superman", "computer",
            "trustno1", "baseball", "michael", "starwars", "matrix", "banana",
            "coffee", "orange", "falcon", "rocket", "guitar", "planet",
            "phoenix", "wizard", "tiger", "eagle", "silver", "galaxy",
            "sunset", "winter", "summer", "spring", "autumn", "ocean",
            "breeze", "mountain", "forest", "river", "thunder", "lightning",
            "cookie", "diamond", "champion", "justice", "freedom"
    };

    public DictionaryAttackSimulator(SessionStats stats) {
        this.sessionStats = stats;

        setLayout(new BorderLayout());
        setBackground(UITheme.CONTENT_BG);
        setBorder(new EmptyBorder(20, 24, 20, 24));

        loadDictionaryWords();
        initUI();
    }

    private void loadDictionaryWords() {
        wordListModel.clear();
        try {
            Path path = Paths.get("data", "sample_words.txt");
            if (Files.exists(path)) {
                List<String> lines = Files.readAllLines(path);
                for (String line : lines) {
                    line = line.trim();
                    if (!line.isEmpty() && !line.startsWith("#")) {
                        wordListModel.addElement(line);
                    }
                }
            }
        } catch (Exception ignored) {}

        if (wordListModel.isEmpty()) {
            for (String w : DEFAULT_WORDS) {
                wordListModel.addElement(w);
            }
        }
    }

    private void initUI() {
        // Header
        JPanel headerPanel = UITheme.createHeader(
                "Module 4: Dictionary Attack Simulation",
                "Simulate candidate wordlist matching against sample targets safely in local memory"
        );
        add(headerPanel, BorderLayout.NORTH);

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setOpaque(false);

        // 1. Two-Column Card: Wordlist on Left, Target & Controls on Right
        mainPanel.add(createSetupCard());
        mainPanel.add(Box.createVerticalStrut(16));

        // 2. Live Monitor Card
        mainPanel.add(createMonitorCard());
        mainPanel.add(Box.createVerticalStrut(16));

        // 3. Educational Defense Principles Card
        mainPanel.add(createDefenseCard());

        JScrollPane scrollPane = new JScrollPane(mainPanel);
        scrollPane.setBorder(null);
        scrollPane.setOpaque(false);
        scrollPane.getViewport().setOpaque(false);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);

        add(scrollPane, BorderLayout.CENTER);
    }

    private JPanel createSetupCard() {
        JPanel card = UITheme.createCard();
        card.setLayout(new GridLayout(1, 2, 20, 0));

        // Left: Wordlist View
        JPanel listPanel = new JPanel(new BorderLayout(0, 8));
        listPanel.setOpaque(false);

        JLabel listTitle = new JLabel("Educational Wordlist (" + wordListModel.size() + " words)");
        listTitle.setFont(UITheme.FONT_SECTION);
        listTitle.setForeground(UITheme.TEXT_PRIMARY);

        wordJList = new JList<>(wordListModel);
        wordJList.setFont(UITheme.FONT_MONO);
        wordJList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        wordJList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && wordJList.getSelectedValue() != null) {
                targetWordField.setText(wordJList.getSelectedValue());
            }
        });

        JScrollPane listScroll = new JScrollPane(wordJList);
        listScroll.setPreferredSize(new Dimension(200, 140));

        JPanel addWordRow = new JPanel(new BorderLayout(6, 0));
        addWordRow.setOpaque(false);
        JTextField newWordField = new JTextField();
        newWordField.setFont(UITheme.FONT_MONO);
        addWordBtn = UITheme.createButton("+ Add Word", UITheme.SIDEBAR_HOVER, Color.WHITE);
        addWordBtn.setFont(UITheme.FONT_SMALL);
        addWordBtn.addActionListener(e -> {
            String word = newWordField.getText().trim();
            if (!word.isEmpty() && !wordListModel.contains(word)) {
                wordListModel.addElement(word);
                newWordField.setText("");
                listTitle.setText("Educational Wordlist (" + wordListModel.size() + " words)");
            }
        });
        addWordRow.add(newWordField, BorderLayout.CENTER);
        addWordRow.add(addWordBtn, BorderLayout.EAST);

        listPanel.add(listTitle, BorderLayout.NORTH);
        listPanel.add(listScroll, BorderLayout.CENTER);
        listPanel.add(addWordRow, BorderLayout.SOUTH);

        // Right: Target Selection & Speed
        JPanel controlPanel = new JPanel();
        controlPanel.setLayout(new BoxLayout(controlPanel, BoxLayout.Y_AXIS));
        controlPanel.setOpaque(false);

        JLabel targetTitle = new JLabel("Configure Simulation Target");
        targetTitle.setFont(UITheme.FONT_SECTION);
        targetTitle.setForeground(UITheme.TEXT_PRIMARY);
        controlPanel.add(targetTitle);
        controlPanel.add(Box.createVerticalStrut(10));

        JLabel presetLbl = new JLabel("Choose Quick Target:");
        presetLbl.setFont(UITheme.FONT_BODY_BOLD);
        presetTargetCombo = new JComboBox<>(new String[]{
                "In Wordlist: 'dragon'",
                "In Wordlist: 'matrix'",
                "In Wordlist: 'letmein'",
                "NOT in Wordlist: 'Titan$#2026!X'"
        });
        presetTargetCombo.setFont(UITheme.FONT_BODY);
        presetTargetCombo.addActionListener(e -> {
            int idx = presetTargetCombo.getSelectedIndex();
            if (idx == 0) targetWordField.setText("dragon");
            else if (idx == 1) targetWordField.setText("matrix");
            else if (idx == 2) targetWordField.setText("letmein");
            else if (idx == 3) targetWordField.setText("Titan$#2026!X");
        });

        controlPanel.add(presetLbl);
        controlPanel.add(presetTargetCombo);
        controlPanel.add(Box.createVerticalStrut(10));

        JLabel customLbl = new JLabel("Target String:");
        customLbl.setFont(UITheme.FONT_BODY_BOLD);
        targetWordField = new JTextField("dragon");
        targetWordField.setFont(UITheme.FONT_MONO);

        controlPanel.add(customLbl);
        controlPanel.add(targetWordField);
        controlPanel.add(Box.createVerticalStrut(10));

        JLabel speedLbl = new JLabel("Simulation Speed:");
        speedLbl.setFont(UITheme.FONT_BODY_BOLD);
        speedCombo = new JComboBox<>(new String[]{"Visual Animated (60 ms/word)", "Fast (10 ms/word)", "Instant (0 ms)"});
        speedCombo.setFont(UITheme.FONT_BODY);

        controlPanel.add(speedLbl);
        controlPanel.add(speedCombo);
        controlPanel.add(Box.createVerticalStrut(14));

        // Action Buttons Row
        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        btnRow.setOpaque(false);

        startBtn = UITheme.createButton("▶ Run Attack", UITheme.PRIMARY_BLUE, Color.WHITE);
        startBtn.addActionListener(e -> startDictionaryAttack());

        stopBtn = UITheme.createButton("⏹ Stop", UITheme.DANGER_RED, Color.WHITE);
        stopBtn.setEnabled(false);
        stopBtn.addActionListener(e -> stopDictionaryAttack());

        resetBtn = UITheme.createButton("Reset", UITheme.SIDEBAR_HOVER, Color.WHITE);
        resetBtn.addActionListener(e -> resetMonitor());

        btnRow.add(startBtn);
        btnRow.add(stopBtn);
        btnRow.add(resetBtn);

        controlPanel.add(btnRow);

        card.add(listPanel);
        card.add(controlPanel);

        return card;
    }

    private JPanel createMonitorCard() {
        JPanel card = UITheme.createCard();
        card.setLayout(new BorderLayout(0, 12));

        JLabel title = new JLabel("Simulation Status & Attack Monitor");
        title.setFont(UITheme.FONT_SECTION);
        title.setForeground(UITheme.TEXT_PRIMARY);

        JPanel metrics = new JPanel(new GridLayout(1, 3, 16, 0));
        metrics.setOpaque(false);

        currentAttemptLabel = new JLabel("Attempt: 0 / " + wordListModel.size());
        currentAttemptLabel.setFont(UITheme.FONT_BODY_BOLD);

        candidateDisplayLabel = new JLabel("Candidate: [Idle]");
        candidateDisplayLabel.setFont(UITheme.FONT_MONO_BOLD);
        candidateDisplayLabel.setForeground(UITheme.PURPLE_ACCENT);

        resultStatusLabel = new JLabel("Status: Ready to test");
        resultStatusLabel.setFont(UITheme.FONT_BODY_BOLD);
        resultStatusLabel.setForeground(UITheme.TEXT_SECONDARY);

        metrics.add(currentAttemptLabel);
        metrics.add(candidateDisplayLabel);
        metrics.add(resultStatusLabel);

        progressBar = new JProgressBar(0, 100);
        progressBar.setValue(0);
        progressBar.setStringPainted(true);
        progressBar.setPreferredSize(new Dimension(100, 22));

        card.add(title, BorderLayout.NORTH);
        card.add(metrics, BorderLayout.CENTER);
        card.add(progressBar, BorderLayout.SOUTH);

        return card;
    }

    private JPanel createDefenseCard() {
        JPanel card = UITheme.createCard();
        card.setLayout(new BorderLayout(0, 8));

        JLabel title = new JLabel("Why Dictionary Attacks Succeed and How to Mitigate Them");
        title.setFont(UITheme.FONT_SECTION);
        title.setForeground(UITheme.TEXT_PRIMARY);

        JTextArea info = new JTextArea();
        info.setFont(UITheme.FONT_BODY);
        info.setEditable(false);
        info.setLineWrap(true);
        info.setWrapStyleWord(true);
        info.setOpaque(false);
        info.setText(
                "• Human Vulnerability:\n" +
                "  Humans naturally prefer memorable words. Real-world wordlists (like RockYou, with 14.3 Million words) contain passwords found in real corporate breaches.\n\n" +
                "• Hybrid / Rule-Based Attacks:\n" +
                "  Attackers do not just check exact words; they apply rules (e.g. 'dragon' -> 'Dr@g0n2024!'). Standard dictionary words with basic substitutions are often cracked in minutes.\n\n" +
                "• How Systems Defend Against Dictionary Attacks:\n" +
                "  1. Account Lockout & Rate Limiting: Block IP or account after 3-5 failed login attempts.\n" +
                "  2. Slow Salted Key-Derivation: Algorithms like Argon2id, bcrypt, and PBKDF2 force attackers to spend millions of CPU clock cycles on each guess.\n" +
                "  3. Multi-Factor Authentication (MFA): Even if a password is found in a dictionary, access requires a second factor (TOTP / Hardware key)."
        );

        card.add(title, BorderLayout.NORTH);
        card.add(info, BorderLayout.CENTER);
        return card;
    }

    private void startDictionaryAttack() {
        final String target = targetWordField.getText().trim();
        if (target.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please specify a target password to test.", "Missing Target", JOptionPane.WARNING_MESSAGE);
            return;
        }

        if (wordListModel.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Wordlist is empty.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        int speedIdx = speedCombo.getSelectedIndex();
        final int delayMs = (speedIdx == 0) ? 60 : (speedIdx == 1 ? 10 : 0);

        isRunning = true;
        startBtn.setEnabled(false);
        stopBtn.setEnabled(true);
        resetBtn.setEnabled(false);
        resultStatusLabel.setText("Status: In progress...");
        resultStatusLabel.setForeground(UITheme.PRIMARY_BLUE);

        final int totalWords = wordListModel.size();

        activeWorker = new SwingWorker<Void, DictionaryStep>() {
            private boolean found = false;
            private int matchedIndex = -1;
            private String matchedWord = "";

            @Override
            protected Void doInBackground() throws Exception {
                for (int i = 0; i < totalWords; i++) {
                    if (!isRunning) break;

                    String candidate = wordListModel.get(i);
                    boolean isMatch = candidate.equals(target);

                    publish(new DictionaryStep(i + 1, totalWords, candidate, isMatch));

                    if (isMatch) {
                        found = true;
                        matchedIndex = i + 1;
                        matchedWord = candidate;
                        break;
                    }

                    if (delayMs > 0) {
                        Thread.sleep(delayMs);
                    }
                }
                return null;
            }

            @Override
            protected void process(List<DictionaryStep> chunks) {
                if (chunks.isEmpty()) return;
                DictionaryStep step = chunks.get(chunks.size() - 1);

                currentAttemptLabel.setText("Attempt: " + step.index + " / " + step.total);
                candidateDisplayLabel.setText("Candidate: '" + step.candidate + "'");

                int pct = (int) (((double) step.index / step.total) * 100);
                progressBar.setValue(pct);

                // Auto-select item in JList to visualize progress
                wordJList.setSelectedIndex(step.index - 1);
                wordJList.ensureIndexIsVisible(step.index - 1);
            }

            @Override
            protected void done() {
                isRunning = false;
                startBtn.setEnabled(true);
                stopBtn.setEnabled(false);
                resetBtn.setEnabled(true);

                sessionStats.recordDictionarySimulation();

                if (found) {
                    progressBar.setValue(100);
                    resultStatusLabel.setText("Status: MATCH FOUND!");
                    resultStatusLabel.setForeground(UITheme.SUCCESS_GREEN);
                    candidateDisplayLabel.setText("Matched: '" + matchedWord + "'");
                    candidateDisplayLabel.setForeground(UITheme.SUCCESS_GREEN);

                    JOptionPane.showMessageDialog(DictionaryAttackSimulator.this,
                            "Success! The candidate '" + matchedWord + "' matched the target.\n" +
                            "Found at attempt #" + matchedIndex + " out of " + totalWords + " words in dictionary.\n\n" +
                            "Takeaway: Words present in known dictionaries offer zero protection against dictionary attacks.",
                            "Password Found in Dictionary", JOptionPane.INFORMATION_MESSAGE);
                } else {
                    resultStatusLabel.setText("Status: NOT in dictionary");
                    resultStatusLabel.setForeground(UITheme.DANGER_RED);
                    JOptionPane.showMessageDialog(DictionaryAttackSimulator.this,
                            "Simulation Complete: Target '" + target + "' was NOT found in the educational dictionary.\n" +
                            "Checked all " + totalWords + " words.\n\n" +
                            "Takeaway: High-entropy passwords and unique passphrases defeat standard dictionary lookups.",
                            "Target Not Found", JOptionPane.INFORMATION_MESSAGE);
                }
            }
        };

        activeWorker.execute();
    }

    private void stopDictionaryAttack() {
        isRunning = false;
        if (activeWorker != null && !activeWorker.isDone()) {
            activeWorker.cancel(true);
        }
        startBtn.setEnabled(true);
        stopBtn.setEnabled(false);
        resetBtn.setEnabled(true);
        resultStatusLabel.setText("Status: Stopped by user");
        resultStatusLabel.setForeground(UITheme.WARNING_AMBER);
    }

    private void resetMonitor() {
        stopDictionaryAttack();
        currentAttemptLabel.setText("Attempt: 0 / " + wordListModel.size());
        candidateDisplayLabel.setText("Candidate: [Idle]");
        candidateDisplayLabel.setForeground(UITheme.PURPLE_ACCENT);
        resultStatusLabel.setText("Status: Ready to test");
        resultStatusLabel.setForeground(UITheme.TEXT_SECONDARY);
        progressBar.setValue(0);
        wordJList.clearSelection();
    }

    private static class DictionaryStep {
        final int index;
        final int total;
        final String candidate;
        final boolean isMatch;

        DictionaryStep(int index, int total, String candidate, boolean isMatch) {
            this.index = index;
            this.total = total;
            this.candidate = candidate;
            this.isMatch = isMatch;
        }
    }
}
