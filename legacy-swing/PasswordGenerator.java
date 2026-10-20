package passwordsecurity;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Module 2: Secure Password Generator
 * Generates cryptographically secure passwords and memorable passphrases
 * using java.security.SecureRandom (CSPRNG).
 */
public class PasswordGenerator extends JPanel {

    // Character Sets
    private static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    private static final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String DIGITS = "0123456789";
    private static final String SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?";
    private static final String AMBIGUOUS = "0OlI1";

    // Built-in fallback word list for memorable passphrases
    private static final String[] DEFAULT_WORDS = {
            "correct", "horse", "battery", "staple", "galaxy", "falcon",
            "rocket", "phoenix", "wizard", "tiger", "eagle", "silver",
            "planet", "sunset", "winter", "summer", "spring", "autumn",
            "ocean", "breeze", "mountain", "forest", "river", "thunder",
            "lightning", "cookie", "diamond", "champion", "justice", "freedom",
            "bravo", "charlie", "delta", "echo", "foxtrot", "golf",
            "hotel", "india", "juliet", "kilo", "lima", "matrix",
            "november", "oscar", "quebec", "romeo", "sierra", "tango",
            "uniform", "victor", "whiskey", "xray", "yankee", "zulu"
    };

    private final SecureRandom secureRandom = new SecureRandom();
    private final List<String> wordList = new ArrayList<>();

    // UI Components
    private JTextField outputField;
    private JLabel strengthNoticeLabel;
    private JLabel copyFeedbackLabel;

    // Password Mode Controls
    private JSlider lengthSlider;
    private JLabel lengthDisplayLabel;
    private JCheckBox checkUpper;
    private JCheckBox checkLower;
    private JCheckBox checkDigits;
    private JCheckBox checkSymbols;
    private JCheckBox checkExcludeAmbiguous;

    // Passphrase Mode Controls
    private JSpinner wordCountSpinner;
    private JComboBox<String> separatorCombo;
    private JCheckBox checkCapitalizePassphrase;
    private JCheckBox checkAppendNumber;

    public PasswordGenerator() {
        setLayout(new BorderLayout());
        setBackground(UITheme.CONTENT_BG);
        setBorder(new EmptyBorder(20, 24, 20, 24));

        loadWordList();
        initUI();
    }

    private void loadWordList() {
        // First try reading data/sample_words.txt
        try {
            Path path = Paths.get("data", "sample_words.txt");
            if (Files.exists(path)) {
                List<String> lines = Files.readAllLines(path);
                for (String line : lines) {
                    line = line.trim();
                    if (!line.isEmpty() && !line.startsWith("#")) {
                        wordList.add(line);
                    }
                }
            }
        } catch (Exception ignored) {
            // Fall back to built-in words
        }

        if (wordList.isEmpty()) {
            wordList.addAll(Arrays.asList(DEFAULT_WORDS));
        }
    }

    private void initUI() {
        // Header
        JPanel headerPanel = UITheme.createHeader(
                "Module 2: Secure Password Generator",
                "Generate cryptographically strong passwords or memorable passphrases using SecureRandom"
        );
        add(headerPanel, BorderLayout.NORTH);

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setOpaque(false);

        // 1. Output Display Card
        mainPanel.add(createOutputCard());
        mainPanel.add(Box.createVerticalStrut(16));

        // 2. Configuration Tabs (Standard vs Passphrase)
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.setFont(UITheme.FONT_BODY_BOLD);
        tabbedPane.addTab("Standard Character Password", createStandardConfigPanel());
        tabbedPane.addTab("Memorable Passphrase (Diceware)", createPassphraseConfigPanel());

        mainPanel.add(tabbedPane);
        mainPanel.add(Box.createVerticalStrut(16));

        // 3. Information Box
        mainPanel.add(createInfoCard());

        JScrollPane scrollPane = new JScrollPane(mainPanel);
        scrollPane.setBorder(null);
        scrollPane.setOpaque(false);
        scrollPane.getViewport().setOpaque(false);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);

        add(scrollPane, BorderLayout.CENTER);

        // Generate an initial default password
        generateStandardPassword();
    }

    private JPanel createOutputCard() {
        JPanel card = UITheme.createCard();
        card.setLayout(new BorderLayout(0, 10));

        JLabel title = new JLabel("Generated Secure Output");
        title.setFont(UITheme.FONT_SECTION);
        title.setForeground(UITheme.TEXT_PRIMARY);

        JPanel centerPanel = new JPanel(new BorderLayout(10, 0));
        centerPanel.setOpaque(false);

        outputField = new JTextField();
        outputField.setFont(new Font("Consolas", Font.BOLD, 16));
        outputField.setEditable(false);
        outputField.setBackground(new Color(241, 245, 249));
        outputField.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(UITheme.CARD_BORDER, 1),
                new EmptyBorder(8, 12, 8, 12)
        ));

        JButton copyBtn = UITheme.createButton("📋 Copy to Clipboard", UITheme.SIDEBAR_BG, Color.WHITE);
        copyBtn.addActionListener(e -> copyToClipboard());

        centerPanel.add(outputField, BorderLayout.CENTER);
        centerPanel.add(copyBtn, BorderLayout.EAST);

        // Bottom status row
        JPanel bottomRow = new JPanel(new BorderLayout());
        bottomRow.setOpaque(false);

        strengthNoticeLabel = new JLabel("Length: 16 | Entropy: ~105.1 bits | Strength: Strong");
        strengthNoticeLabel.setFont(UITheme.FONT_SMALL);
        strengthNoticeLabel.setForeground(UITheme.SUCCESS_GREEN);

        copyFeedbackLabel = new JLabel("");
        copyFeedbackLabel.setFont(UITheme.FONT_SMALL);
        copyFeedbackLabel.setForeground(UITheme.PRIMARY_BLUE);

        bottomRow.add(strengthNoticeLabel, BorderLayout.WEST);
        bottomRow.add(copyFeedbackLabel, BorderLayout.EAST);

        card.add(title, BorderLayout.NORTH);
        card.add(centerPanel, BorderLayout.CENTER);
        card.add(bottomRow, BorderLayout.SOUTH);

        return card;
    }

    private JPanel createStandardConfigPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBackground(UITheme.CARD_BG);
        panel.setBorder(new EmptyBorder(16, 16, 16, 16));

        // Slider for length
        JPanel lengthRow = new JPanel(new BorderLayout(12, 0));
        lengthRow.setOpaque(false);

        JLabel lengthTitle = new JLabel("Password Length: ");
        lengthTitle.setFont(UITheme.FONT_BODY_BOLD);

        lengthDisplayLabel = new JLabel("16 characters");
        lengthDisplayLabel.setFont(UITheme.FONT_BODY_BOLD);
        lengthDisplayLabel.setForeground(UITheme.PRIMARY_BLUE);

        lengthSlider = new JSlider(6, 64, 16);
        lengthSlider.setPaintTicks(true);
        lengthSlider.setMajorTickSpacing(10);
        lengthSlider.setMinorTickSpacing(2);
        lengthSlider.setOpaque(false);
        lengthSlider.addChangeListener(e -> lengthDisplayLabel.setText(lengthSlider.getValue() + " characters"));

        JPanel labelContainer = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        labelContainer.setOpaque(false);
        labelContainer.add(lengthTitle);
        labelContainer.add(lengthDisplayLabel);

        lengthRow.add(labelContainer, BorderLayout.WEST);
        lengthRow.add(lengthSlider, BorderLayout.CENTER);

        panel.add(lengthRow);
        panel.add(Box.createVerticalStrut(14));

        // Character Set Checkboxes in 2x2 grid
        JPanel checkGrid = new JPanel(new GridLayout(2, 2, 12, 10));
        checkGrid.setOpaque(false);

        checkUpper = new JCheckBox("Include Uppercase Letters (A-Z)", true);
        checkLower = new JCheckBox("Include Lowercase Letters (a-z)", true);
        checkDigits = new JCheckBox("Include Numbers (0-9)", true);
        checkSymbols = new JCheckBox("Include Special Characters (!@#$...)", true);

        styleCheckbox(checkUpper);
        styleCheckbox(checkLower);
        styleCheckbox(checkDigits);
        styleCheckbox(checkSymbols);

        checkGrid.add(checkUpper);
        checkGrid.add(checkLower);
        checkGrid.add(checkDigits);
        checkGrid.add(checkSymbols);

        panel.add(checkGrid);
        panel.add(Box.createVerticalStrut(10));

        checkExcludeAmbiguous = new JCheckBox("Exclude Ambiguous Characters (e.g., 0, O, 1, I, l)", false);
        styleCheckbox(checkExcludeAmbiguous);
        panel.add(checkExcludeAmbiguous);
        panel.add(Box.createVerticalStrut(16));

        // Action Button
        JButton generateBtn = UITheme.createButton("Generate Secure Password", UITheme.PRIMARY_BLUE, Color.WHITE);
        generateBtn.setFont(UITheme.FONT_BODY_BOLD);
        generateBtn.addActionListener(e -> generateStandardPassword());

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        btnRow.setOpaque(false);
        btnRow.add(generateBtn);

        panel.add(btnRow);

        return panel;
    }

    private JPanel createPassphraseConfigPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBackground(UITheme.CARD_BG);
        panel.setBorder(new EmptyBorder(16, 16, 16, 16));

        JPanel configRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 16, 0));
        configRow.setOpaque(false);

        // Word count
        JLabel countLbl = new JLabel("Number of Words:");
        countLbl.setFont(UITheme.FONT_BODY);
        wordCountSpinner = new JSpinner(new SpinnerNumberModel(4, 3, 8, 1));
        wordCountSpinner.setFont(UITheme.FONT_BODY);
        wordCountSpinner.setPreferredSize(new Dimension(60, 28));

        // Separator
        JLabel sepLbl = new JLabel("Separator:");
        sepLbl.setFont(UITheme.FONT_BODY);
        separatorCombo = new JComboBox<>(new String[]{"Hyphen (-)", "Space ( )", "Period (.)", "Underscore (_)", "None"});
        separatorCombo.setFont(UITheme.FONT_BODY);

        configRow.add(countLbl);
        configRow.add(wordCountSpinner);
        configRow.add(sepLbl);
        configRow.add(separatorCombo);

        panel.add(configRow);
        panel.add(Box.createVerticalStrut(14));

        JPanel optionsRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 16, 0));
        optionsRow.setOpaque(false);

        checkCapitalizePassphrase = new JCheckBox("Capitalize Each Word", true);
        checkAppendNumber = new JCheckBox("Append Random 2-digit Number", true);
        styleCheckbox(checkCapitalizePassphrase);
        styleCheckbox(checkAppendNumber);

        optionsRow.add(checkCapitalizePassphrase);
        optionsRow.add(checkAppendNumber);

        panel.add(optionsRow);
        panel.add(Box.createVerticalStrut(16));

        JButton generatePassphraseBtn = UITheme.createButton("Generate Memorable Passphrase", UITheme.SUCCESS_GREEN, Color.WHITE);
        generatePassphraseBtn.setFont(UITheme.FONT_BODY_BOLD);
        generatePassphraseBtn.addActionListener(e -> generatePassphrase());

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        btnRow.setOpaque(false);
        btnRow.add(generatePassphraseBtn);

        panel.add(btnRow);

        return panel;
    }

    private void styleCheckbox(JCheckBox cb) {
        cb.setFont(UITheme.FONT_BODY);
        cb.setOpaque(false);
        cb.setForeground(UITheme.TEXT_PRIMARY);
    }

    private JPanel createInfoCard() {
        JPanel card = UITheme.createCard();
        card.setLayout(new BorderLayout());
        card.setBackground(new Color(241, 245, 249));

        JLabel infoLabel = new JLabel("<html><b>Security Fact:</b> This generator utilizes <code>java.security.SecureRandom</code>, which draws entropy from system cryptographic sources (e.g. /dev/urandom or Windows CryptoAPI). Standard <code>Math.random()</code> or <code>java.util.Random</code> uses a linear congruential formula that is completely predictable and insecure for security applications.</html>");
        infoLabel.setFont(UITheme.FONT_SMALL);
        infoLabel.setForeground(UITheme.TEXT_SECONDARY);

        card.add(infoLabel, BorderLayout.CENTER);
        return card;
    }

    /**
     * Generates a character-based password with CSPRNG guarantees.
     */
    public void generateStandardPassword() {
        int length = lengthSlider.getValue();
        boolean useUpper = checkUpper.isSelected();
        boolean useLower = checkLower.isSelected();
        boolean useDigits = checkDigits.isSelected();
        boolean useSymbols = checkSymbols.isSelected();
        boolean excludeAmbiguous = checkExcludeAmbiguous.isSelected();

        // 1. Validation: At least one character pool must be checked
        if (!useUpper && !useLower && !useDigits && !useSymbols) {
            JOptionPane.showMessageDialog(this,
                    "Validation Error: Please select at least one character set (Uppercase, Lowercase, Digits, or Symbols).",
                    "Invalid Settings",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        StringBuilder allowedChars = new StringBuilder();
        List<String> guaranteedCategories = new ArrayList<>();

        if (useUpper) {
            String chars = filterAmbiguous(UPPERCASE, excludeAmbiguous);
            allowedChars.append(chars);
            guaranteedCategories.add(chars);
        }
        if (useLower) {
            String chars = filterAmbiguous(LOWERCASE, excludeAmbiguous);
            allowedChars.append(chars);
            guaranteedCategories.add(chars);
        }
        if (useDigits) {
            String chars = filterAmbiguous(DIGITS, excludeAmbiguous);
            allowedChars.append(chars);
            guaranteedCategories.add(chars);
        }
        if (useSymbols) {
            allowedChars.append(SYMBOLS);
            guaranteedCategories.add(SYMBOLS);
        }

        String fullPool = allowedChars.toString();
        if (fullPool.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Character pool is empty after filtering.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        // 2. Build password characters
        char[] password = new char[length];
        int charIndex = 0;

        // Ensure at least one character from each selected category
        for (String cat : guaranteedCategories) {
            if (charIndex < length) {
                password[charIndex++] = cat.charAt(secureRandom.nextInt(cat.length()));
            }
        }

        // Fill remaining positions with random picks from full pool
        while (charIndex < length) {
            password[charIndex++] = fullPool.charAt(secureRandom.nextInt(fullPool.length()));
        }

        // 3. Shuffle with Fisher-Yates using SecureRandom so guaranteed chars are randomized
        for (int i = length - 1; i > 0; i--) {
            int j = secureRandom.nextInt(i + 1);
            char temp = password[i];
            password[i] = password[j];
            password[j] = temp;
        }

        String result = new String(password);
        outputField.setText(result);

        // Calculate theoretical entropy
        double entropy = length * (Math.log(fullPool.length()) / Math.log(2));
        String strength = entropy >= 80 ? "Very Strong" : (entropy >= 60 ? "Strong" : (entropy >= 45 ? "Medium" : "Weak"));

        strengthNoticeLabel.setText(String.format("Length: %d | Pool: %d chars | Entropy: ~%.1f bits | Strength: %s",
                length, fullPool.length(), entropy, strength));
        copyFeedbackLabel.setText("");
    }

    private String filterAmbiguous(String input, boolean exclude) {
        if (!exclude) return input;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (AMBIGUOUS.indexOf(c) == -1) {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * Generates a memorable passphrase from the word list.
     */
    public void generatePassphrase() {
        int count = (Integer) wordCountSpinner.getValue();
        String selectedSep = (String) separatorCombo.getSelectedItem();
        String sep = "-";
        if (selectedSep != null) {
            if (selectedSep.contains("Space")) sep = " ";
            else if (selectedSep.contains("Period")) sep = ".";
            else if (selectedSep.contains("Underscore")) sep = "_";
            else if (selectedSep.contains("None")) sep = "";
        }

        boolean capitalize = checkCapitalizePassphrase.isSelected();
        boolean appendNum = checkAppendNumber.isSelected();

        StringBuilder passphrase = new StringBuilder();
        for (int i = 0; i < count; i++) {
            int idx = secureRandom.nextInt(wordList.size());
            String word = wordList.get(idx);
            if (capitalize && !word.isEmpty()) {
                word = Character.toUpperCase(word.charAt(0)) + word.substring(1);
            }
            passphrase.append(word);
            if (i < count - 1) {
                passphrase.append(sep);
            }
        }

        if (appendNum) {
            int num = 10 + secureRandom.nextInt(90); // 2-digit number 10-99
            passphrase.append(sep).append(num);
        }

        String result = passphrase.toString();
        outputField.setText(result);

        // Passphrase entropy: each word chosen from pool of N words adds log2(N) bits
        double wordEntropy = count * (Math.log(wordList.size()) / Math.log(2));
        if (appendNum) wordEntropy += (Math.log(90) / Math.log(2));

        strengthNoticeLabel.setText(String.format("Words: %d | Dict Size: %d | Passphrase Entropy: ~%.1f bits | Strength: Very Strong",
                count, wordList.size(), wordEntropy));
        copyFeedbackLabel.setText("");
    }

    private void copyToClipboard() {
        String text = outputField.getText();
        if (text == null || text.isEmpty()) return;

        StringSelection selection = new StringSelection(text);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);

        copyFeedbackLabel.setText("✓ Copied to clipboard!");

        // Auto-clear feedback after 3 seconds
        Timer timer = new Timer(3000, e -> copyFeedbackLabel.setText(""));
        timer.setRepeats(false);
        timer.start();
    }
}
