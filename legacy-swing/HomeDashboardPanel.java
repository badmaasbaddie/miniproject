package passwordsecurity;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.function.Consumer;

/**
 * HomeDashboardPanel: Landing screen offering quick overview and shortcuts to all 9 modules.
 */
public class HomeDashboardPanel extends JPanel {

    private final Consumer<String> navigator;
    private final SessionStats sessionStats;

    public HomeDashboardPanel(Consumer<String> navigator, SessionStats sessionStats) {
        this.navigator = navigator;
        this.sessionStats = sessionStats;

        setLayout(new BorderLayout());
        setBackground(UITheme.CONTENT_BG);
        setBorder(new EmptyBorder(24, 28, 24, 28));

        initUI();
    }

    private void initUI() {
        // Top Banner
        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.setOpaque(false);

        JPanel header = UITheme.createHeader(
                "Password Security Suite",
                "An interactive educational laboratory for learning password cryptography and defense mechanisms"
        );
        topPanel.add(header, BorderLayout.WEST);

        // Security Notice Box
        JPanel noticeCard = UITheme.createCard();
        noticeCard.setLayout(new BorderLayout());
        noticeCard.setBackground(new Color(239, 246, 255)); // Soft blue
        noticeCard.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(191, 219, 254), 1),
                new EmptyBorder(10, 14, 10, 14)
        ));

        JLabel noticeLabel = new JLabel("<html><b>Academic Notice:</b> All simulations, dictionaries, and hashing tests run entirely in local memory for educational study. No real passwords are ever stored or transmitted.</html>");
        noticeLabel.setFont(UITheme.FONT_BODY);
        noticeLabel.setForeground(new Color(30, 64, 175));
        noticeCard.add(noticeLabel, BorderLayout.CENTER);

        JPanel northContainer = new JPanel(new BorderLayout(0, 12));
        northContainer.setOpaque(false);
        northContainer.add(topPanel, BorderLayout.NORTH);
        northContainer.add(noticeCard, BorderLayout.SOUTH);

        add(northContainer, BorderLayout.NORTH);

        // Center Grid of Module Cards
        JPanel gridPanel = new JPanel(new GridLayout(3, 3, 16, 16));
        gridPanel.setOpaque(false);
        gridPanel.setBorder(new EmptyBorder(16, 0, 0, 0));

        gridPanel.add(createModuleCard("1. Password Analyzer",
                "Evaluate password length, character sets, entropy, and detect weak patterns.",
                "ANALYZER", UITheme.PRIMARY_BLUE));

        gridPanel.add(createModuleCard("2. Password Generator",
                "Generate high-entropy passwords and passphrases using SecureRandom.",
                "GENERATOR", UITheme.SUCCESS_GREEN));

        gridPanel.add(createModuleCard("3. Crack-Time Estimator",
                "Compare mathematical combination sizes and hypothetical brute force cracking times.",
                "ESTIMATOR", UITheme.PURPLE_ACCENT));

        gridPanel.add(createModuleCard("4. Brute Force Sim",
                "Educational simulation demonstrating combination growth with password length.",
                "BRUTE_FORCE", UITheme.WARNING_AMBER));

        gridPanel.add(createModuleCard("5. Dictionary Attack Sim",
                "Simulate wordlist matching step-by-step against sample targets safely.",
                "DICTIONARY", UITheme.DANGER_RED));

        gridPanel.add(createModuleCard("6. Password Hashing Lab",
                "Compute SHA-256 digests and learn why salted PBKDF2/Argon2 is needed in production.",
                "HASHING_LAB", UITheme.PRIMARY_BLUE));

        gridPanel.add(createModuleCard("7. Hash Matching Demo",
                "Controlled reverse-lookup demonstration matching candidate words to digests.",
                "HASH_MATCHING", UITheme.PURPLE_ACCENT));

        gridPanel.add(createModuleCard("8. Login Security Demo",
                "Test salted PBKDF2 login, rate-limiting, and account lockout protections.",
                "LOGIN_SECURITY", UITheme.SUCCESS_GREEN));

        gridPanel.add(createModuleCard("9. Analytics Dashboard",
                "Review session statistics, strength distribution charts, and simulation reports.",
                "ANALYTICS", UITheme.SIDEBAR_BG));

        // Put in scroll pane for small screens
        JScrollPane scrollPane = new JScrollPane(gridPanel);
        scrollPane.setBorder(null);
        scrollPane.setOpaque(false);
        scrollPane.getViewport().setOpaque(false);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);

        add(scrollPane, BorderLayout.CENTER);
    }

    private JPanel createModuleCard(String title, String description, String targetView, Color accentColor) {
        JPanel card = UITheme.createCard();
        card.setLayout(new BorderLayout(0, 10));

        // Top strip / Title
        JPanel titlePanel = new JPanel(new BorderLayout());
        titlePanel.setOpaque(false);

        JLabel titleLbl = new JLabel(title);
        titleLbl.setFont(UITheme.FONT_SECTION);
        titleLbl.setForeground(UITheme.TEXT_PRIMARY);

        JPanel colorBar = new JPanel();
        colorBar.setPreferredSize(new Dimension(4, 20));
        colorBar.setBackground(accentColor);

        titlePanel.add(colorBar, BorderLayout.WEST);
        titlePanel.add(Box.createHorizontalStrut(8), BorderLayout.CENTER);
        titlePanel.add(titleLbl, BorderLayout.EAST);

        // Description
        JLabel descLbl = new JLabel("<html><body style='width: 170px;'>" + description + "</body></html>");
        descLbl.setFont(UITheme.FONT_BODY);
        descLbl.setForeground(UITheme.TEXT_SECONDARY);

        // Action Button
        JButton launchBtn = UITheme.createButton("Open Module →", accentColor, Color.WHITE);
        launchBtn.setFont(UITheme.FONT_SMALL);
        launchBtn.addActionListener(e -> navigator.accept(targetView));

        card.add(titlePanel, BorderLayout.NORTH);
        card.add(descLbl, BorderLayout.CENTER);
        card.add(launchBtn, BorderLayout.SOUTH);

        return card;
    }
}
