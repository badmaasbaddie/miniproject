package passwordsecurity;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * MainFrame: Primary window of the Password Security Suite.
 * Features a modern left sidebar navigation and CardLayout right content area.
 */
public class MainFrame extends JFrame {

    public static final String CARD_HOME = "HOME";
    public static final String CARD_ANALYZER = "ANALYZER";
    public static final String CARD_GENERATOR = "GENERATOR";
    public static final String CARD_ESTIMATOR = "ESTIMATOR";
    public static final String CARD_BRUTE_FORCE = "BRUTE_FORCE";
    public static final String CARD_DICTIONARY = "DICTIONARY";
    public static final String CARD_HASHING_LAB = "HASHING_LAB";
    public static final String CARD_HASH_MATCHING = "HASH_MATCHING";
    public static final String CARD_LOGIN_SECURITY = "LOGIN_SECURITY";
    public static final String CARD_ANALYTICS = "ANALYTICS";

    private final CardLayout cardLayout = new CardLayout();
    private final JPanel contentCardsPanel = new JPanel(cardLayout);
    private final Map<String, JButton> navButtons = new LinkedHashMap<>();

    private final SessionStats sessionStats = new SessionStats();

    // Module panels
    private HomeDashboardPanel homeDashboardPanel;
    private PasswordAnalyzer passwordAnalyzerPanel;
    private PasswordGenerator passwordGeneratorPanel;
    private CrackTimeEstimator crackTimeEstimatorPanel;
    private BruteForceSimulator bruteForceSimulatorPanel;
    private DictionaryAttackSimulator dictionaryAttackSimulatorPanel;
    private PasswordHashingLab passwordHashingLabPanel;
    private HashMatchingDemo hashMatchingDemoPanel;
    private LoginSecurityDemo loginSecurityDemoPanel;
    private AnalyticsDashboard analyticsDashboardPanel;

    private String currentCard = CARD_HOME;

    public MainFrame() {
        setTitle("Password Security Suite - Educational Cybersecurity Lab");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setMinimumSize(new Dimension(1120, 740));
        setPreferredSize(new Dimension(1180, 780));
        setLocationRelativeTo(null);

        initModules();
        initUI();
        navigateTo(CARD_HOME);
    }

    private void initModules() {
        homeDashboardPanel = new HomeDashboardPanel(this::navigateTo, sessionStats);
        passwordAnalyzerPanel = new PasswordAnalyzer(sessionStats);
        passwordGeneratorPanel = new PasswordGenerator();
        crackTimeEstimatorPanel = new CrackTimeEstimator();
        bruteForceSimulatorPanel = new BruteForceSimulator(sessionStats);
        dictionaryAttackSimulatorPanel = new DictionaryAttackSimulator(sessionStats);
        passwordHashingLabPanel = new PasswordHashingLab(sessionStats);
        hashMatchingDemoPanel = new HashMatchingDemo(sessionStats);
        loginSecurityDemoPanel = new LoginSecurityDemo(sessionStats);
        analyticsDashboardPanel = new AnalyticsDashboard(sessionStats);

        contentCardsPanel.add(homeDashboardPanel, CARD_HOME);
        contentCardsPanel.add(passwordAnalyzerPanel, CARD_ANALYZER);
        contentCardsPanel.add(passwordGeneratorPanel, CARD_GENERATOR);
        contentCardsPanel.add(crackTimeEstimatorPanel, CARD_ESTIMATOR);
        contentCardsPanel.add(bruteForceSimulatorPanel, CARD_BRUTE_FORCE);
        contentCardsPanel.add(dictionaryAttackSimulatorPanel, CARD_DICTIONARY);
        contentCardsPanel.add(passwordHashingLabPanel, CARD_HASHING_LAB);
        contentCardsPanel.add(hashMatchingDemoPanel, CARD_HASH_MATCHING);
        contentCardsPanel.add(loginSecurityDemoPanel, CARD_LOGIN_SECURITY);
        contentCardsPanel.add(analyticsDashboardPanel, CARD_ANALYTICS);
    }

    private void initUI() {
        Container container = getContentPane();
        container.setLayout(new BorderLayout());

        // Left Navigation Sidebar
        JPanel sidebar = createSidebar();
        container.add(sidebar, BorderLayout.WEST);

        // Content Area
        container.add(contentCardsPanel, BorderLayout.CENTER);
    }

    private JPanel createSidebar() {
        JPanel sidebar = new JPanel(new BorderLayout());
        sidebar.setBackground(UITheme.SIDEBAR_BG);
        sidebar.setPreferredSize(new Dimension(250, 0));
        sidebar.setBorder(new EmptyBorder(16, 12, 16, 12));

        // Sidebar Header
        JPanel brandPanel = new JPanel(new BorderLayout(0, 4));
        brandPanel.setOpaque(false);
        brandPanel.setBorder(new EmptyBorder(8, 8, 20, 8));

        JLabel titleLabel = new JLabel("Security Suite");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 19));
        titleLabel.setForeground(Color.WHITE);

        JLabel subtitleLabel = new JLabel("Java Cybersecurity Lab");
        subtitleLabel.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        subtitleLabel.setForeground(UITheme.SIDEBAR_MUTED);

        brandPanel.add(titleLabel, BorderLayout.NORTH);
        brandPanel.add(subtitleLabel, BorderLayout.SOUTH);

        sidebar.add(brandPanel, BorderLayout.NORTH);

        // Navigation Button List
        JPanel navList = new JPanel();
        navList.setLayout(new BoxLayout(navList, BoxLayout.Y_AXIS));
        navList.setOpaque(false);

        addNavButton(navList, "Home Dashboard", CARD_HOME);
        addNavSectionDivider(navList, "ANALYSIS & GENERATION");
        addNavButton(navList, "Password Analyzer", CARD_ANALYZER);
        addNavButton(navList, "Password Generator", CARD_GENERATOR);
        addNavButton(navList, "Crack-Time Estimator", CARD_ESTIMATOR);

        addNavSectionDivider(navList, "ATTACK SIMULATIONS");
        addNavButton(navList, "Brute Force Simulation", CARD_BRUTE_FORCE);
        addNavButton(navList, "Dictionary Attack Sim", CARD_DICTIONARY);

        addNavSectionDivider(navList, "CRYPTOGRAPHY & DEFENSE");
        addNavButton(navList, "Password Hashing Lab", CARD_HASHING_LAB);
        addNavButton(navList, "Hash Matching Demo", CARD_HASH_MATCHING);
        addNavButton(navList, "Login Security Demo", CARD_LOGIN_SECURITY);

        addNavSectionDivider(navList, "REPORTS");
        addNavButton(navList, "Analytics Dashboard", CARD_ANALYTICS);

        JScrollPane navScroll = new JScrollPane(navList);
        navScroll.setBorder(null);
        navScroll.setOpaque(false);
        navScroll.getViewport().setOpaque(false);
        navScroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        sidebar.add(navScroll, BorderLayout.CENTER);

        // Sidebar Footer
        JPanel footer = new JPanel(new BorderLayout(0, 8));
        footer.setOpaque(false);
        footer.setBorder(new EmptyBorder(12, 4, 4, 4));

        JButton resetBtn = new JButton("Reset Session Data");
        resetBtn.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        resetBtn.setForeground(UITheme.SIDEBAR_MUTED);
        resetBtn.setBackground(UITheme.SIDEBAR_HOVER);
        resetBtn.setFocusPainted(false);
        resetBtn.setBorder(new EmptyBorder(6, 10, 6, 10));
        resetBtn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        resetBtn.addActionListener(e -> {
            int confirm = JOptionPane.showConfirmDialog(
                    this,
                    "Are you sure you want to reset all session statistics?",
                    "Confirm Reset",
                    JOptionPane.YES_NO_OPTION
            );
            if (confirm == JOptionPane.YES_OPTION) {
                sessionStats.resetAll();
                JOptionPane.showMessageDialog(this, "Session data reset successfully.");
                if (CARD_ANALYTICS.equals(currentCard)) {
                    navigateTo(CARD_ANALYTICS);
                }
            }
        });

        JLabel academicBadge = new JLabel("College Edition v1.0", SwingConstants.CENTER);
        academicBadge.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        academicBadge.setForeground(UITheme.SIDEBAR_MUTED);

        footer.add(resetBtn, BorderLayout.NORTH);
        footer.add(academicBadge, BorderLayout.SOUTH);

        sidebar.add(footer, BorderLayout.SOUTH);

        return sidebar;
    }

    private void addNavSectionDivider(JPanel parent, String title) {
        JLabel sectionLabel = new JLabel(title);
        sectionLabel.setFont(new Font("Segoe UI", Font.BOLD, 10));
        sectionLabel.setForeground(UITheme.SIDEBAR_MUTED);
        sectionLabel.setBorder(new EmptyBorder(14, 10, 6, 4));
        sectionLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        parent.add(sectionLabel);
    }

    private void addNavButton(JPanel parent, String text, String cardKey) {
        JButton btn = new JButton(text);
        btn.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        btn.setForeground(UITheme.SIDEBAR_TEXT);
        btn.setBackground(UITheme.SIDEBAR_BG);
        btn.setHorizontalAlignment(SwingConstants.LEFT);
        btn.setBorder(new EmptyBorder(8, 12, 8, 12));
        btn.setFocusPainted(false);
        btn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        btn.setMaximumSize(new Dimension(Integer.MAX_VALUE, 36));
        btn.setAlignmentX(Component.LEFT_ALIGNMENT);
        btn.setOpaque(true);

        btn.addActionListener(e -> navigateTo(cardKey));

        // Hover effect for non-active buttons
        btn.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                if (!cardKey.equals(currentCard)) {
                    btn.setBackground(UITheme.SIDEBAR_HOVER);
                }
            }

            @Override
            public void mouseExited(java.awt.event.MouseEvent evt) {
                if (!cardKey.equals(currentCard)) {
                    btn.setBackground(UITheme.SIDEBAR_BG);
                }
            }
        });

        navButtons.put(cardKey, btn);
        parent.add(btn);
    }

    public void navigateTo(String cardKey) {
        currentCard = cardKey;
        cardLayout.show(contentCardsPanel, cardKey);

        // Update button highlights
        for (Map.Entry<String, JButton> entry : navButtons.entrySet()) {
            JButton btn = entry.getValue();
            if (entry.getKey().equals(cardKey)) {
                btn.setBackground(UITheme.SIDEBAR_ACTIVE);
                btn.setForeground(Color.WHITE);
                btn.setFont(new Font("Segoe UI", Font.BOLD, 13));
            } else {
                btn.setBackground(UITheme.SIDEBAR_BG);
                btn.setForeground(UITheme.SIDEBAR_TEXT);
                btn.setFont(new Font("Segoe UI", Font.PLAIN, 13));
            }
        }

        // Notify AnalyticsDashboard or other panels if they need refresh
        if (CARD_ANALYTICS.equals(cardKey) && analyticsDashboardPanel != null) {
            analyticsDashboardPanel.repaint();
        }
    }

    public SessionStats getSessionStats() {
        return sessionStats;
    }
}
