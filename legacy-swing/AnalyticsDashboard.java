package passwordsecurity;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

/**
 * Module 8: Reports and Analytics Dashboard
 * Aggregates non-sensitive session telemetry: password strength metrics,
 * a pure Swing custom distribution bar chart, simulation activity, and report export.
 */
public class AnalyticsDashboard extends JPanel {

    private final SessionStats sessionStats;

    // KPI Display Labels
    private JLabel totalAnalyzedLabel;
    private JLabel avgScoreLabel;
    private JLabel strongCountLabel;
    private JLabel mediumCountLabel;
    private JLabel weakCountLabel;

    // Simulation Summary Labels
    private JLabel bruteSimCountLabel;
    private JLabel dictSimCountLabel;
    private JLabel hashingTestCountLabel;
    private JLabel loginAttemptsCountLabel;
    private JLabel lockoutCountLabel;

    // Chart Component
    private StrengthChartPanel chartPanel;

    // History Table
    private DefaultTableModel tableModel;
    private JTable historyTable;

    public AnalyticsDashboard(SessionStats stats) {
        this.sessionStats = stats;

        setLayout(new BorderLayout());
        setBackground(UITheme.CONTENT_BG);
        setBorder(new EmptyBorder(20, 24, 20, 24));

        initUI();
    }

    private void initUI() {
        // Header
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setOpaque(false);

        JPanel titleBlock = UITheme.createHeader(
                "Module 8: Reports and Analytics Dashboard",
                "Session telemetry, strength distributions, attack simulation logs, and security reports"
        );
        headerPanel.add(titleBlock, BorderLayout.WEST);

        // Header Actions: Refresh & Export
        JPanel actionRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 10));
        actionRow.setOpaque(false);

        JButton refreshBtn = UITheme.createButton("🔄 Refresh Data", UITheme.SIDEBAR_HOVER, Color.WHITE);
        refreshBtn.setFont(UITheme.FONT_SMALL);
        refreshBtn.addActionListener(e -> refreshDashboard());

        JButton exportBtn = UITheme.createButton("💾 Export Report (TXT)", UITheme.PRIMARY_BLUE, Color.WHITE);
        exportBtn.setFont(UITheme.FONT_SMALL);
        exportBtn.addActionListener(e -> exportSessionReport());

        actionRow.add(refreshBtn);
        actionRow.add(exportBtn);
        headerPanel.add(actionRow, BorderLayout.EAST);

        add(headerPanel, BorderLayout.NORTH);

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setOpaque(false);

        // 1. Top KPI Summary Cards Row
        mainPanel.add(createKpiCardsRow());
        mainPanel.add(Box.createVerticalStrut(16));

        // 2. Center Row: Chart on Left, Lab Activity on Right
        mainPanel.add(createChartAndActivityRow());
        mainPanel.add(Box.createVerticalStrut(16));

        // 3. Bottom Row: Recent Non-Sensitive Analysis Log Table
        mainPanel.add(createHistoryTableCard());

        JScrollPane scrollPane = new JScrollPane(mainPanel);
        scrollPane.setBorder(null);
        scrollPane.setOpaque(false);
        scrollPane.getViewport().setOpaque(false);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);

        add(scrollPane, BorderLayout.CENTER);

        refreshDashboard();
    }

    private JPanel createKpiCardsRow() {
        JPanel row = new JPanel(new GridLayout(1, 5, 12, 0));
        row.setOpaque(false);

        totalAnalyzedLabel = new JLabel("0", SwingConstants.CENTER);
        avgScoreLabel = new JLabel("0.0", SwingConstants.CENTER);
        strongCountLabel = new JLabel("0", SwingConstants.CENTER);
        mediumCountLabel = new JLabel("0", SwingConstants.CENTER);
        weakCountLabel = new JLabel("0", SwingConstants.CENTER);

        row.add(createKpiCard("Total Analyzed", totalAnalyzedLabel, UITheme.TEXT_PRIMARY));
        row.add(createKpiCard("Average Score", avgScoreLabel, UITheme.PRIMARY_BLUE));
        row.add(createKpiCard("Strong Passwords", strongCountLabel, UITheme.SUCCESS_GREEN));
        row.add(createKpiCard("Medium Passwords", mediumCountLabel, UITheme.WARNING_AMBER));
        row.add(createKpiCard("Weak Passwords", weakCountLabel, UITheme.DANGER_RED));

        return row;
    }

    private JPanel createKpiCard(String title, JLabel valueLabel, Color accentColor) {
        JPanel card = UITheme.createCard();
        card.setLayout(new BorderLayout(0, 4));

        JLabel titleLbl = new JLabel(title, SwingConstants.CENTER);
        titleLbl.setFont(UITheme.FONT_SMALL);
        titleLbl.setForeground(UITheme.TEXT_SECONDARY);

        valueLabel.setFont(new Font("Segoe UI", Font.BOLD, 24));
        valueLabel.setForeground(accentColor);

        card.add(titleLbl, BorderLayout.NORTH);
        card.add(valueLabel, BorderLayout.CENTER);
        return card;
    }

    private JPanel createChartAndActivityRow() {
        JPanel row = new JPanel(new GridLayout(1, 2, 16, 0));
        row.setOpaque(false);

        // Chart Card
        JPanel chartCard = UITheme.createCard();
        chartCard.setLayout(new BorderLayout(0, 8));
        JLabel chartTitle = new JLabel("Password Strength Classification Chart");
        chartTitle.setFont(UITheme.FONT_SECTION);
        chartTitle.setForeground(UITheme.TEXT_PRIMARY);

        chartPanel = new StrengthChartPanel();
        chartPanel.setPreferredSize(new Dimension(300, 200));

        chartCard.add(chartTitle, BorderLayout.NORTH);
        chartCard.add(chartPanel, BorderLayout.CENTER);

        // Simulation Activity Card
        JPanel activityCard = UITheme.createCard();
        activityCard.setLayout(new BorderLayout(0, 10));

        JLabel actTitle = new JLabel("Security Lab Telemetry");
        actTitle.setFont(UITheme.FONT_SECTION);
        actTitle.setForeground(UITheme.TEXT_PRIMARY);

        JPanel actGrid = new JPanel(new GridLayout(5, 2, 12, 10));
        actGrid.setOpaque(false);

        bruteSimCountLabel = new JLabel("0");
        dictSimCountLabel = new JLabel("0");
        hashingTestCountLabel = new JLabel("0");
        loginAttemptsCountLabel = new JLabel("0");
        lockoutCountLabel = new JLabel("0");

        actGrid.add(createActLabel("Brute Force Simulations:"));
        actGrid.add(bruteSimCountLabel);
        actGrid.add(createActLabel("Dictionary Attack Runs:"));
        actGrid.add(dictSimCountLabel);
        actGrid.add(createActLabel("Hashing Lab Tests:"));
        actGrid.add(hashingTestCountLabel);
        actGrid.add(createActLabel("Total Login Attempts:"));
        actGrid.add(loginAttemptsCountLabel);
        actGrid.add(createActLabel("Account Lockouts Triggered:"));
        actGrid.add(lockoutCountLabel);

        activityCard.add(actTitle, BorderLayout.NORTH);
        activityCard.add(actGrid, BorderLayout.CENTER);

        row.add(chartCard);
        row.add(activityCard);

        return row;
    }

    private JLabel createActLabel(String text) {
        JLabel lbl = new JLabel(text);
        lbl.setFont(UITheme.FONT_BODY_BOLD);
        lbl.setForeground(UITheme.TEXT_SECONDARY);
        return lbl;
    }

    private JPanel createHistoryTableCard() {
        JPanel card = UITheme.createCard();
        card.setLayout(new BorderLayout(0, 10));

        JLabel title = new JLabel("Recent Password Evaluations (Non-Sensitive Telemetry Only)");
        title.setFont(UITheme.FONT_SECTION);
        title.setForeground(UITheme.TEXT_PRIMARY);

        String[] columns = {"Timestamp", "Score / 100", "Category", "Entropy (bits)", "Approx Crack Time"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        historyTable = new JTable(tableModel);
        historyTable.setFont(UITheme.FONT_BODY);
        historyTable.setRowHeight(24);
        historyTable.getTableHeader().setFont(UITheme.FONT_BODY_BOLD);

        JScrollPane tableScroll = new JScrollPane(historyTable);
        tableScroll.setPreferredSize(new Dimension(600, 150));

        JLabel noteLabel = new JLabel("Note: In compliance with zero-knowledge security standards, plaintext passwords are never recorded in logs or reports.");
        noteLabel.setFont(UITheme.FONT_SMALL);
        noteLabel.setForeground(UITheme.TEXT_MUTED);

        card.add(title, BorderLayout.NORTH);
        card.add(tableScroll, BorderLayout.CENTER);
        card.add(noteLabel, BorderLayout.SOUTH);

        return card;
    }

    /**
     * Refreshes the analytics dashboard with the latest session data.
     */
    public void refreshDashboard() {
        int total = sessionStats.getTotalAnalyzed();
        int weak = sessionStats.getWeakCount();
        int medium = sessionStats.getMediumCount();
        int strong = sessionStats.getStrongCount();
        double avgScore = sessionStats.getAverageScore();

        totalAnalyzedLabel.setText(String.valueOf(total));
        avgScoreLabel.setText(String.format("%.1f", avgScore));
        strongCountLabel.setText(String.valueOf(strong));
        mediumCountLabel.setText(String.valueOf(medium));
        weakCountLabel.setText(String.valueOf(weak));

        bruteSimCountLabel.setText(String.valueOf(sessionStats.getBruteForceSimCount()));
        dictSimCountLabel.setText(String.valueOf(sessionStats.getDictionarySimCount()));
        hashingTestCountLabel.setText(String.valueOf(sessionStats.getHashingTestsCount()));
        loginAttemptsCountLabel.setText(String.valueOf(sessionStats.getLoginAttemptsCount()));
        lockoutCountLabel.setText(String.valueOf(sessionStats.getLoginLockoutCount()));

        chartPanel.updateCounts(weak, medium, strong);

        // Update History Table
        tableModel.setRowCount(0);
        List<SessionStats.AnalysisRecord> history = sessionStats.getAnalysisHistory();
        SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss");

        for (int i = history.size() - 1; i >= 0; i--) {
            SessionStats.AnalysisRecord r = history.get(i);
            tableModel.addRow(new Object[]{
                    sdf.format(new Date(r.getTimestamp())),
                    r.getScore() + " / 100",
                    r.getCategory(),
                    String.format("%.1f", r.getEntropy()),
                    r.getCrackTimeEst()
            });
        }
    }

    @Override
    public void repaint() {
        super.repaint();
        if (sessionStats != null && totalAnalyzedLabel != null) {
            refreshDashboard();
        }
    }

    /**
     * Exports non-sensitive session statistics to a clean text file.
     */
    private void exportSessionReport() {
        try {
            File reportDir = new File("reports");
            if (!reportDir.exists()) reportDir.mkdirs();

            String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
            File reportFile = new File(reportDir, "security_report_" + timestamp + ".txt");

            try (PrintWriter writer = new PrintWriter(new FileWriter(reportFile))) {
                writer.println("==========================================================");
                writer.println("       PASSWORD SECURITY SUITE - SESSION REPORT          ");
                writer.println("==========================================================");
                writer.println("Generated At: " + new Date());
                writer.println("Academic Lab Version: College Edition v1.0");
                writer.println("Compliance: Strict Zero-Knowledge (No Passwords Logged)");
                writer.println();
                writer.println("----------------------------------------------------------");
                writer.println("1. PASSWORD EVALUATION METRICS");
                writer.println("----------------------------------------------------------");
                writer.println("Total Passwords Analyzed: " + sessionStats.getTotalAnalyzed());
                writer.println("Average Strength Score:   " + String.format("%.2f", sessionStats.getAverageScore()) + " / 100");
                writer.println("Strong Passwords Count:   " + sessionStats.getStrongCount());
                writer.println("Medium Passwords Count:   " + sessionStats.getMediumCount());
                writer.println("Weak Passwords Count:     " + sessionStats.getWeakCount());
                writer.println();
                writer.println("----------------------------------------------------------");
                writer.println("2. SECURITY LAB SIMULATION TELEMETRY");
                writer.println("----------------------------------------------------------");
                writer.println("Brute Force Simulations:  " + sessionStats.getBruteForceSimCount());
                writer.println("Dictionary Attack Runs:   " + sessionStats.getDictionarySimCount());
                writer.println("Hashing Tests Performed:  " + sessionStats.getHashingTestsCount());
                writer.println("Login Attempts Processed: " + sessionStats.getLoginAttemptsCount());
                writer.println("Account Lockouts Handled: " + sessionStats.getLoginLockoutCount());
                writer.println();
                writer.println("----------------------------------------------------------");
                writer.println("3. RECENT EVALUATION HISTORY (METADATA ONLY)");
                writer.println("----------------------------------------------------------");
                writer.printf("%-12s %-12s %-12s %-15s %s%n", "Time", "Score", "Rating", "Entropy (bits)", "Approx. Crack Time");
                writer.println("--------------------------------------------------------------------------------");

                SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss");
                for (SessionStats.AnalysisRecord r : sessionStats.getAnalysisHistory()) {
                    writer.printf("%-12s %-12s %-12s %-15.1f %s%n",
                            sdf.format(new Date(r.getTimestamp())),
                            r.getScore() + "/100",
                            r.getCategory(),
                            r.getEntropy(),
                            r.getCrackTimeEst());
                }
                writer.println();
                writer.println("==========================================================");
                writer.println("End of Academic Security Report.");
                writer.println("==========================================================");
            }

            JOptionPane.showMessageDialog(this,
                    "Session report successfully exported to:\n" + reportFile.getAbsolutePath(),
                    "Report Exported", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this,
                    "Failed to export report: " + ex.getMessage(),
                    "Export Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * Pure Swing custom component for drawing an elegant strength distribution bar chart.
     */
    private static class StrengthChartPanel extends JPanel {
        private int weak = 0;
        private int medium = 0;
        private int strong = 0;

        public StrengthChartPanel() {
            setBackground(Color.WHITE);
        }

        public void updateCounts(int weak, int medium, int strong) {
            this.weak = weak;
            this.medium = medium;
            this.strong = strong;
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            Graphics2D g2 = (Graphics2D) g;
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

            int width = getWidth();
            int height = getHeight();
            int total = weak + medium + strong;

            if (total == 0) {
                g2.setColor(UITheme.TEXT_MUTED);
                g2.setFont(UITheme.FONT_BODY);
                String msg = "No analysis data yet. Test passwords in Module 1 to populate.";
                FontMetrics fm = g2.getFontMetrics();
                int x = (width - fm.stringWidth(msg)) / 2;
                int y = height / 2;
                g2.drawString(msg, Math.max(10, x), y);
                return;
            }

            // Draw 3 Bars: Weak, Medium, Strong
            int barWidth = 60;
            int gap = (width - (barWidth * 3)) / 4;
            int bottomMargin = 40;
            int topMargin = 25;
            int maxBarHeight = height - bottomMargin - topMargin;

            int maxCount = Math.max(1, Math.max(weak, Math.max(medium, strong)));

            // 1. Weak Bar
            drawBar(g2, gap, bottomMargin, maxBarHeight, barWidth, weak, maxCount, "Weak", UITheme.DANGER_RED, total);

            // 2. Medium Bar
            drawBar(g2, gap * 2 + barWidth, bottomMargin, maxBarHeight, barWidth, medium, maxCount, "Medium", UITheme.WARNING_AMBER, total);

            // 3. Strong Bar
            drawBar(g2, gap * 3 + barWidth * 2, bottomMargin, maxBarHeight, barWidth, strong, maxCount, "Strong", UITheme.SUCCESS_GREEN, total);
        }

        private void drawBar(Graphics2D g2, int x, int bottomMargin, int maxBarHeight, int barWidth,
                             int count, int maxCount, String label, Color color, int total) {
            int barH = (int) (((double) count / maxCount) * maxBarHeight);
            int y = getHeight() - bottomMargin - barH;

            // Bar fill
            g2.setColor(color);
            g2.fillRoundRect(x, y, barWidth, barH, 8, 8);

            // Count & Percentage on top of bar
            g2.setColor(UITheme.TEXT_PRIMARY);
            g2.setFont(UITheme.FONT_SMALL);
            FontMetrics fm = g2.getFontMetrics();
            int pct = (int) Math.round(((double) count / total) * 100);
            String valStr = count + " (" + pct + "%)";
            int valX = x + (barWidth - fm.stringWidth(valStr)) / 2;
            g2.drawString(valStr, valX, y - 5);

            // Label below bar
            g2.setColor(UITheme.TEXT_SECONDARY);
            g2.setFont(UITheme.FONT_BODY_BOLD);
            fm = g2.getFontMetrics();
            int lblX = x + (barWidth - fm.stringWidth(label)) / 2;
            g2.drawString(label, lblX, getHeight() - bottomMargin + 20);
        }
    }
}
