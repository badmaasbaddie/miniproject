package passwordsecurity;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.EmptyBorder;
import java.awt.*;

/**
 * UITheme: Central styling and visual helper class for Password Security Suite.
 * Provides a clean, modern palette and reusable UI helpers without external libraries.
 */
public class UITheme {

    // Color Palette - Modern Slate & Vibrant Accents
    public static final Color SIDEBAR_BG = new Color(30, 41, 59);          // Slate 800
    public static final Color SIDEBAR_HOVER = new Color(51, 65, 85);       // Slate 700
    public static final Color SIDEBAR_ACTIVE = new Color(14, 165, 233);     // Sky 500
    public static final Color SIDEBAR_TEXT = new Color(226, 232, 240);      // Slate 200
    public static final Color SIDEBAR_MUTED = new Color(148, 163, 184);     // Slate 400

    public static final Color CONTENT_BG = new Color(248, 250, 252);       // Slate 50
    public static final Color CARD_BG = Color.WHITE;
    public static final Color CARD_BORDER = new Color(226, 232, 240);      // Slate 200

    public static final Color TEXT_PRIMARY = new Color(15, 23, 42);        // Slate 900
    public static final Color TEXT_SECONDARY = new Color(100, 116, 139);   // Slate 500
    public static final Color TEXT_MUTED = new Color(148, 163, 184);       // Slate 400

    public static final Color PRIMARY_BLUE = new Color(37, 99, 235);       // Blue 600
    public static final Color PRIMARY_HOVER = new Color(29, 78, 216);      // Blue 700
    public static final Color SUCCESS_GREEN = new Color(22, 163, 74);      // Green 600
    public static final Color WARNING_AMBER = new Color(217, 119, 6);      // Amber 600
    public static final Color DANGER_RED = new Color(220, 38, 38);         // Red 600
    public static final Color PURPLE_ACCENT = new Color(124, 58, 237);     // Purple 600

    // Standard Fonts
    public static final Font FONT_TITLE = new Font("Segoe UI", Font.BOLD, 20);
    public static final Font FONT_SUBTITLE = new Font("Segoe UI", Font.PLAIN, 13);
    public static final Font FONT_SECTION = new Font("Segoe UI", Font.BOLD, 15);
    public static final Font FONT_BODY = new Font("Segoe UI", Font.PLAIN, 13);
    public static final Font FONT_BODY_BOLD = new Font("Segoe UI", Font.BOLD, 13);
    public static final Font FONT_SMALL = new Font("Segoe UI", Font.PLAIN, 11);
    public static final Font FONT_MONO = new Font("Consolas", Font.PLAIN, 13);
    public static final Font FONT_MONO_BOLD = new Font("Consolas", Font.BOLD, 14);

    /**
     * Creates a card-style panel with a white background and subtle rounded border.
     */
    public static JPanel createCard() {
        JPanel card = new JPanel();
        card.setBackground(CARD_BG);
        card.setLayout(new BorderLayout());
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(CARD_BORDER, 1),
                new EmptyBorder(16, 18, 16, 18)
        ));
        return card;
    }

    /**
     * Creates a modern styled button with hover effect.
     */
    public static JButton createButton(String text, Color bg, Color fg) {
        JButton button = new JButton(text);
        button.setFont(FONT_BODY_BOLD);
        button.setBackground(bg);
        button.setForeground(fg);
        button.setFocusPainted(false);
        button.setBorder(new EmptyBorder(8, 16, 8, 16));
        button.setCursor(new Cursor(Cursor.HAND_CURSOR));
        button.setOpaque(true);

        // Simple hover listener
        button.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                button.setBackground(bg.darker());
            }

            @Override
            public void mouseExited(java.awt.event.MouseEvent evt) {
                button.setBackground(bg);
            }
        });

        return button;
    }

    /**
     * Creates a title header panel with module name and description.
     */
    public static JPanel createHeader(String title, String subtitle) {
        JPanel header = new JPanel(new GridLayout(2, 1, 0, 4));
        header.setOpaque(false);
        header.setBorder(new EmptyBorder(4, 0, 16, 0));

        JLabel titleLabel = new JLabel(title);
        titleLabel.setFont(FONT_TITLE);
        titleLabel.setForeground(TEXT_PRIMARY);

        JLabel subLabel = new JLabel(subtitle);
        subLabel.setFont(FONT_SUBTITLE);
        subLabel.setForeground(TEXT_SECONDARY);

        header.add(titleLabel);
        header.add(subLabel);
        return header;
    }

    /**
     * Creates a styled label with badge look.
     */
    public static JLabel createBadge(String text, Color bgColor) {
        JLabel badge = new JLabel(text, SwingConstants.CENTER);
        badge.setOpaque(true);
        badge.setBackground(bgColor);
        badge.setForeground(Color.WHITE);
        badge.setFont(FONT_BODY_BOLD);
        badge.setBorder(new EmptyBorder(4, 10, 4, 10));
        return badge;
    }
}
