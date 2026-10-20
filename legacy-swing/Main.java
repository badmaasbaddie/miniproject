package passwordsecurity;

import javax.swing.*;

/**
 * Main: Application entry point for Password Security Suite.
 * Sets up system look and feel and launches MainFrame on the Swing Event Dispatch Thread.
 */
public class Main {
    public static void main(String[] args) {
        // Set system look and feel for native rendering
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) {
            // Fall back to default Swing look and feel
        }

        // Launch UI on Event Dispatch Thread (EDT)
        SwingUtilities.invokeLater(() -> {
            MainFrame app = new MainFrame();
            app.setVisible(true);
        });
    }
}
