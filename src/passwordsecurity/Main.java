package passwordsecurity;

import passwordsecurity.web.WebServer;

import java.awt.Desktop;
import java.awt.GraphicsEnvironment;
import java.io.IOException;
import java.net.BindException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Entry point: starts the local web server and opens the suite in the default browser.
 *
 * Usage: java -cp bin passwordsecurity.Main [--port 8080] [--no-browser]
 */
public class Main {

    public static void main(String[] args) throws Exception {
        int port = 8080;
        boolean openBrowser = true;
        for (int i = 0; i < args.length; i++) {
            if ("--port".equals(args[i]) && i + 1 < args.length) port = Integer.parseInt(args[++i]);
            else if ("--no-browser".equals(args[i])) openBrowser = false;
        }

        Path root = findProjectRoot();
        WebServer server = new WebServer(root);
        int bound = bindWithFallback(server, port);
        String url = "http://localhost:" + bound + "/";

        System.out.println("==========================================================");
        System.out.println("  Password Security Suite is running");
        System.out.println("  Open: " + url);
        System.out.println("  (local only - press Ctrl+C to stop)");
        System.out.println("==========================================================");

        if (openBrowser) openInBrowser(url);
    }

    /** Tries the requested port, then the next 10, so a busy 8080 doesn't stop the app. */
    private static int bindWithFallback(WebServer server, int port) throws IOException {
        for (int p = port; p < port + 10; p++) {
            try {
                return server.start(p);
            } catch (BindException busy) {
                System.out.println("Port " + p + " is busy, trying " + (p + 1) + "...");
            }
        }
        return server.start(0);
    }

    /** The folder that contains web/: the working directory, or the parent of bin/. */
    private static Path findProjectRoot() {
        Path cwd = Paths.get("").toAbsolutePath();
        if (Files.isDirectory(cwd.resolve("web"))) return cwd;
        try {
            Path classes = Paths.get(Main.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            Path parent = classes.getParent();
            if (parent != null && Files.isDirectory(parent.resolve("web"))) return parent;
        } catch (Exception ignored) {
            // fall back to cwd
        }
        return cwd;
    }

    private static void openInBrowser(String url) {
        try {
            if (!GraphicsEnvironment.isHeadless() && Desktop.isDesktopSupported()
                    && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(new URI(url));
            }
        } catch (Exception e) {
            System.out.println("Could not open a browser automatically; open " + url + " manually.");
        }
    }
}
