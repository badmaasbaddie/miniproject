package passwordsecurity.web;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import passwordsecurity.core.AttackSimulations;
import passwordsecurity.core.CrackTimeEstimator;
import passwordsecurity.core.Hashing;
import passwordsecurity.core.LoginService;
import passwordsecurity.core.PasswordAnalyzer;
import passwordsecurity.core.PasswordGenerator;
import passwordsecurity.core.SecurityMath;
import passwordsecurity.core.SessionStats;
import passwordsecurity.core.Wordlists;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Local web server for the Password Security Suite.
 * Serves the HTML/CSS/JS front-end from {@code web/} and a small JSON API under {@code /api/}.
 * Binds to 127.0.0.1 only; passwords sent to the API are processed in memory and never logged or stored.
 */
public final class WebServer {

    private final Path webRoot;
    private final Path dictionaryFile;
    private final SessionStats stats = new SessionStats();
    private final LoginService login = new LoginService();
    private final List<String> dictionary;
    private HttpServer server;
    private ExecutorService executor;

    /** Thrown by handlers to send a 400 with a friendly message. */
    private static final class BadRequest extends RuntimeException {
        private static final long serialVersionUID = 1L;
        BadRequest(String msg) { super(msg); }
    }

    public WebServer(Path projectRoot) {
        this.webRoot = projectRoot.resolve("web").toAbsolutePath().normalize();
        this.dictionaryFile = projectRoot.resolve("data").resolve("sample_words.txt");
        this.dictionary = Wordlists.loadDictionary(dictionaryFile);
    }

    /** Starts on {@code port} (0 = any free port) and returns the port actually bound. */
    public int start(int port) throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 0);
        server.createContext("/", this::handle);
        executor = Executors.newFixedThreadPool(4, r -> {
            Thread t = new Thread(r, "pss-http");
            t.setDaemon(true);
            return t;
        });
        server.setExecutor(executor);
        server.start();
        return server.getAddress().getPort();
    }

    public void stop() {
        if (server != null) server.stop(0);
        if (executor != null) executor.shutdownNow();
    }

    public SessionStats stats() {
        return stats;
    }

    // ------------------------------------------------------------------ dispatch

    private void handle(HttpExchange ex) throws IOException {
        try {
            if (!isLocalHost(ex.getRequestHeaders().getFirst("Host"))) {
                send(ex, 403, "text/plain", "Forbidden");
                return;
            }
            String path = ex.getRequestURI().getPath();
            if (path.startsWith("/api/")) {
                handleApi(ex, path.substring(4));
            } else {
                serveStatic(ex, path);
            }
        } catch (BadRequest e) {
            sendJson(ex, 400, Json.obj("error", e.getMessage()));
        } catch (IllegalArgumentException e) {
            sendJson(ex, 400, Json.obj("error", e.getMessage()));
        } catch (Exception e) {
            sendJson(ex, 500, Json.obj("error", "Internal error: " + e.getClass().getSimpleName()));
        } finally {
            ex.close();
        }
    }

    /** Rejects requests whose Host is not loopback (guards against DNS-rebinding). */
    private static boolean isLocalHost(String host) {
        if (host == null) return true;
        String h = host.replaceFirst(":\\d+$", "").toLowerCase();
        return h.equals("localhost") || h.equals("127.0.0.1") || h.equals("[::1]");
    }

    private void handleApi(HttpExchange ex, String route) throws IOException {
        String method = ex.getRequestMethod();
        Map<String, String> p = "POST".equals(method) ? parseForm(readBody(ex)) : parseForm(ex.getRequestURI().getRawQuery());

        switch (method + " " + route) {
            case "POST /analyze":              sendJson(ex, 200, analyze(p)); return;
            case "POST /generate/password":    sendJson(ex, 200, generatePassword(p)); return;
            case "POST /generate/passphrase":  sendJson(ex, 200, generatePassphrase(p)); return;
            case "POST /bruteforce/space":     sendJson(ex, 200, bruteForceSpace(p)); return;
            case "POST /bruteforce/run":       sendJson(ex, 200, bruteForceRun(p)); return;
            case "GET /dictionary":            sendJson(ex, 200, dictionaryWords()); return;
            case "POST /dictionary/add":       sendJson(ex, 200, dictionaryAdd(p)); return;
            case "POST /dictionary/reset":     sendJson(ex, 200, dictionaryReset()); return;
            case "POST /dictionary/run":       sendJson(ex, 200, dictionaryRun(p)); return;
            case "POST /hash":                 sendJson(ex, 200, hash(p)); return;
            case "POST /hash/demo":            sendJson(ex, 200, hashDemo(p)); return;
            case "GET /hashmatch":             sendJson(ex, 200, hashMatchSamples()); return;
            case "POST /hashmatch/run":        sendJson(ex, 200, hashMatchRun(p)); return;
            case "GET /login/accounts":        sendJson(ex, 200, loginAccounts()); return;
            case "GET /login/status":          sendJson(ex, 200, loginStatus(p)); return;
            case "POST /login":                sendJson(ex, 200, loginAttempt(p)); return;
            case "POST /login/reset":          sendJson(ex, 200, loginReset(p)); return;
            case "GET /estimate/rates":        sendJson(ex, 200, rates()); return;
            case "POST /estimate":             sendJson(ex, 200, estimate(p)); return;
            case "GET /ping":                  sendJson(ex, 200, Json.obj("app", "password-security-suite")); return;
            case "GET /stats":                 sendJson(ex, 200, statsJson()); return;
            case "POST /stats/reset":          stats.resetAll(); sendJson(ex, 200, statsJson()); return;
            case "GET /report":                sendReport(ex); return;
            default:                           sendJson(ex, 404, Json.obj("error", "Unknown API route: " + method + " " + route));
        }
    }

    // ------------------------------------------------------------------ Module 1

    private Map<String, Object> analyze(Map<String, String> p) {
        PasswordAnalyzer.Result r = PasswordAnalyzer.analyze(p.getOrDefault("password", ""));
        boolean record = "1".equals(p.get("record")) && r.length > 0;
        if (record) stats.recordAnalysis(r.score, r.category, r.entropy, r.crackTime);
        return Json.obj(
                "length", r.length, "hasUpper", r.hasUpper, "hasLower", r.hasLower,
                "hasDigit", r.hasDigit, "hasSymbol", r.hasSymbol, "poolSize", r.poolSize,
                "entropy", r.entropy, "score", r.score, "category", r.category,
                "crackTime", r.crackTime, "warnings", r.warnings, "recorded", record);
    }

    // ------------------------------------------------------------------ Module 2

    private Map<String, Object> generatePassword(Map<String, String> p) {
        PasswordGenerator.Result r = PasswordGenerator.generatePassword(
                intParam(p, "length", 16), flag(p, "upper"), flag(p, "lower"),
                flag(p, "digits"), flag(p, "symbols"), flag(p, "excludeAmbiguous"));
        return Json.obj("value", r.value, "poolSize", r.poolSize, "entropy", r.entropy, "strength", r.strength);
    }

    private Map<String, Object> generatePassphrase(Map<String, String> p) {
        String sep = p.getOrDefault("separator", "-");
        if (!sep.matches("[- ._]?")) throw new BadRequest("Separator must be one of - . _ space or none.");
        PasswordGenerator.Result r = PasswordGenerator.generatePassphrase(
                intParam(p, "words", 4), sep, flag(p, "capitalize"), flag(p, "appendNumber"));
        return Json.obj("value", r.value, "poolSize", r.poolSize, "entropy", r.entropy, "strength", r.strength);
    }

    // ------------------------------------------------------------------ Module 3

    private String bfPool(Map<String, String> p) {
        return AttackSimulations.buildPool(flag(p, "digits"), flag(p, "lower"), flag(p, "upper"), flag(p, "symbols"));
    }

    private Map<String, Object> bruteForceSpace(Map<String, String> p) {
        String pool = bfPool(p);
        int len = p.getOrDefault("target", "").length();
        BigInteger combos = SecurityMath.combinations(pool.length(), len);
        return Json.obj("poolSize", pool.length(), "combinations", SecurityMath.formatBig(combos),
                "estimate", SecurityMath.formatDuration(combos, BigInteger.valueOf(100_000_000L)));
    }

    private Map<String, Object> bruteForceRun(Map<String, String> p) {
        AttackSimulations.BruteForceResult r = AttackSimulations.bruteForce(p.getOrDefault("target", ""), bfPool(p));
        stats.recordBruteForceSimulation();
        return Json.obj("found", r.found, "capped", r.capped, "attempts", r.attempts,
                "elapsedMs", r.elapsedNanos / 1_000_000.0,
                "timeLimitSeconds", AttackSimulations.TIME_LIMIT_MS / 1000,
                "attemptsPerSecond", r.attemptsPerSecond, "projectedFullSearch", r.projectedFullSearch,
                "totalCombinations", SecurityMath.formatBig(r.totalCombinations),
                "totalCombinationsRaw", r.totalCombinations.toString(), "samples", r.samples);
    }

    // ------------------------------------------------------------------ Module 4

    private Map<String, Object> dictionaryWords() {
        synchronized (dictionary) {
            return Json.obj("words", new ArrayList<>(dictionary));
        }
    }

    private Map<String, Object> dictionaryAdd(Map<String, String> p) {
        String word = p.getOrDefault("word", "").trim();
        if (word.isEmpty()) throw new BadRequest("Enter a word to add.");
        if (word.length() > 64) throw new BadRequest("Words are limited to 64 characters.");
        synchronized (dictionary) {
            if (dictionary.contains(word)) throw new BadRequest("'" + word + "' is already in the wordlist.");
            dictionary.add(word);
        }
        return dictionaryWords();
    }

    private Map<String, Object> dictionaryReset() {
        List<String> fresh = Wordlists.loadDictionary(dictionaryFile);
        synchronized (dictionary) {
            dictionary.clear();
            dictionary.addAll(fresh);
        }
        return dictionaryWords();
    }

    private Map<String, Object> dictionaryRun(Map<String, String> p) {
        String target = p.getOrDefault("target", "").trim();
        if (target.isEmpty()) throw new BadRequest("Enter a target password to test.");
        int index;
        int total;
        synchronized (dictionary) {
            index = AttackSimulations.dictionaryAttack(target, dictionary);
            total = dictionary.size();
        }
        stats.recordDictionarySimulation();
        return Json.obj("found", index > 0, "index", index, "total", total);
    }

    // ------------------------------------------------------------------ Module 5

    private Map<String, Object> hash(Map<String, String> p) {
        String input = p.getOrDefault("input", "");
        stats.recordHashingTest();
        return Json.obj("hash", Hashing.sha256(input));
    }

    private Map<String, Object> hashDemo(Map<String, String> p) {
        String type = p.getOrDefault("type", "");
        Map<String, Object> out;
        switch (type) {
            case "determinism": {
                String input = p.getOrDefault("input", "");
                if (input.isEmpty()) input = "SampleSecret";
                List<String> runs = new ArrayList<>();
                for (int i = 0; i < 4; i++) runs.add(Hashing.sha256(input));
                out = Json.obj("input", input, "runs", runs);
                break;
            }
            case "avalanche": {
                String base = "Password123";
                String h0 = Hashing.sha256(base);
                List<Object> rows = new ArrayList<>();
                rows.add(Json.obj("input", base, "change", "Original", "hash", h0, "bitsChanged", 0));
                String[][] variants = {{"password123", "Changed 'P' to 'p'"}, {"Password124", "Changed '3' to '4'"}};
                for (String[] v : variants) {
                    String h = Hashing.sha256(v[0]);
                    rows.add(Json.obj("input", v[0], "change", v[1], "hash", h, "bitsChanged", Hashing.bitDifference(h0, h)));
                }
                out = Json.obj("rows", rows, "totalBits", 256);
                break;
            }
            case "salt": {
                String pwd = "password123";
                String saltA = Hashing.toHex(Hashing.randomBytes(8));
                String saltB = Hashing.toHex(Hashing.randomBytes(8));
                out = Json.obj("password", pwd, "unsalted", Hashing.sha256(pwd),
                        "alice", Json.obj("salt", saltA, "hash", Hashing.sha256(saltA + pwd)),
                        "bob", Json.obj("salt", saltB, "hash", Hashing.sha256(saltB + pwd)));
                break;
            }
            default:
                throw new BadRequest("Unknown demo type.");
        }
        stats.recordHashingTest();
        return out;
    }

    // ------------------------------------------------------------------ Module 6

    private Map<String, Object> hashMatchSamples() {
        List<Object> targets = new ArrayList<>();
        for (String[] t : Wordlists.HASH_TARGETS) {
            targets.add(Json.obj("label", t[0], "hash", Hashing.sha256(t[1]), "description", t[2]));
        }
        return Json.obj("targets", targets, "candidates", Wordlists.HASH_CANDIDATES);
    }

    private Map<String, Object> hashMatchRun(Map<String, String> p) {
        List<AttackSimulations.HashMatchStep> steps = AttackSimulations.hashMatch(p.getOrDefault("hash", ""), Wordlists.HASH_CANDIDATES);
        stats.recordHashingTest();
        List<Object> out = new ArrayList<>();
        boolean found = false;
        for (AttackSimulations.HashMatchStep s : steps) {
            out.add(Json.obj("word", s.word, "hash", s.hash, "match", s.match));
            found |= s.match;
        }
        return Json.obj("found", found, "steps", out, "total", Wordlists.HASH_CANDIDATES.size());
    }

    // ------------------------------------------------------------------ Module 7

    private Map<String, Object> loginAccounts() {
        Map<String, String> demoPasswords = new HashMap<>();
        for (String[] d : LoginService.DEMO_ACCOUNTS) demoPasswords.put(d[0], d[1]);
        List<Object> list = new ArrayList<>();
        for (LoginService.Account a : login.accounts()) {
            list.add(Json.obj("username", a.username, "demoPassword", demoPasswords.get(a.username),
                    "salt", a.saltHex, "hash", a.hashHex));
        }
        return Json.obj("accounts", list, "maxAttempts", LoginService.MAX_ATTEMPTS,
                "lockoutSeconds", LoginService.LOCKOUT_MS / 1000, "iterations", Hashing.PBKDF2_ITERATIONS);
    }

    private Map<String, Object> loginStatus(Map<String, String> p) {
        LoginService.Result r = login.status(p.getOrDefault("username", ""));
        if (r == null) return Json.obj("known", false);
        return Json.obj("known", true, "remainingAttempts", r.remainingAttempts, "lockRemainingMs", r.lockRemainingMs);
    }

    private Map<String, Object> loginAttempt(Map<String, String> p) {
        String username = p.getOrDefault("username", "").trim();
        LoginService.Result r = login.attempt(username, p.getOrDefault("password", "").toCharArray());
        if (r.outcome != LoginService.Outcome.INVALID) {
            stats.recordLoginAttempt(r.outcome == LoginService.Outcome.LOCKED_NOW);
        }
        String time = new SimpleDateFormat("HH:mm:ss").format(new Date());
        return Json.obj("outcome", r.outcome.name(), "message", r.message, "remainingAttempts", r.remainingAttempts,
                "lockRemainingMs", r.lockRemainingMs, "time", time);
    }

    private Map<String, Object> loginReset(Map<String, String> p) {
        if (!login.reset(p.getOrDefault("username", "").trim())) throw new BadRequest("Unknown demo account.");
        return loginStatus(p);
    }

    // ------------------------------------------------------------------ Module 9

    private Map<String, Object> rates() {
        List<Object> list = new ArrayList<>();
        for (int i = 0; i < CrackTimeEstimator.RATE_NAMES.length; i++) {
            list.add(Json.obj("name", CrackTimeEstimator.RATE_NAMES[i], "perSecond", CrackTimeEstimator.RATE_VALUES[i]));
        }
        return Json.obj("rates", list);
    }

    private Map<String, Object> estimate(Map<String, String> p) {
        CrackTimeEstimator.Estimate a = CrackTimeEstimator.estimate(p.getOrDefault("p1", ""));
        CrackTimeEstimator.Estimate b = CrackTimeEstimator.estimate(p.getOrDefault("p2", ""));
        return Json.obj("p1", estimateJson(a), "p2", estimateJson(b), "insight", CrackTimeEstimator.compare(a, b));
    }

    private static Map<String, Object> estimateJson(CrackTimeEstimator.Estimate e) {
        return Json.obj("length", e.length, "poolSize", e.poolSize, "entropy", e.entropy,
                "combinations", SecurityMath.formatBig(e.combinations),
                "averageTimes", e.averageTimes, "worstTimes", e.worstTimes);
    }

    // ------------------------------------------------------------------ Module 8

    private Map<String, Object> statsJson() {
        List<Object> history = new ArrayList<>();
        for (SessionStats.AnalysisRecord r : stats.getAnalysisHistory()) {
            history.add(Json.obj("timestamp", r.getTimestamp(), "score", r.getScore(), "category", r.getCategory(),
                    "entropy", r.getEntropy(), "crackTime", r.getCrackTimeEst()));
        }
        return Json.obj(
                "totalAnalyzed", stats.getTotalAnalyzed(), "averageScore", stats.getAverageScore(),
                "weak", stats.getWeakCount(), "medium", stats.getMediumCount(), "strong", stats.getStrongCount(),
                "bruteForce", stats.getBruteForceSimCount(), "dictionary", stats.getDictionarySimCount(),
                "hashing", stats.getHashingTestsCount(), "loginAttempts", stats.getLoginAttemptsCount(),
                "lockouts", stats.getLoginLockoutCount(), "history", history);
    }

    private void sendReport(HttpExchange ex) throws IOException {
        String name = "security_report_" + new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date()) + ".txt";
        ex.getResponseHeaders().set("Content-Disposition", "attachment; filename=\"" + name + "\"");
        send(ex, 200, "text/plain; charset=utf-8", stats.buildReport());
    }

    // ------------------------------------------------------------------ static files

    private void serveStatic(HttpExchange ex, String path) throws IOException {
        if (!"GET".equals(ex.getRequestMethod()) && !"HEAD".equals(ex.getRequestMethod())) {
            send(ex, 405, "text/plain", "Method not allowed");
            return;
        }
        if (path.equals("/")) path = "/index.html";
        Path file = webRoot.resolve(path.substring(1)).normalize();
        if (!file.startsWith(webRoot) || !Files.isRegularFile(file)) {
            send(ex, 404, "text/plain", "Not found");
            return;
        }
        byte[] body = Files.readAllBytes(file);
        ex.getResponseHeaders().set("Content-Type", contentType(file.getFileName().toString()));
        ex.getResponseHeaders().set("Cache-Control", "no-cache");
        ex.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        ex.sendResponseHeaders(200, body.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(body);
        }
    }

    private static String contentType(String name) {
        if (name.endsWith(".html")) return "text/html; charset=utf-8";
        if (name.endsWith(".css")) return "text/css; charset=utf-8";
        if (name.endsWith(".js")) return "text/javascript; charset=utf-8";
        if (name.endsWith(".svg")) return "image/svg+xml";
        if (name.endsWith(".png")) return "image/png";
        if (name.endsWith(".ico")) return "image/x-icon";
        return "application/octet-stream";
    }

    // ------------------------------------------------------------------ helpers

    private static String readBody(HttpExchange ex) throws IOException {
        try (InputStream in = ex.getRequestBody()) {
            byte[] data = in.readNBytes(64 * 1024 + 1);
            if (data.length > 64 * 1024) throw new BadRequest("Request too large.");
            return new String(data, StandardCharsets.UTF_8);
        }
    }

    static Map<String, String> parseForm(String raw) {
        Map<String, String> m = new HashMap<>();
        if (raw == null || raw.isEmpty()) return m;
        for (String pair : raw.split("&")) {
            int eq = pair.indexOf('=');
            String k = eq < 0 ? pair : pair.substring(0, eq);
            String v = eq < 0 ? "" : pair.substring(eq + 1);
            m.put(URLDecoder.decode(k, StandardCharsets.UTF_8), URLDecoder.decode(v, StandardCharsets.UTF_8));
        }
        return m;
    }

    private static boolean flag(Map<String, String> p, String key) {
        String v = p.get(key);
        return "1".equals(v) || "true".equals(v) || "on".equals(v);
    }

    private static int intParam(Map<String, String> p, String key, int def) {
        String v = p.get(key);
        if (v == null || v.isEmpty()) return def;
        try {
            return Integer.parseInt(v.trim());
        } catch (NumberFormatException e) {
            throw new BadRequest("'" + key + "' must be a whole number.");
        }
    }

    private static void sendJson(HttpExchange ex, int status, Object body) throws IOException {
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        send(ex, status, "application/json; charset=utf-8", Json.write(body));
    }

    private static void send(HttpExchange ex, int status, String type, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", type);
        ex.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }
}
