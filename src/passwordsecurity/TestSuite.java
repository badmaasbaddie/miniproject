package passwordsecurity;

import passwordsecurity.core.AttackSimulations;
import passwordsecurity.core.CrackTimeEstimator;
import passwordsecurity.core.Hashing;
import passwordsecurity.core.LoginService;
import passwordsecurity.core.PasswordAnalyzer;
import passwordsecurity.core.PasswordGenerator;
import passwordsecurity.core.SecurityMath;
import passwordsecurity.core.SessionStats;
import passwordsecurity.web.WebServer;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

/**
 * Automated tests for every module. Each test calls the real production code in
 * passwordsecurity.core, and the last group drives the HTTP API end to end.
 *
 * Run: java -cp bin passwordsecurity.TestSuite   (from the project root)
 */
public class TestSuite {

    private static int passed = 0;
    private static int total = 0;

    public static void main(String[] args) throws Exception {
        System.out.println("==========================================================");
        System.out.println("   PASSWORD SECURITY SUITE - AUTOMATED TEST SUITE");
        System.out.println("==========================================================");

        testAnalyzer();
        testGenerator();
        testBruteForce();
        testDictionary();
        testHashing();
        testHashMatching();
        testLogin();
        testSessionStats();
        testCrackTime();
        testWebApi();

        System.out.println("==========================================================");
        System.out.printf("Test Summary: %d / %d Tests Passed (%.1f%%)%n", passed, total, 100.0 * passed / total);
        System.out.println("==========================================================");
        if (passed == total) {
            System.out.println(">>> ALL AUTOMATED TEST CASES PASSED SUCCESSFULLY! <<<");
        } else {
            System.err.println(">>> SOME TESTS FAILED. INVESTIGATION REQUIRED. <<<");
            System.exit(1);
        }
    }

    private static void check(String name, boolean condition) {
        total++;
        if (condition) {
            passed++;
            System.out.println("[PASS] " + name);
        } else {
            System.err.println("[FAIL] " + name);
        }
    }

    // ---------------------------------------------------------------- Module 1
    private static void testAnalyzer() {
        PasswordAnalyzer.Result empty = PasswordAnalyzer.analyze("");
        check("Empty password scores 0 and is Weak", empty.score == 0 && "Weak".equals(empty.category));

        PasswordAnalyzer.Result shortPwd = PasswordAnalyzer.analyze("abc");
        check("Short password 'abc' is Weak (score < 45)", shortPwd.score < 45 && "Weak".equals(shortPwd.category));
        check("Short password warns about minimum length",
                shortPwd.warnings.stream().anyMatch(w -> w.contains("minimum")));

        PasswordAnalyzer.Result complex = PasswordAnalyzer.analyze("St0ng#P@ssw0rd!2026");
        check("Complex password detects all 4 character classes",
                complex.hasUpper && complex.hasLower && complex.hasDigit && complex.hasSymbol);
        check("Complex password pool size is 95", complex.poolSize == 95);
        check("Entropy for 19-char complex password exceeds 100 bits", complex.entropy > 100.0);

        PasswordAnalyzer.Result strong = PasswordAnalyzer.analyze("Vx7#qLm!2zR$wK9p");
        check("Random 16-char password is Strong", "Strong".equals(strong.category) && strong.warnings.isEmpty());

        check("Sequential run '123' detected", PasswordAnalyzer.hasSequentialRun("user12345"));
        check("Descending run 'cba' detected", PasswordAnalyzer.hasSequentialRun("xcbax"));
        check("Two repeats are not a triple repeat", !PasswordAnalyzer.hasTripleRepeat("passwword"));
        check("Triple repeat 'www' detected", PasswordAnalyzer.hasTripleRepeat("passwwword"));

        PasswordAnalyzer.Result common = PasswordAnalyzer.analyze("MyPassword2026!");
        check("Common word 'password' flagged case-insensitively",
                common.warnings.stream().anyMatch(w -> w.contains("'password'")));
    }

    // ---------------------------------------------------------------- Module 2
    private static void testGenerator() {
        PasswordGenerator.Result r = PasswordGenerator.generatePassword(24, true, true, true, true, false);
        check("Generated password has requested length", r.value.length() == 24);
        SecurityMath.Composition c = SecurityMath.compose(r.value);
        check("Generated password contains every selected class", c.hasUpper && c.hasLower && c.hasDigit && c.hasSymbol);

        PasswordGenerator.Result r2 = PasswordGenerator.generatePassword(24, true, true, true, true, false);
        check("Two generated passwords differ (SecureRandom)", !r.value.equals(r2.value));

        boolean noAmbiguous = true;
        for (int i = 0; i < 50; i++) {
            String v = PasswordGenerator.generatePassword(64, true, true, true, false, true).value;
            if (v.matches(".*[0OlI1].*")) noAmbiguous = false;
        }
        check("Exclude-ambiguous never emits 0 O l I 1", noAmbiguous);

        check("Empty character-set selection is rejected",
                throwsIAE(() -> PasswordGenerator.generatePassword(16, false, false, false, false, false)));
        check("Out-of-range length is rejected",
                throwsIAE(() -> PasswordGenerator.generatePassword(2, true, true, true, true, false)));

        PasswordGenerator.Result phrase = PasswordGenerator.generatePassphrase(4, "-", false, false);
        String[] words = phrase.value.split("-");
        check("Passphrase has 4 hyphen-separated words", words.length == 4);
        check("Passphrase words all come from the passphrase vocabulary",
                Arrays.stream(words).allMatch(PasswordGenerator.PASSPHRASE_WORDS::contains));

        PasswordGenerator.Result capNum = PasswordGenerator.generatePassphrase(3, ".", true, true);
        String[] parts = capNum.value.split("\\.");
        check("Capitalized passphrase with number has 3 words + 2-digit number",
                parts.length == 4 && Character.isUpperCase(parts[0].charAt(0)) && parts[3].matches("[1-9][0-9]"));
        check("3-word passphrase is not labelled Very Strong (entropy-based)",
                !"Very Strong".equals(PasswordGenerator.generatePassphrase(3, "-", false, false).strength));
    }

    // ---------------------------------------------------------------- Module 3
    private static void testBruteForce() {
        AttackSimulations.BruteForceResult r = AttackSimulations.bruteForce("429", AttackSimulations.BF_DIGITS);
        check("Brute force finds '429' at attempt #430", r.found && r.attempts == 430);

        AttackSimulations.BruteForceResult cat = AttackSimulations.bruteForce("cat", AttackSimulations.BF_LOWER);
        check("Brute force finds 'cat' in lowercase pool", cat.found);
        check("Search space for 3 lowercase chars is 17,576", cat.totalCombinations.equals(BigInteger.valueOf(17_576)));

        AttackSimulations.BruteForceResult capped = AttackSimulations.bruteForce("zzzzzz", AttackSimulations.BF_LOWER);
        check("Long target is capped at 50,000 attempts", !capped.found && capped.capped && capped.attempts == 50_000);

        check("Target character outside pool is rejected",
                throwsIAE(() -> AttackSimulations.bruteForce("ab1", AttackSimulations.BF_LOWER)));
    }

    // ---------------------------------------------------------------- Module 4
    private static void testDictionary() {
        List<String> dict = Arrays.asList("alpha", "bravo", "charlie", "delta", "echo");
        check("Dictionary match found at attempt #3", AttackSimulations.dictionaryAttack("charlie", dict) == 3);
        check("Missing word reported after full scan", AttackSimulations.dictionaryAttack("foxtrot", dict) == -1);
        check("Dictionary match is case-sensitive", AttackSimulations.dictionaryAttack("Charlie", dict) == -1);
    }

    // ---------------------------------------------------------------- Module 5
    private static void testHashing() {
        String h1 = Hashing.sha256("AcademicTestingPassword2026!");
        check("SHA-256 hash is 64 hex characters", h1.matches("[0-9a-f]{64}"));
        check("SHA-256 is deterministic", h1.equals(Hashing.sha256("AcademicTestingPassword2026!")));
        check("SHA-256('password') matches the known test vector",
                Hashing.sha256("password").equals("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"));

        String a = Hashing.sha256("Security123"), b = Hashing.sha256("security123");
        int bits = Hashing.bitDifference(a, b);
        check("Avalanche: 1-char change flips roughly half the 256 bits (80-176)", bits > 80 && bits < 176);

        String salt1 = Hashing.toHex(Hashing.randomBytes(8)), salt2 = Hashing.toHex(Hashing.randomBytes(8));
        check("Same password with different salts gives different hashes",
                !Hashing.sha256(salt1 + "password123").equals(Hashing.sha256(salt2 + "password123")));
        check("Hex round-trip preserves bytes",
                Arrays.equals(Hashing.fromHex("00ff10ab"), new byte[]{0, (byte) 0xff, 0x10, (byte) 0xab}));
    }

    // ---------------------------------------------------------------- Module 6
    private static void testHashMatching() {
        List<String> candidates = Arrays.asList("admin", "matrix", "cookie");
        List<AttackSimulations.HashMatchStep> steps = AttackSimulations.hashMatch(Hashing.sha256("matrix"), candidates);
        check("Hash match finds 'matrix' at step 2", steps.size() == 2 && steps.get(1).match && "matrix".equals(steps.get(1).word));

        List<AttackSimulations.HashMatchStep> miss = AttackSimulations.hashMatch(Hashing.sha256("Falcon#2026!Z"), candidates);
        check("High-entropy hash is not matched", miss.size() == 3 && miss.stream().noneMatch(s -> s.match));

        check("Malformed target hash is rejected", throwsIAE(() -> AttackSimulations.hashMatch("abc", candidates)));
    }

    // ---------------------------------------------------------------- Module 7
    private static void testLogin() {
        byte[] salt = new byte[16];
        for (int i = 0; i < 16; i++) salt[i] = (byte) (i + 1);
        String hash1 = Hashing.pbkdf2("Study#Hard2026!".toCharArray(), salt);
        check("PBKDF2 is deterministic for the same password and salt",
                hash1.equals(Hashing.pbkdf2("Study#Hard2026!".toCharArray(), salt)));
        check("PBKDF2 produces a 256-bit (64 hex) key", hash1.length() == 64);
        check("PBKDF2 rejects a wrong password", !hash1.equals(Hashing.pbkdf2("WrongPassword".toCharArray(), salt)));

        long[] now = {1_000_000L};
        LoginService svc = new LoginService(() -> now[0]);

        check("Correct demo password logs in",
                svc.attempt("alice_student", "Study#Hard2026!".toCharArray()).outcome == LoginService.Outcome.SUCCESS);
        check("Unknown user gets the generic message",
                svc.attempt("mallory", "x".toCharArray()).message.equals("Invalid username or password."));

        LoginService.Result f1 = svc.attempt("bob_admin", "bad".toCharArray());
        LoginService.Result f2 = svc.attempt("bob_admin", "bad".toCharArray());
        LoginService.Result f3 = svc.attempt("bob_admin", "bad".toCharArray());
        check("Remaining attempts count down 2, 1", f1.remainingAttempts == 2 && f2.remainingAttempts == 1);
        check("Account locks after exactly 3 failed attempts", f3.outcome == LoginService.Outcome.LOCKED_NOW);
        check("Correct password is blocked while locked",
                svc.attempt("bob_admin", "Secur1ty#P@ss".toCharArray()).outcome == LoginService.Outcome.BLOCKED);

        now[0] += LoginService.LOCKOUT_MS;
        check("Cooldown expiry unlocks the account",
                svc.attempt("bob_admin", "Secur1ty#P@ss".toCharArray()).outcome == LoginService.Outcome.SUCCESS);

        svc.attempt("charlie_guest", "bad".toCharArray());
        svc.attempt("charlie_guest", "bad".toCharArray());
        svc.attempt("charlie_guest", "bad".toCharArray());
        svc.reset("charlie_guest");
        check("Emergency reset unlocks immediately",
                svc.attempt("charlie_guest", "Guest$Login77".toCharArray()).outcome == LoginService.Outcome.SUCCESS);

        svc.attempt("alice_student", "bad".toCharArray());
        svc.attempt("alice_student", "bad".toCharArray());
        svc.attempt("alice_student", "Study#Hard2026!".toCharArray());
        check("Successful login clears the failure counter", svc.status("alice_student").remainingAttempts == 3);
    }

    // ---------------------------------------------------------------- Module 8
    private static void testSessionStats() {
        SessionStats stats = new SessionStats();
        stats.recordAnalysis(80, "Strong", 90.0, "10 years");
        stats.recordAnalysis(30, "Weak", 25.0, "Instant");
        stats.recordAnalysis(60, "Medium", 50.0, "5 days");
        check("SessionStats records 3 analyses (1 Strong / 1 Medium / 1 Weak)",
                stats.getTotalAnalyzed() == 3 && stats.getStrongCount() == 1 && stats.getMediumCount() == 1 && stats.getWeakCount() == 1);
        check("SessionStats average score is accurate", Math.abs(stats.getAverageScore() - 170 / 3.0) < 0.001);

        stats.recordBruteForceSimulation();
        stats.recordDictionarySimulation();
        stats.recordHashingTest();
        stats.recordLoginAttempt(false);
        stats.recordLoginAttempt(true);
        check("Simulation counters increment", stats.getBruteForceSimCount() == 1 && stats.getDictionarySimCount() == 1
                && stats.getHashingTestsCount() == 1);
        check("Login attempts and lockouts counted separately",
                stats.getLoginAttemptsCount() == 2 && stats.getLoginLockoutCount() == 1);

        String report = stats.buildReport();
        check("Report contains the metrics", report.contains("Total Passwords Analyzed: 3") && report.contains("Account Lockouts:         1"));

        stats.resetAll();
        check("Reset clears everything", stats.getTotalAnalyzed() == 0 && stats.getAverageScore() == 0.0 && stats.getLoginAttemptsCount() == 0);
    }

    // ---------------------------------------------------------------- Module 9
    private static void testCrackTime() {
        BigInteger huge = SecurityMath.combinations(95, 64);
        check("95^64 search space exceeds Long.MAX_VALUE without overflow",
                huge.compareTo(BigInteger.valueOf(Long.MAX_VALUE)) > 0);
        check("Huge search space formats as > 1 trillion years",
                SecurityMath.formatDuration(huge, BigInteger.valueOf(10_000_000_000L)).equals("> 1 trillion years"));

        BigInteger rate = BigInteger.valueOf(1000);
        check("Sub-millisecond durations are labelled correctly", SecurityMath.formatDuration(BigInteger.ZERO.add(BigInteger.ONE), rate).equals("< 1 second")
                && SecurityMath.formatDuration(BigInteger.ONE, BigInteger.valueOf(10_000)).equals("< 1 millisecond"));
        check("90 seconds formats as 1 minute", SecurityMath.formatDuration(BigInteger.valueOf(90), BigInteger.ONE).equals("1 minute"));

        CrackTimeEstimator.Estimate weak = CrackTimeEstimator.estimate("summer99");
        CrackTimeEstimator.Estimate strong = CrackTimeEstimator.estimate("Summer#99!Peak");
        check("Estimator: 'summer99' pool is 36", weak.poolSize == 36 && weak.length == 8);
        check("Estimator: longer mixed password has larger search space", strong.combinations.compareTo(weak.combinations) > 0);
        check("Estimator: times for all 5 guessing speeds",
                weak.averageTimes.length == 5 && Arrays.stream(weak.worstTimes).allMatch(s -> s != null && !s.isEmpty()));
        check("Estimator: online rate is slower than GPU cluster",
                !weak.worstTimes[0].equals(weak.worstTimes[3]));
        check("Estimator comparison names Password 2 as stronger",
                CrackTimeEstimator.compare(weak, strong).startsWith("Password 2 has ~"));
    }

    // ---------------------------------------------------------------- Web API
    private static void testWebApi() throws Exception {
        WebServer server = new WebServer(Paths.get("").toAbsolutePath());
        int port = server.start(0);
        String base = "http://127.0.0.1:" + port;
        try {
            String home = http("GET", base + "/", null);
            check("Web: index page is served", home.contains("<title>"));
            check("Web: path traversal is blocked", status(base + "/../src/passwordsecurity/Main.java") == 404);

            String analyze = http("POST", base + "/api/analyze", "password=" + enc("Vx7#qLm!2zR$wK9p") + "&record=1");
            check("Web: /api/analyze returns Strong", analyze.contains("\"category\":\"Strong\""));

            String gen = http("POST", base + "/api/generate/password", "length=20&upper=1&lower=1&digits=1&symbols=1");
            check("Web: /api/generate/password returns a value", gen.contains("\"value\":"));
            check("Web: invalid generator settings return 400",
                    status(base + "/api/generate/password", "length=20") == 400);

            String bf = http("POST", base + "/api/bruteforce/run", "target=cat&lower=1");
            check("Web: /api/bruteforce/run finds 'cat'", bf.contains("\"found\":true"));

            String dict = http("POST", base + "/api/dictionary/run", "target=dragon");
            check("Web: /api/dictionary/run finds 'dragon' in data/sample_words.txt", dict.contains("\"found\":true"));

            String hm = http("POST", base + "/api/hashmatch/run", "hash=" + Hashing.sha256("cookie"));
            check("Web: /api/hashmatch/run matches 'cookie'", hm.contains("\"found\":true"));

            String login = http("POST", base + "/api/login", "username=alice_student&password=" + enc("Study#Hard2026!"));
            check("Web: /api/login succeeds with demo credentials", login.contains("\"outcome\":\"SUCCESS\""));

            String est = http("POST", base + "/api/estimate", "p1=summer99&p2=" + enc("Summer#99!Peak"));
            check("Web: /api/estimate compares two passwords", est.contains("Password 2 has"));

            String stats = http("GET", base + "/api/stats", null);
            check("Web: /api/stats reflects activity",
                    stats.contains("\"totalAnalyzed\":1") && stats.contains("\"bruteForce\":1") && stats.contains("\"loginAttempts\":1"));
            check("Web: stats never contain the analysed password", !stats.contains("Vx7#qLm"));

            String report = http("GET", base + "/api/report", null);
            check("Web: /api/report returns the text report", report.contains("SESSION REPORT"));
        } finally {
            server.stop();
        }
    }

    // ---------------------------------------------------------------- helpers
    private interface Action { void run(); }

    private static boolean throwsIAE(Action a) {
        try {
            a.run();
            return false;
        } catch (IllegalArgumentException e) {
            return true;
        }
    }

    private static String enc(String s) {
        return java.net.URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static int status(String url) throws Exception {
        HttpURLConnection c = (HttpURLConnection) URI.create(url).toURL().openConnection();
        return c.getResponseCode();
    }

    private static int status(String url, String body) throws Exception {
        HttpURLConnection c = open("POST", url, body);
        return c.getResponseCode();
    }

    private static HttpURLConnection open(String method, String url, String body) throws Exception {
        HttpURLConnection c = (HttpURLConnection) URI.create(url).toURL().openConnection();
        c.setRequestMethod(method);
        if (body != null) {
            c.setDoOutput(true);
            c.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            try (OutputStream os = c.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
            }
        }
        return c;
    }

    private static String http(String method, String url, String body) throws Exception {
        HttpURLConnection c = open(method, url, body);
        InputStream in = c.getResponseCode() < 400 ? c.getInputStream() : c.getErrorStream();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        in.transferTo(out);
        return out.toString(StandardCharsets.UTF_8.name());
    }
}
