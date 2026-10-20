package passwordsecurity.core;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Module 1: Password Strength Analyzer.
 * Scores a password on length, character diversity, entropy and weak patterns.
 * The password itself is never stored or logged.
 */
public final class PasswordAnalyzer {

    /** Crack-time shown by the analyzer assumes a fast GPU rig: 10 billion guesses/sec. */
    public static final BigInteger ANALYZER_RATE = BigInteger.valueOf(10_000_000_000L);

    static final String[] COMMON_PATTERNS = {
            "password", "123456", "admin", "welcome", "qwerty", "login",
            "football", "dragon", "master", "monkey", "letmein", "princess",
            "sunshine", "shadow", "computer", "iloveyou"
    };

    private PasswordAnalyzer() {}

    public static final class Result {
        public int length;
        public boolean hasUpper, hasLower, hasDigit, hasSymbol;
        public int poolSize;
        public double entropy;
        public int score;
        public String category;
        public String crackTime;
        public final List<String> warnings = new ArrayList<>();
    }

    public static Result analyze(String password) {
        Result r = new Result();
        r.length = password.length();

        SecurityMath.Composition c = SecurityMath.compose(password);
        r.hasUpper = c.hasUpper;
        r.hasLower = c.hasLower;
        r.hasDigit = c.hasDigit;
        r.hasSymbol = c.hasSymbol;
        r.poolSize = c.poolSize();
        r.entropy = SecurityMath.entropyBits(r.length, r.poolSize);

        if (r.length == 0) {
            r.score = 0;
            r.category = "Weak";
            r.crackTime = "Instant";
            r.warnings.add("Password is empty.");
            return r;
        }

        // Pattern checks
        String lower = password.toLowerCase();
        for (String pattern : COMMON_PATTERNS) {
            if (lower.contains(pattern)) {
                r.warnings.add("Contains common weak pattern/word: '" + pattern + "'");
            }
        }
        if (hasTripleRepeat(password)) {
            r.warnings.add("Contains 3 or more repeated identical characters in sequence.");
        }
        if (hasSequentialRun(password)) {
            r.warnings.add("Contains predictable sequential characters (e.g. 123, abc).");
        }
        if (r.length < 8) {
            r.warnings.add("Password length is less than recommended minimum (8 characters).");
        }

        // Score (0-100)
        int score;
        if (r.length >= 16) score = 40;
        else if (r.length >= 12) score = 30;
        else if (r.length >= 8) score = 20;
        else if (r.length >= 6) score = 10;
        else score = 2;

        int variety = c.varietyCount();
        score += variety * 10;
        if (variety >= 4 && r.length >= 12) score += 20;
        else if (variety >= 3 && r.length >= 10) score += 10;

        score -= r.warnings.size() * 12;
        r.score = Math.max(0, Math.min(100, score));

        if (r.score >= 75) r.category = "Strong";
        else if (r.score >= 45) r.category = "Medium";
        else r.category = "Weak";

        r.crackTime = SecurityMath.formatDuration(SecurityMath.combinations(r.poolSize, r.length), ANALYZER_RATE);
        return r;
    }

    /** True if any character appears 3+ times in a row (e.g. "aaa", "111"). */
    public static boolean hasTripleRepeat(String s) {
        for (int i = 0; i < s.length() - 2; i++) {
            if (s.charAt(i) == s.charAt(i + 1) && s.charAt(i) == s.charAt(i + 2)) return true;
        }
        return false;
    }

    /** True if there is an ascending or descending run of 3 (e.g. "123", "abc", "cba"). */
    public static boolean hasSequentialRun(String s) {
        for (int i = 0; i < s.length() - 2; i++) {
            char c1 = s.charAt(i), c2 = s.charAt(i + 1), c3 = s.charAt(i + 2);
            if ((c2 == c1 + 1 && c3 == c2 + 1) || (c2 == c1 - 1 && c3 == c2 - 1)) return true;
        }
        return false;
    }
}
