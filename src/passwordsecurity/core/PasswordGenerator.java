package passwordsecurity.core;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Module 2: Secure Password Generator.
 * Random passwords and memorable passphrases drawn from java.security.SecureRandom (CSPRNG).
 */
public final class PasswordGenerator {

    public static final int MIN_LENGTH = 6, MAX_LENGTH = 64;
    public static final int MIN_WORDS = 3, MAX_WORDS = 8;

    static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    static final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    static final String DIGITS = "0123456789";
    static final String SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?";
    static final String AMBIGUOUS = "0OlI1";

    /**
     * Passphrase vocabulary. Deliberately separate from the dictionary-attack wordlist,
     * which contains leaked passwords like "123456" that must never appear in a passphrase.
     */
    public static final List<String> PASSPHRASE_WORDS = Collections.unmodifiableList(Arrays.asList(
            "correct", "horse", "battery", "staple", "galaxy", "falcon",
            "rocket", "phoenix", "wizard", "tiger", "eagle", "silver",
            "planet", "sunset", "winter", "summer", "spring", "autumn",
            "ocean", "breeze", "mountain", "forest", "river", "thunder",
            "lightning", "cookie", "diamond", "champion", "justice", "freedom",
            "bravo", "charlie", "delta", "echo", "foxtrot", "golf",
            "hotel", "india", "juliet", "kilo", "lima", "matrix",
            "november", "oscar", "quebec", "romeo", "sierra", "tango",
            "uniform", "victor", "whiskey", "xray", "yankee", "zulu"
    ));

    private static final SecureRandom RANDOM = new SecureRandom();

    private PasswordGenerator() {}

    public static final class Result {
        public String value;
        public int poolSize;      // characters (password) or words (passphrase)
        public double entropy;
        public String strength;
    }

    public static Result generatePassword(int length, boolean upper, boolean lower, boolean digits,
                                          boolean symbols, boolean excludeAmbiguous) {
        if (length < MIN_LENGTH || length > MAX_LENGTH) {
            throw new IllegalArgumentException("Length must be between " + MIN_LENGTH + " and " + MAX_LENGTH + ".");
        }
        if (!upper && !lower && !digits && !symbols) {
            throw new IllegalArgumentException("Select at least one character set (uppercase, lowercase, digits or symbols).");
        }

        List<String> categories = new ArrayList<>();
        if (upper) categories.add(filter(UPPERCASE, excludeAmbiguous));
        if (lower) categories.add(filter(LOWERCASE, excludeAmbiguous));
        if (digits) categories.add(filter(DIGITS, excludeAmbiguous));
        if (symbols) categories.add(SYMBOLS);
        String pool = String.join("", categories);

        char[] out = new char[length];
        int i = 0;
        // Guarantee at least one character from every selected category...
        for (String cat : categories) {
            out[i++] = cat.charAt(RANDOM.nextInt(cat.length()));
        }
        // ...fill the rest from the whole pool...
        while (i < length) {
            out[i++] = pool.charAt(RANDOM.nextInt(pool.length()));
        }
        // ...then Fisher-Yates shuffle so the guaranteed characters are not always first.
        for (int k = length - 1; k > 0; k--) {
            int j = RANDOM.nextInt(k + 1);
            char t = out[k];
            out[k] = out[j];
            out[j] = t;
        }

        Result r = new Result();
        r.value = new String(out);
        r.poolSize = pool.length();
        r.entropy = SecurityMath.entropyBits(length, pool.length());
        r.strength = strengthFor(r.entropy);
        return r;
    }

    public static Result generatePassphrase(int wordCount, String separator, boolean capitalize, boolean appendNumber) {
        if (wordCount < MIN_WORDS || wordCount > MAX_WORDS) {
            throw new IllegalArgumentException("Word count must be between " + MIN_WORDS + " and " + MAX_WORDS + ".");
        }
        List<String> words = new ArrayList<>();
        for (int i = 0; i < wordCount; i++) {
            String w = PASSPHRASE_WORDS.get(RANDOM.nextInt(PASSPHRASE_WORDS.size()));
            if (capitalize) w = Character.toUpperCase(w.charAt(0)) + w.substring(1);
            words.add(w);
        }
        if (appendNumber) {
            words.add(String.valueOf(10 + RANDOM.nextInt(90))); // 10-99
        }

        Result r = new Result();
        r.value = String.join(separator, words);
        r.poolSize = PASSPHRASE_WORDS.size();
        // Each word adds log2(N) bits; the trailing number adds log2(90).
        r.entropy = wordCount * (Math.log(PASSPHRASE_WORDS.size()) / Math.log(2))
                + (appendNumber ? Math.log(90) / Math.log(2) : 0);
        r.strength = strengthFor(r.entropy);
        return r;
    }

    public static String strengthFor(double entropy) {
        if (entropy >= 80) return "Very Strong";
        if (entropy >= 60) return "Strong";
        if (entropy >= 45) return "Medium";
        return "Weak";
    }

    private static String filter(String chars, boolean excludeAmbiguous) {
        if (!excludeAmbiguous) return chars;
        StringBuilder sb = new StringBuilder();
        for (char c : chars.toCharArray()) {
            if (AMBIGUOUS.indexOf(c) < 0) sb.append(c);
        }
        return sb.toString();
    }
}
