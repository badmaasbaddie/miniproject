package passwordsecurity.core;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Modules 3, 4 and 6: educational attack simulations that run entirely in local memory
 * against sample targets the user types in. Nothing here touches a real system.
 */
public final class AttackSimulations {

    public static final String BF_DIGITS = "0123456789";
    public static final String BF_LOWER = "abcdefghijklmnopqrstuvwxyz";
    public static final String BF_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    public static final String BF_SYMBOLS = "!@#$%^&*";

    /** Attempt caps keep the demo responsive: longer targets get a tighter cap. */
    public static final long CAP_SHORT = 500_000, CAP_LONG = 50_000;
    public static final int MAX_BRUTE_FORCE_LENGTH = 12;

    private AttackSimulations() {}

    // ---------------------------------------------------------------- Brute force

    public static String buildPool(boolean digits, boolean lower, boolean upper, boolean symbols) {
        return (digits ? BF_DIGITS : "") + (lower ? BF_LOWER : "") + (upper ? BF_UPPER : "") + (symbols ? BF_SYMBOLS : "");
    }

    public static final class BruteForceResult {
        public boolean found;
        public boolean capped;
        public long attempts;
        public long maxAttempts;
        public long elapsedNanos;
        public BigInteger totalCombinations;
        /** Evenly spaced snapshots of candidates tried, for the browser to animate. */
        public final List<String> samples = new ArrayList<>();
    }

    /**
     * Enumerates every string of the target's length over {@code pool}, in order,
     * until it matches or hits the attempt cap.
     */
    public static BruteForceResult bruteForce(String target, String pool) {
        if (target.isEmpty()) throw new IllegalArgumentException("Enter a target string for the simulation.");
        if (pool.isEmpty()) throw new IllegalArgumentException("Select at least one character set.");
        if (target.length() > MAX_BRUTE_FORCE_LENGTH) {
            throw new IllegalArgumentException("Keep the demo target to " + MAX_BRUTE_FORCE_LENGTH + " characters or fewer.");
        }
        for (char c : target.toCharArray()) {
            if (pool.indexOf(c) < 0) {
                throw new IllegalArgumentException("Character '" + c + "' is not in the selected pool. Enable the matching character set.");
            }
        }

        BruteForceResult r = new BruteForceResult();
        int len = target.length();
        r.totalCombinations = SecurityMath.combinations(pool.length(), len);
        r.maxAttempts = len > 4 ? CAP_LONG : CAP_SHORT;
        long expected = r.totalCombinations.min(BigInteger.valueOf(r.maxAttempts)).longValue();
        long sampleEvery = Math.max(1, expected / 120);

        int[] idx = new int[len];
        char[] cur = new char[len];
        for (int i = 0; i < len; i++) cur[i] = pool.charAt(0);

        long start = System.nanoTime();
        while (true) {
            r.attempts++;
            String candidate = new String(cur);
            if (candidate.equals(target)) {
                r.found = true;
                break;
            }
            if (r.attempts % sampleEvery == 0) r.samples.add(candidate);
            if (r.attempts >= r.maxAttempts) {
                r.capped = true;
                break;
            }
            // Odometer increment: rightmost position advances fastest.
            int p = len - 1;
            while (p >= 0) {
                idx[p]++;
                if (idx[p] < pool.length()) {
                    cur[p] = pool.charAt(idx[p]);
                    break;
                }
                idx[p] = 0;
                cur[p] = pool.charAt(0);
                p--;
            }
            if (p < 0) break; // exhausted (cannot happen when target is in pool)
        }
        r.elapsedNanos = System.nanoTime() - start;
        return r;
    }

    // ---------------------------------------------------------------- Dictionary

    /** Returns the 1-based attempt number at which {@code target} is found, or -1 after a full scan. */
    public static int dictionaryAttack(String target, List<String> words) {
        for (int i = 0; i < words.size(); i++) {
            if (words.get(i).equals(target)) return i + 1;
        }
        return -1;
    }

    // ---------------------------------------------------------------- Hash matching

    public static final class HashMatchStep {
        public final String word;
        public final String hash;
        public final boolean match;

        HashMatchStep(String word, String hash, boolean match) {
            this.word = word;
            this.hash = hash;
            this.match = match;
        }
    }

    /** Forward-hashes each candidate and compares it to the target digest (no hash is "reversed"). */
    public static List<HashMatchStep> hashMatch(String targetHash, List<String> candidates) {
        String target = targetHash.trim().toLowerCase();
        if (!target.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Target must be a 64-character hexadecimal SHA-256 digest.");
        }
        List<HashMatchStep> steps = new ArrayList<>();
        for (String word : candidates) {
            String h = Hashing.sha256(word);
            boolean match = h.equals(target);
            steps.add(new HashMatchStep(word, h, match));
            if (match) break;
        }
        return steps;
    }
}
