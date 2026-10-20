package passwordsecurity.core;

import java.math.BigInteger;

/**
 * Module 9: Crack-Time Estimator.
 * Theoretical brute-force search space (R^L) and the time to exhaust it at different guessing speeds.
 */
public final class CrackTimeEstimator {

    public static final String[] RATE_NAMES = {
            "Online web service (rate limited)",
            "Single CPU script",
            "Fast GPU rig (MD5 / SHA-256)",
            "Massive GPU cluster",
            "Heavy KDF (Argon2id / bcrypt)"
    };

    public static final long[] RATE_VALUES = {
            10L,
            100_000L,
            10_000_000_000L,
            1_000_000_000_000L,
            1_000L
    };

    private CrackTimeEstimator() {}

    public static final class Estimate {
        public int length;
        public int poolSize;
        public double entropy;
        public BigInteger combinations;
        /** Average (50% of keyspace) and worst-case (100%) time at each rate in RATE_VALUES. */
        public final String[] averageTimes = new String[RATE_VALUES.length];
        public final String[] worstTimes = new String[RATE_VALUES.length];
    }

    public static Estimate estimate(String password) {
        Estimate e = new Estimate();
        e.length = password.length();
        e.poolSize = SecurityMath.compose(password).poolSize();
        e.entropy = SecurityMath.entropyBits(e.length, e.poolSize);
        e.combinations = SecurityMath.combinations(e.poolSize, e.length);
        BigInteger half = e.combinations.divide(BigInteger.valueOf(2));
        for (int i = 0; i < RATE_VALUES.length; i++) {
            BigInteger rate = BigInteger.valueOf(RATE_VALUES[i]);
            e.averageTimes[i] = SecurityMath.formatDuration(half, rate);
            e.worstTimes[i] = SecurityMath.formatDuration(e.combinations, rate);
        }
        return e;
    }

    /** One-line comparison of two search spaces, e.g. "Password 2 has ~4.1 × 10^12 times more combinations". */
    public static String compare(Estimate a, Estimate b) {
        if (a.combinations.signum() == 0 || b.combinations.signum() == 0) {
            return "Enter both passwords to compare their search spaces.";
        }
        int cmp = b.combinations.compareTo(a.combinations);
        if (cmp == 0) return "Both passwords have exactly the same theoretical search space.";
        BigInteger bigger = cmp > 0 ? b.combinations : a.combinations;
        BigInteger smaller = cmp > 0 ? a.combinations : b.combinations;
        return "Password " + (cmp > 0 ? 2 : 1) + " has ~" + SecurityMath.formatBig(bigger.divide(smaller))
                + " times more combinations than Password " + (cmp > 0 ? 1 : 2) + ".";
    }
}
