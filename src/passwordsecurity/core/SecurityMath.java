package passwordsecurity.core;

import java.math.BigInteger;

/**
 * Shared math helpers: character-pool detection, search-space size (R^L)
 * and human-readable crack-time formatting. Uses BigInteger so huge
 * keyspaces (e.g. 95^64) never overflow.
 */
public final class SecurityMath {

    public static final BigInteger SECONDS_PER_YEAR = BigInteger.valueOf(31_536_000L);

    private SecurityMath() {}

    /** Which character classes appear in a password, and the resulting pool size R. */
    public static final class Composition {
        public boolean hasUpper;
        public boolean hasLower;
        public boolean hasDigit;
        public boolean hasSymbol;

        public int poolSize() {
            int pool = 0;
            if (hasLower) pool += 26;
            if (hasUpper) pool += 26;
            if (hasDigit) pool += 10;
            if (hasSymbol) pool += 33; // printable ASCII symbols
            return pool;
        }

        public int varietyCount() {
            return (hasLower ? 1 : 0) + (hasUpper ? 1 : 0) + (hasDigit ? 1 : 0) + (hasSymbol ? 1 : 0);
        }
    }

    public static Composition compose(String password) {
        Composition c = new Composition();
        for (int i = 0; i < password.length(); i++) {
            char ch = password.charAt(i);
            if (Character.isUpperCase(ch)) c.hasUpper = true;
            else if (Character.isLowerCase(ch)) c.hasLower = true;
            else if (Character.isDigit(ch)) c.hasDigit = true;
            else c.hasSymbol = true; // punctuation, symbols, whitespace
        }
        return c;
    }

    /** Entropy in bits: E = L * log2(R). */
    public static double entropyBits(int length, int poolSize) {
        if (poolSize <= 0 || length <= 0) return 0.0;
        return length * (Math.log(poolSize) / Math.log(2));
    }

    public static BigInteger combinations(int poolSize, int length) {
        if (poolSize <= 0 || length <= 0) return BigInteger.ZERO;
        return BigInteger.valueOf(poolSize).pow(length);
    }

    /**
     * Formats the time needed to test {@code guesses} candidates at {@code ratePerSecond}.
     * Sub-second results are reported honestly ("< 1 second" vs "< 1 millisecond").
     */
    public static String formatDuration(BigInteger guesses, BigInteger ratePerSecond) {
        if (guesses.signum() <= 0) return "Instant";
        BigInteger seconds = guesses.divide(ratePerSecond);
        if (seconds.signum() == 0) {
            // guesses / rate < 0.001  <=>  guesses * 1000 < rate
            return guesses.multiply(BigInteger.valueOf(1000)).compareTo(ratePerSecond) < 0
                    ? "< 1 millisecond" : "< 1 second";
        }
        if (seconds.compareTo(BigInteger.valueOf(60)) < 0) return plural(seconds, "second");
        if (seconds.compareTo(BigInteger.valueOf(3600)) < 0) return plural(seconds.divide(BigInteger.valueOf(60)), "minute");
        if (seconds.compareTo(BigInteger.valueOf(86400)) < 0) return plural(seconds.divide(BigInteger.valueOf(3600)), "hour");
        if (seconds.compareTo(SECONDS_PER_YEAR) < 0) return plural(seconds.divide(BigInteger.valueOf(86400)), "day");

        BigInteger years = seconds.divide(SECONDS_PER_YEAR);
        if (years.compareTo(BigInteger.valueOf(1000)) < 0) return plural(years, "year");
        if (years.compareTo(BigInteger.valueOf(1_000_000)) < 0) return years.divide(BigInteger.valueOf(1000)) + " thousand years";
        if (years.compareTo(BigInteger.valueOf(1_000_000_000)) < 0) return years.divide(BigInteger.valueOf(1_000_000)) + " million years";
        if (years.compareTo(BigInteger.valueOf(1_000_000_000_000L)) < 0) return years.divide(BigInteger.valueOf(1_000_000_000)) + " billion years";
        return "> 1 trillion years";
    }

    private static String plural(BigInteger n, String unit) {
        return n + " " + unit + (BigInteger.ONE.equals(n) ? "" : "s");
    }

    /** "1,234,567" for small values, "4.398 × 10^46" for huge ones. */
    public static String formatBig(BigInteger val) {
        String s = val.toString();
        if (s.length() <= 12) return String.format("%,d", val);
        return s.charAt(0) + "." + s.substring(1, 4) + " × 10^" + (s.length() - 1);
    }
}
