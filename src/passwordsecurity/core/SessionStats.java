package passwordsecurity.core;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

/**
 * In-memory analytics for the current session (Module 8).
 * Stores only non-sensitive metadata: scores, categories, counters. Never password text.
 */
public class SessionStats {

    public static class AnalysisRecord {
        private final int score;
        private final String category;
        private final double entropy;
        private final String crackTimeEst;
        private final long timestamp;

        public AnalysisRecord(int score, String category, double entropy, String crackTimeEst) {
            this.score = score;
            this.category = category;
            this.entropy = entropy;
            this.crackTimeEst = crackTimeEst;
            this.timestamp = System.currentTimeMillis();
        }

        public int getScore() { return score; }
        public String getCategory() { return category; }
        public double getEntropy() { return entropy; }
        public String getCrackTimeEst() { return crackTimeEst; }
        public long getTimestamp() { return timestamp; }
    }

    private int weakCount, mediumCount, strongCount, totalScore;
    private int bruteForceSimCount, dictionarySimCount, hashingTestsCount, loginAttemptsCount, loginLockoutCount;
    private final List<AnalysisRecord> history = new ArrayList<>();

    public synchronized void recordAnalysis(int score, String category, double entropy, String crackTimeEst) {
        totalScore += score;
        if ("Strong".equalsIgnoreCase(category)) strongCount++;
        else if ("Medium".equalsIgnoreCase(category)) mediumCount++;
        else weakCount++;
        history.add(new AnalysisRecord(score, category, entropy, crackTimeEst));
    }

    public synchronized void recordBruteForceSimulation() { bruteForceSimCount++; }
    public synchronized void recordDictionarySimulation() { dictionarySimCount++; }
    public synchronized void recordHashingTest() { hashingTestsCount++; }

    /** @param causedLockout true only when this attempt triggered a new lockout */
    public synchronized void recordLoginAttempt(boolean causedLockout) {
        loginAttemptsCount++;
        if (causedLockout) loginLockoutCount++;
    }

    public synchronized void resetAll() {
        weakCount = mediumCount = strongCount = totalScore = 0;
        bruteForceSimCount = dictionarySimCount = hashingTestsCount = loginAttemptsCount = loginLockoutCount = 0;
        history.clear();
    }

    public synchronized int getTotalAnalyzed() { return history.size(); }
    public synchronized int getWeakCount() { return weakCount; }
    public synchronized int getMediumCount() { return mediumCount; }
    public synchronized int getStrongCount() { return strongCount; }
    public synchronized double getAverageScore() { return history.isEmpty() ? 0.0 : (double) totalScore / history.size(); }
    public synchronized int getBruteForceSimCount() { return bruteForceSimCount; }
    public synchronized int getDictionarySimCount() { return dictionarySimCount; }
    public synchronized int getHashingTestsCount() { return hashingTestsCount; }
    public synchronized int getLoginAttemptsCount() { return loginAttemptsCount; }
    public synchronized int getLoginLockoutCount() { return loginLockoutCount; }

    public synchronized List<AnalysisRecord> getAnalysisHistory() {
        return Collections.unmodifiableList(new ArrayList<>(history));
    }

    /** Plain-text session report (metadata only) for the "Export report" download. */
    public synchronized String buildReport() {
        String line = "==========================================================\n";
        String rule = "----------------------------------------------------------\n";
        StringBuilder sb = new StringBuilder();
        sb.append(line)
          .append("       PASSWORD SECURITY SUITE - SESSION REPORT\n")
          .append(line)
          .append("Generated At: ").append(new Date()).append('\n')
          .append("Compliance:   Zero-knowledge (no passwords recorded)\n\n")
          .append(rule).append("1. PASSWORD EVALUATION METRICS\n").append(rule)
          .append("Total Passwords Analyzed: ").append(getTotalAnalyzed()).append('\n')
          .append(String.format("Average Strength Score:   %.2f / 100%n", getAverageScore()))
          .append("Strong Passwords Count:   ").append(strongCount).append('\n')
          .append("Medium Passwords Count:   ").append(mediumCount).append('\n')
          .append("Weak Passwords Count:     ").append(weakCount).append("\n\n")
          .append(rule).append("2. SECURITY LAB SIMULATION TELEMETRY\n").append(rule)
          .append("Brute Force Simulations:  ").append(bruteForceSimCount).append('\n')
          .append("Dictionary Attack Runs:   ").append(dictionarySimCount).append('\n')
          .append("Hashing Tests Performed:  ").append(hashingTestsCount).append('\n')
          .append("Login Attempts Processed: ").append(loginAttemptsCount).append('\n')
          .append("Account Lockouts:         ").append(loginLockoutCount).append("\n\n")
          .append(rule).append("3. EVALUATION HISTORY (METADATA ONLY)\n").append(rule)
          .append(String.format("%-10s %-9s %-8s %-15s %s%n", "Time", "Score", "Rating", "Entropy (bits)", "Approx. Crack Time"));
        SimpleDateFormat fmt = new SimpleDateFormat("HH:mm:ss");
        for (AnalysisRecord r : history) {
            sb.append(String.format("%-10s %-9s %-8s %-15.1f %s%n", fmt.format(new Date(r.getTimestamp())),
                    r.getScore() + "/100", r.getCategory(), r.getEntropy(), r.getCrackTimeEst()));
        }
        sb.append('\n').append(line).append("End of report.\n").append(line);
        return sb.toString();
    }
}
