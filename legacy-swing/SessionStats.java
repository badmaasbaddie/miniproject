package passwordsecurity;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * SessionStats: Manages in-memory analytics for the current user session.
 * Stores strictly non-sensitive metadata (scores, categories, simulation counts).
 * Plaintext passwords are NEVER stored in this class or anywhere in session memory.
 */
public class SessionStats {

    // Record of an analysis event (without storing actual password text)
    public static class AnalysisRecord {
        private final int score;
        private final String category; // "Weak", "Medium", "Strong"
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

    private int totalAnalyzed = 0;
    private int weakCount = 0;
    private int mediumCount = 0;
    private int strongCount = 0;
    private int totalScoreAccumulated = 0;

    private int bruteForceSimCount = 0;
    private int dictionarySimCount = 0;
    private int hashingTestsCount = 0;
    private int loginAttemptsCount = 0;
    private int loginLockoutCount = 0;

    private final List<AnalysisRecord> analysisHistory = new ArrayList<>();

    /**
     * Records a password analysis result without storing the password text.
     */
    public synchronized void recordAnalysis(int score, String category, double entropy, String crackTimeEst) {
        totalAnalyzed++;
        totalScoreAccumulated += score;

        if ("Strong".equalsIgnoreCase(category)) {
            strongCount++;
        } else if ("Medium".equalsIgnoreCase(category)) {
            mediumCount++;
        } else {
            weakCount++;
        }

        analysisHistory.add(new AnalysisRecord(score, category, entropy, crackTimeEst));
    }

    public synchronized void recordBruteForceSimulation() {
        bruteForceSimCount++;
    }

    public synchronized void recordDictionarySimulation() {
        dictionarySimCount++;
    }

    public synchronized void recordHashingTest() {
        hashingTestsCount++;
    }

    public synchronized void recordLoginAttempt(boolean wasLocked) {
        loginAttemptsCount++;
        if (wasLocked) {
            loginLockoutCount++;
        }
    }

    public synchronized void resetAll() {
        totalAnalyzed = 0;
        weakCount = 0;
        mediumCount = 0;
        strongCount = 0;
        totalScoreAccumulated = 0;
        bruteForceSimCount = 0;
        dictionarySimCount = 0;
        hashingTestsCount = 0;
        loginAttemptsCount = 0;
        loginLockoutCount = 0;
        analysisHistory.clear();
    }

    // Getters
    public synchronized int getTotalAnalyzed() { return totalAnalyzed; }
    public synchronized int getWeakCount() { return weakCount; }
    public synchronized int getMediumCount() { return mediumCount; }
    public synchronized int getStrongCount() { return strongCount; }

    public synchronized double getAverageScore() {
        if (totalAnalyzed == 0) return 0.0;
        return (double) totalScoreAccumulated / totalAnalyzed;
    }

    public synchronized int getBruteForceSimCount() { return bruteForceSimCount; }
    public synchronized int getDictionarySimCount() { return dictionarySimCount; }
    public synchronized int getHashingTestsCount() { return hashingTestsCount; }
    public synchronized int getLoginAttemptsCount() { return loginAttemptsCount; }
    public synchronized int getLoginLockoutCount() { return loginLockoutCount; }

    public synchronized List<AnalysisRecord> getAnalysisHistory() {
        return Collections.unmodifiableList(new ArrayList<>(analysisHistory));
    }
}
