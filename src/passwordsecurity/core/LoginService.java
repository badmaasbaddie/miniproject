package passwordsecurity.core;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.LongSupplier;

/**
 * Module 7: Login Security Demo.
 * Demo accounts stored as salted PBKDF2 hashes, with failed-attempt tracking,
 * a 3-strike lockout and a timed cooldown.
 */
public final class LoginService {

    public static final int MAX_ATTEMPTS = 3;
    public static final long LOCKOUT_MS = 15_000;

    /** Demo credentials shown on the page so students can practise. Never real accounts. */
    public static final String[][] DEMO_ACCOUNTS = {
            {"alice_student", "Study#Hard2026!"},
            {"bob_admin", "Secur1ty#P@ss"},
            {"charlie_guest", "Guest$Login77"},
    };

    public enum Outcome { SUCCESS, FAILED, LOCKED_NOW, BLOCKED, UNKNOWN_USER, INVALID }

    public static final class Account {
        public final String username;
        public final String saltHex;
        public final String hashHex;
        int failedAttempts;
        long lockExpiry; // 0 = not locked

        Account(String username, String saltHex, String hashHex) {
            this.username = username;
            this.saltHex = saltHex;
            this.hashHex = hashHex;
        }
    }

    public static final class Result {
        public Outcome outcome;
        public String message;
        public int remainingAttempts;
        public long lockRemainingMs;
    }

    private final Map<String, Account> accounts = new LinkedHashMap<>();
    private final LongSupplier clock;

    public LoginService() {
        this(System::currentTimeMillis);
    }

    public LoginService(LongSupplier clock) {
        this.clock = clock;
        for (String[] demo : DEMO_ACCOUNTS) register(demo[0], demo[1]);
    }

    private void register(String username, String password) {
        byte[] salt = Hashing.randomBytes(16);
        accounts.put(username, new Account(username, Hashing.toHex(salt), Hashing.pbkdf2(password.toCharArray(), salt)));
    }

    public synchronized Iterable<Account> accounts() {
        return accounts.values();
    }

    public synchronized Result attempt(String username, char[] password) {
        Result r = new Result();
        try {
            if (username == null || username.isEmpty() || password.length == 0) {
                r.outcome = Outcome.INVALID;
                r.message = "Enter both username and password.";
                return r;
            }
            Account acc = accounts.get(username);
            if (acc == null) {
                // Same message as a wrong password: never reveal which usernames exist.
                r.outcome = Outcome.UNKNOWN_USER;
                r.message = "Invalid username or password.";
                return r;
            }
            refreshLock(acc);
            long now = clock.getAsLong();
            if (acc.lockExpiry > now) {
                r.outcome = Outcome.BLOCKED;
                r.lockRemainingMs = acc.lockExpiry - now;
                r.message = "Account is locked. Try again in " + ((r.lockRemainingMs + 999) / 1000) + "s.";
                return r;
            }

            String computed = Hashing.pbkdf2(password, Hashing.fromHex(acc.saltHex));
            if (Hashing.constantTimeEquals(computed, acc.hashHex)) {
                acc.failedAttempts = 0;
                r.outcome = Outcome.SUCCESS;
                r.message = "Welcome back, " + username + "! Verified against the salted PBKDF2 hash.";
            } else {
                acc.failedAttempts++;
                if (acc.failedAttempts >= MAX_ATTEMPTS) {
                    acc.lockExpiry = now + LOCKOUT_MS;
                    r.outcome = Outcome.LOCKED_NOW;
                    r.lockRemainingMs = LOCKOUT_MS;
                    r.message = "Three consecutive failures. Account locked for " + (LOCKOUT_MS / 1000) + " seconds.";
                } else {
                    r.outcome = Outcome.FAILED;
                    r.message = "Invalid username or password.";
                }
            }
            r.remainingAttempts = Math.max(0, MAX_ATTEMPTS - acc.failedAttempts);
            return r;
        } finally {
            java.util.Arrays.fill(password, '\0');
        }
    }

    /** Current state of one account (for the status panel), or null if unknown. */
    public synchronized Result status(String username) {
        Account acc = accounts.get(username);
        if (acc == null) return null;
        refreshLock(acc);
        Result r = new Result();
        long now = clock.getAsLong();
        r.lockRemainingMs = Math.max(0, acc.lockExpiry - now);
        r.remainingAttempts = r.lockRemainingMs > 0 ? 0 : MAX_ATTEMPTS - acc.failedAttempts;
        r.outcome = r.lockRemainingMs > 0 ? Outcome.BLOCKED : null;
        return r;
    }

    /** Admin "emergency reset": unlocks the account and clears its failure counter. */
    public synchronized boolean reset(String username) {
        Account acc = accounts.get(username);
        if (acc == null) return false;
        acc.failedAttempts = 0;
        acc.lockExpiry = 0;
        return true;
    }

    /** Once the cooldown has passed, lift the lock and start counting failures afresh. */
    private void refreshLock(Account acc) {
        if (acc.lockExpiry != 0 && clock.getAsLong() >= acc.lockExpiry) {
            acc.lockExpiry = 0;
            acc.failedAttempts = 0;
        }
    }
}
