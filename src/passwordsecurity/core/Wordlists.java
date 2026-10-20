package passwordsecurity.core;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** Local sample wordlists for the dictionary and hash-matching demos. */
public final class Wordlists {

    /** Fallback used when data/sample_words.txt is missing. */
    static final List<String> DEFAULT_DICTIONARY = Collections.unmodifiableList(Arrays.asList(
            "password", "123456", "12345678", "qwerty", "admin", "welcome",
            "login", "football", "dragon", "sunshine", "master", "shadow",
            "secret", "letmein", "monkey", "princess", "superman", "computer",
            "trustno1", "baseball", "michael", "starwars", "matrix", "banana",
            "coffee", "orange", "falcon", "rocket", "guitar", "planet",
            "phoenix", "wizard", "tiger", "eagle", "silver", "galaxy",
            "sunset", "winter", "summer", "spring", "autumn", "ocean",
            "breeze", "mountain", "forest", "river", "thunder", "lightning",
            "cookie", "diamond", "champion", "justice", "freedom"
    ));

    /** Candidate words the hash-matching demo hashes and compares. */
    public static final List<String> HASH_CANDIDATES = Collections.unmodifiableList(Arrays.asList(
            "admin", "welcome", "123456", "password", "qwerty", "football",
            "dragon", "master", "monkey", "shadow", "sunshine", "letmein",
            "princess", "superman", "computer", "matrix", "falcon", "rocket",
            "winter", "summer", "ocean", "cookie", "diamond", "freedom"
    ));

    /** Leaked-hash samples: {label, plaintext, description}. The plaintext is only hashed, never shown before a match. */
    public static final String[][] HASH_TARGETS = {
            {"Leaked hash #1", "password", "Common default password"},
            {"Leaked hash #2", "matrix", "Pop-culture dictionary word"},
            {"Leaked hash #3", "cookie", "Everyday English noun"},
            {"Leaked hash #4", "Falcon#2026!Z", "High-entropy password (not in the sample dictionary)"},
    };

    private Wordlists() {}

    /** Reads one word per line, skipping blanks and '#' comments; falls back to the built-in list. */
    public static List<String> loadDictionary(Path file) {
        List<String> words = new ArrayList<>();
        try {
            if (Files.exists(file)) {
                for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                    line = line.trim();
                    if (!line.isEmpty() && !line.startsWith("#") && !words.contains(line)) words.add(line);
                }
            }
        } catch (IOException ignored) {
            // fall through to the built-in list
        }
        return words.isEmpty() ? new ArrayList<>(DEFAULT_DICTIONARY) : words;
    }
}
