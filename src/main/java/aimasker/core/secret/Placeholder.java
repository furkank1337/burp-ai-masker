package aimasker.core.secret;

import aimasker.core.audit.Fingerprinter;
import java.util.regex.Pattern;

/**
 * Placeholders written in place of secrets and personal data, e.g. {@code [COOKIE:3f9a1c2b]}.
 * The suffix is a keyed hash of the original, so the same value always gets the same
 * placeholder and an analyst (or the AI) can still tell that two requests share a session.
 */
public final class Placeholder {

    /** Matches any placeholder this project writes, including {@code [REDACTED]}. */
    private static final Pattern ANY = Pattern.compile("\\[[A-Z][A-Z0-9_]*(?::[0-9a-f]{8})?\\]");

    private Placeholder() {
    }

    public static String of(String kind, String value, Fingerprinter fingerprinter) {
        return "[" + kind + ":" + fingerprinter.shortId(value) + "]";
    }

    public static boolean is(CharSequence value) {
        return ANY.matcher(value).matches();
    }
}
