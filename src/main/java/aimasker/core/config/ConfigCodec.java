package aimasker.core.config;

import aimasker.core.domain.DomainRule;
import aimasker.core.http.ProcessingOptions;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Plain-text, line-based serialisation of {@link RedactorConfig}. No third-party parser is
 * needed, which keeps the extension free of runtime dependencies.
 *
 * <pre>
 * version=1
 * enabled=true
 * domain=nday.blog\tredacted.com\tN-Day Security,NDay Labs
 * </pre>
 */
public final class ConfigCodec {

    public static final int VERSION = 1;

    private ConfigCodec() {
    }

    public static String encode(RedactorConfig config) {
        ProcessingOptions p = config.processing();
        StringBuilder out = new StringBuilder();
        out.append("# Burp AI Masker configuration\n");
        out.append("version=").append(VERSION).append('\n');
        out.append("enabled=").append(config.enabled()).append('\n');
        out.append("keepSubdomainLabels=").append(config.keepSubdomainLabels()).append('\n');
        out.append("autoBrandKeywords=").append(config.autoBrandKeywords()).append('\n');
        out.append("maskSecrets=").append(config.masking().secrets()).append('\n');
        out.append("maskPersonalData=").append(config.masking().personalData()).append('\n');
        out.append("maskIpAddresses=").append(config.masking().ipAddresses()).append('\n');
        out.append("processRequests=").append(p.processRequests()).append('\n');
        out.append("processResponses=").append(p.processResponses()).append('\n');
        out.append("processHeaders=").append(p.processHeaders()).append('\n');
        out.append("processBodies=").append(p.processBodies()).append('\n');
        out.append("omitBinaryBodies=").append(p.omitBinaryBodies()).append('\n');
        out.append("maxPartChars=").append(p.maxPartChars()).append('\n');
        out.append("verboseAudit=").append(config.verboseAudit()).append('\n');
        for (DomainRule rule : config.domainRules()) {
            out.append("domain=").append(rule.target()).append('\t').append(rule.replacement());
            if (!rule.keywords().isEmpty()) {
                out.append('\t').append(String.join(",", rule.keywords()));
            }
            out.append('\n');
        }
        return out.toString();
    }

    /**
     * @throws ConfigException on any malformed or unknown content; callers must then fall back
     *                         to a blocking configuration rather than guess
     */
    public static RedactorConfig decode(String text) {
        Map<String, String> values = new HashMap<>();
        List<DomainRule> rules = new ArrayList<>();
        int lineNumber = 0;
        for (String line : text.split("\n")) {
            lineNumber++;
            String trimmed = line.strip();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }
            int eq = trimmed.indexOf('=');
            if (eq <= 0) {
                throw new ConfigException("Malformed configuration line " + lineNumber + ".");
            }
            String key = trimmed.substring(0, eq);
            String value = trimmed.substring(eq + 1);
            if (key.equals("domain")) {
                String[] parts = value.split("\t", -1);
                if (parts.length != 2 && parts.length != 3) {
                    throw new ConfigException("Malformed domain rule on line " + lineNumber + ".");
                }
                try {
                    rules.add(DomainRule.of(parts[0], parts[1],
                            parts.length == 3 ? DomainRule.parseKeywords(parts[2]) : List.of()));
                } catch (IllegalArgumentException e) {
                    throw new ConfigException("Invalid domain rule on line " + lineNumber + ": " + e.getMessage());
                }
            } else if (values.put(key, value) != null) {
                throw new ConfigException("Duplicate configuration key on line " + lineNumber + ".");
            }
        }
        if (!String.valueOf(VERSION).equals(values.remove("version"))) {
            throw new ConfigException("Unsupported configuration version.");
        }
        RedactorConfig defaults = RedactorConfig.defaults();
        ProcessingOptions d = defaults.processing();
        try {
            ProcessingOptions processing = new ProcessingOptions(
                    bool(values, "processRequests", d.processRequests()),
                    bool(values, "processResponses", d.processResponses()),
                    bool(values, "processHeaders", d.processHeaders()),
                    bool(values, "processBodies", d.processBodies()),
                    bool(values, "omitBinaryBodies", d.omitBinaryBodies()),
                    integer(values, "maxPartChars", d.maxPartChars()));
            RedactorConfig config = new RedactorConfig(
                    bool(values, "enabled", defaults.enabled()),
                    rules,
                    bool(values, "keepSubdomainLabels", defaults.keepSubdomainLabels()),
                    bool(values, "autoBrandKeywords", defaults.autoBrandKeywords()),
                    new MaskingOptions(
                            bool(values, "maskSecrets", defaults.masking().secrets()),
                            bool(values, "maskPersonalData", defaults.masking().personalData()),
                            bool(values, "maskIpAddresses", defaults.masking().ipAddresses())),
                    processing,
                    bool(values, "verboseAudit", defaults.verboseAudit()));
            if (!values.isEmpty()) {
                throw new ConfigException("Unknown configuration key.");
            }
            return config;
        } catch (IllegalArgumentException e) {
            throw e instanceof ConfigException ce ? ce : new ConfigException("Invalid configuration: " + e.getMessage());
        }
    }

    private static boolean bool(Map<String, String> values, String key, boolean fallback) {
        String value = values.remove(key);
        if (value == null) {
            return fallback;
        }
        return switch (value) {
            case "true" -> true;
            case "false" -> false;
            default -> throw new ConfigException("Invalid boolean for " + key + ".");
        };
    }

    private static int integer(Map<String, String> values, String key, int fallback) {
        String value = values.remove(key);
        if (value == null) {
            return fallback;
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new ConfigException("Invalid number for " + key + ".");
        }
    }

    public static final class ConfigException extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;

        public ConfigException(String message) {
            super(message);
        }
    }
}
