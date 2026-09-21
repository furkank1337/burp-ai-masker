package aimasker.core.config;

import aimasker.core.Detection;
import aimasker.core.Detector;
import aimasker.core.domain.DomainDetector;
import aimasker.core.domain.DomainRule;
import aimasker.core.http.ProcessingOptions;
import aimasker.core.keyword.KeywordDetector;
import aimasker.core.secret.ApiKeyDetector;
import aimasker.core.secret.EmailDetector;
import aimasker.core.secret.IpAddressDetector;
import aimasker.core.secret.JwtDetector;
import aimasker.core.secret.PersonalIdDetector;
import aimasker.core.secret.SensitiveFieldDetector;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Immutable extension configuration. Every change produces a new instance, so a message is
 * always processed against one consistent snapshot.
 *
 * @param enabled             when {@code false}, nothing is sent to an AI (fail closed)
 * @param domainRules         customer domains, their replacements and brand keywords
 * @param keepSubdomainLabels {@code api.nday.blog -> api.redacted.com} instead of {@code redacted.com}
 * @param autoBrandKeywords   also redact the brand name derived from each domain
 *                            ({@code example.com -> Example, EXAMPLE, ...}); off by default
 * @param masking             which categories besides domains are masked (secrets, personal data, IPs)
 * @param processing          which parts of messages are rewritten
 * @param verboseAudit        log one line per redacted value instead of one per message
 */
public record RedactorConfig(
        boolean enabled,
        List<DomainRule> domainRules,
        boolean keepSubdomainLabels,
        boolean autoBrandKeywords,
        MaskingOptions masking,
        ProcessingOptions processing,
        boolean verboseAudit) {

    public RedactorConfig {
        domainRules = List.copyOf(domainRules);
        validate(domainRules, detectors(domainRules, keepSubdomainLabels, autoBrandKeywords, masking));
    }

    /** Secure default: enabled, but with no rules configured every AI transmission is blocked. */
    public static RedactorConfig defaults() {
        return new RedactorConfig(true, List.of(), true, false, MaskingOptions.all(), ProcessingOptions.defaults(), false);
    }

    public RedactorConfig withEnabled(boolean value) {
        return new RedactorConfig(value, domainRules, keepSubdomainLabels, autoBrandKeywords, masking, processing, verboseAudit);
    }

    public RedactorConfig withDomainRules(List<DomainRule> value) {
        return new RedactorConfig(enabled, value, keepSubdomainLabels, autoBrandKeywords, masking, processing, verboseAudit);
    }

    public RedactorConfig withKeepSubdomainLabels(boolean value) {
        return new RedactorConfig(enabled, domainRules, value, autoBrandKeywords, masking, processing, verboseAudit);
    }

    public RedactorConfig withAutoBrandKeywords(boolean value) {
        return new RedactorConfig(enabled, domainRules, keepSubdomainLabels, value, masking, processing, verboseAudit);
    }

    public RedactorConfig withMasking(MaskingOptions value) {
        return new RedactorConfig(enabled, domainRules, keepSubdomainLabels, autoBrandKeywords, value, processing, verboseAudit);
    }

    public RedactorConfig withProcessing(ProcessingOptions value) {
        return new RedactorConfig(enabled, domainRules, keepSubdomainLabels, autoBrandKeywords, masking, value, verboseAudit);
    }

    public RedactorConfig withVerboseAudit(boolean value) {
        return new RedactorConfig(enabled, domainRules, keepSubdomainLabels, autoBrandKeywords, masking, processing, value);
    }

    /** Adds the rule, replacing any existing rule for the same target. */
    public RedactorConfig withRuleAdded(DomainRule rule) {
        List<DomainRule> rules = new ArrayList<>();
        boolean replaced = false;
        for (DomainRule existing : domainRules) {
            if (existing.target().equals(rule.target())) {
                rules.add(rule);
                replaced = true;
            } else {
                rules.add(existing);
            }
        }
        if (!replaced) {
            rules.add(rule);
        }
        return withDomainRules(rules);
    }

    /** Removes the rule for {@code target} (normalised first). */
    public RedactorConfig withRuleRemoved(String target) {
        String normalized = DomainRule.normalizeTarget(target);
        List<DomainRule> rules = new ArrayList<>(domainRules);
        rules.removeIf(existing -> existing.target().equals(normalized));
        return withDomainRules(rules);
    }

    /**
     * The detectors this configuration runs, in order. Domains go first so that later
     * placeholders keep the (already masked) domain context, e.g. {@code [EMAIL:..]@redacted.com}.
     * JWTs go before field masking so tokens keep their structure.
     */
    public List<Detector> detectors() {
        return detectors(domainRules, keepSubdomainLabels, autoBrandKeywords, masking);
    }

    private static List<Detector> detectors(List<DomainRule> rules, boolean keepSubdomainLabels,
                                            boolean autoBrandKeywords, MaskingOptions masking) {
        List<Detector> detectors = new ArrayList<>();
        if (!rules.isEmpty()) {
            detectors.add(new DomainDetector(rules, keepSubdomainLabels));
            KeywordDetector keywords = new KeywordDetector(rules, autoBrandKeywords);
            if (!keywords.isEmpty()) {
                detectors.add(keywords);
            }
        }
        if (masking.secrets()) {
            detectors.add(new JwtDetector());
            detectors.add(new ApiKeyDetector());
        }
        if (masking.secrets() || masking.personalData()) {
            detectors.add(new SensitiveFieldDetector(masking.secrets(), masking.personalData()));
        }
        if (masking.personalData()) {
            detectors.add(new EmailDetector());
            detectors.add(new PersonalIdDetector());
        }
        if (masking.ipAddresses()) {
            detectors.add(new IpAddressDetector());
        }
        return List.copyOf(detectors);
    }

    /**
     * Rejects duplicate targets and replacements that would themselves be redacted (for example
     * target {@code redacted.com}, or keyword {@code redacted}), which would leave the output
     * permanently leaking.
     */
    private static void validate(List<DomainRule> rules, List<Detector> detectors) {
        Set<String> targets = new HashSet<>();
        for (DomainRule rule : rules) {
            if (!targets.add(rule.target())) {
                throw new DomainRule.InvalidRuleException("The same target domain is configured twice.");
            }
        }
        for (DomainRule rule : rules) {
            for (String output : List.of(rule.replacement(), "x." + rule.replacement(), rule.keywordReplacement())) {
                for (Detector detector : detectors) {
                    List<Detection> found = detector.detect(output);
                    if (!found.isEmpty()) {
                        throw new DomainRule.InvalidRuleException(
                                "A replacement value contains a configured target domain or keyword.");
                    }
                }
            }
        }
    }
}
