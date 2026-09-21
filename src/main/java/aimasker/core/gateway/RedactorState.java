package aimasker.core.gateway;

import aimasker.core.RedactionEngine;
import aimasker.core.audit.Fingerprinter;
import aimasker.core.config.RedactorConfig;
import aimasker.core.validation.LeakageValidator;

/**
 * A configuration together with the engine and validator compiled from it. Swapped atomically
 * whenever the configuration changes.
 */
public record RedactorState(RedactorConfig config, RedactionEngine engine, LeakageValidator validator) {

    public static RedactorState of(RedactorConfig config, Fingerprinter fingerprinter) {
        // Future detectors (IP, e-mail, JWT, custom patterns, ...) are registered in RedactorConfig.detectors().
        RedactionEngine engine = new RedactionEngine(config.detectors(), fingerprinter);
        return new RedactorState(config, engine, new LeakageValidator(engine));
    }
}
