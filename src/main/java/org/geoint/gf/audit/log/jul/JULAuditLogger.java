package org.geoint.gf.audit.log.jul;

import java.io.IOException;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.geoint.gf.audit.log.AuditAttribute;
import org.geoint.gf.audit.log.AuditCategory;
import org.geoint.gf.audit.log.AuditLogger;
import org.geoint.logging.splunk.SplunkLogRecord;
import org.geoint.logging.splunk.StandardSplunkFormatter;

/**
 * Logs audits using a {@link java.util.logging.Logger Logger} under the logger
 * name <i>org.geoint.gf.audit</i>.
 *
 */
public class JULAuditLogger implements AuditLogger {

    private static final String PARENT_LOGGER = "org.geoint.gf.audit";
    private static final Logger logger;
    private static final String PROP_LOG_PATTERN
            = "org.geoint.gf.audit.file.pattern";
    private static final String PROP_LOG_COUNT
            = "org.geoint.gf.audit.file.count";
    private static final String PROP_LOG_APPEND
            = "org.geoint.gf.audit.file.append";
    private static final String PROP_LOG_LIMIT
            = "org.geoint.gf.audit.file.limit";
    private static final String PROP_LOG_LEVEL
            = "org.geoint.gf.audit.file.level";
    private static final String DEFAULT_PATTERN = "%t/gf-audit.%g.log";
    private static final String DEFAULT_LIMIT = "200000";
    private static final String DEFAULT_COUNT = "5";
    private static final String DEFAULT_APPEND = "true";
    private static final String DEFAULT_LEVEL = Level.INFO.getName();

    static {
        logger = Logger.getLogger(PARENT_LOGGER);

        try {
            final FileHandler fh = new FileHandler(
                    System.getProperties().getProperty(PROP_LOG_PATTERN,
                            DEFAULT_PATTERN),
                    Integer.valueOf(
                            System.getProperties().getProperty(PROP_LOG_LIMIT,
                                    DEFAULT_LIMIT)
                    ),
                    Integer.valueOf(
                            System.getProperties().getProperty(PROP_LOG_COUNT,
                                    DEFAULT_COUNT)
                    ),
                    Boolean.valueOf(
                            System.getProperties().getProperty(PROP_LOG_APPEND,
                                    DEFAULT_APPEND)
                    )
            );

            Level level = Level.parse(
                    System.getProperties().getProperty(PROP_LOG_LEVEL,
                            DEFAULT_LEVEL)
            );
            fh.setLevel(level);
            logger.setLevel(level);
            logger.addHandler(fh);

            fh.setFormatter(new StandardSplunkFormatter());

            logger.log(Level.INFO, "Started AuditLogger");
        } catch (IOException ex) {
            //use the GF managed logger
            logger.log(Level.SEVERE,
                    "Unable to setup GF Audit module logging", ex);
        }
    }

    @Override
    public void debug(String message) {
        logger.log(Level.FINE, () -> message);
    }

    @Override
    public void system(String message) {
        SplunkLogRecord r = new SplunkLogRecord(Level.INFO, message);
        r.field("category", AuditCategory.SYSTEM.name());

        logger.log(r);
    }

    @Override
    public void log(AuditCategory category, String username, String message,
            AuditAttribute... attributes) {
        log(category, username, message, null, attributes);
    }

    @Override
    public void log(AuditCategory category, String username,
            String message, Throwable ex, AuditAttribute... attributes) {
        log(category, Level.INFO, username, message, ex, attributes);
    }

    @Override
    public void error(AuditCategory category, String username, String error,
            AuditAttribute... attributes) {
        log(category, Level.SEVERE, username, error, null, attributes);
    }

    @Override
    public void error(AuditCategory category, String username,
            String error, Throwable ex, AuditAttribute... attributes) {
        log(category, Level.SEVERE, username, error, ex, attributes);
    }

    private void log(AuditCategory category, Level level,
            String username, String message, Throwable ex,
            AuditAttribute... attributes) {
        if (username == null) {
            if (logger.isLoggable(Level.FINE)) {
                username = "unknown";
            } else {
                //normally don't audit-log anything that can't be attributable 
                //to a user
                return;
            }
        }

        SplunkLogRecord r = new SplunkLogRecord(level, message);
        r.field("category", category.name())
                .field("username", username);
        if (ex != null) {
            r.setThrown(ex);
        }

        for (AuditAttribute a : attributes) {
            r.field(a.getName(), a.getValue());
        }

        logger.log(r);
    }
}
