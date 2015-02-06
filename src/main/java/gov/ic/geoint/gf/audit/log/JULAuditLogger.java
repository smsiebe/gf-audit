package gov.ic.geoint.gf.audit.log;

import java.io.IOException;
import java.util.logging.FileHandler;
import java.util.logging.Formatter;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.login.LoginException;

/**
 * Logs using a java.util.logging Logger
 */
public class JULAuditLogger implements AuditLogger {

    private static final String PARENT_LOGGER = "gov.ic.geoint.gf.audit";
    private static final String PROP_LOG_PATTERN = "audit.file.pattern";
    private static final String PROP_LOG_COUNT = "audit.file.count";
    private static final String PROP_LOG_APPEND = "audit.file.append";
    private static final String PROP_LOG_LIMIT = "audit.file.limit";
    private static final String PROP_LOG_LEVEL = "audit.file.level";
    private static final String PROP_LOG_FORMATTER = "audit.file.formatter";
    private static final String DEFAULT_PATTERN = "%t/gf-audit.%g.log";
    private static final String DEFAULT_LIMIT = "200000";
    private static final String DEFAULT_COUNT = "5";
    private static final String DEFAULT_APPEND = "true";
    private static final String DEFAULT_LEVEL = Level.INFO.getName();
    private static final String DEFAULT_FORMATTER = STIGAuditFormatter.class.getName();
    private static final Logger logger = Logger.getLogger(PARENT_LOGGER);

    static {
        try {
            final FileHandler fh = new FileHandler(
                    System.getProperties().getProperty(PROP_LOG_PATTERN, DEFAULT_PATTERN),
                    Integer.valueOf(System.getProperties().getProperty(PROP_LOG_LIMIT, DEFAULT_LIMIT)),
                    Integer.valueOf(System.getProperties().getProperty(PROP_LOG_COUNT, DEFAULT_COUNT)),
                    Boolean.valueOf(System.getProperties().getProperty(PROP_LOG_APPEND, DEFAULT_APPEND)));

            Level level = Level.parse(System.getProperties().getProperty(PROP_LOG_LEVEL, DEFAULT_LEVEL));
            fh.setLevel(level);
            logger.setLevel(level);
            logger.addHandler(fh);

            try {
                Class formatterType = Class.forName(System.getProperties().getProperty(PROP_LOG_FORMATTER, DEFAULT_FORMATTER));
                fh.setFormatter((Formatter) formatterType.newInstance());
            } catch (ClassNotFoundException | InstantiationException | IllegalAccessException ex) {
                fh.setFormatter(new STIGAuditFormatter());
                logger.log(Level.WARNING, "Problems adding custom log formatter "
                        + "to the audit logger, using default "
                        + "SimpleAuditFormatter", ex);
            }

            logger.log(Level.INFO, "Started AuditLogger");
        } catch (IOException | SecurityException ex) {
            //use the GF managed logger
            logger.log(Level.SEVERE,
                    "Unable to setup GF Audit module logging", ex);
        }
    }

    @Override
    public void debug(String message) {
        if (logger.isLoggable(Level.FINE)) {
            logger.fine(message);
        }
    }

    @Override
    public void log(AuditCategory category, String message) {
        logger.log(Level.INFO, "[{0}] {1}", new Object[]{category, message});
    }

    @Override
    public void log(AuditCategory category, String message, LoginException ex) {
        if (logger.isLoggable(Level.FINE)) {
            StringBuilder sb = new StringBuilder();
            sb.append("[").append(category).append("] ").append(message);
            logger.log(Level.FINE, sb.toString(), ex);
        } else {
            log(category, message);
        }
    }

    @Override
    public void error(AuditCategory category, String error) {
        logger.log(Level.SEVERE, "[{0}] {1}", new Object[]{category, error});
    }

    @Override
    public void error(AuditCategory category, String error, Exception ex) {
        StringBuilder sb = new StringBuilder();
        sb.append("[").append(category).append("] ").append(error);
        logger.log(Level.SEVERE, sb.toString(), ex);
    }

}
