package org.geoint.gf.audit.log.jul;

import java.io.IOException;
import java.util.logging.FileHandler;
import java.util.logging.Formatter;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.login.LoginException;
import org.geoint.gf.audit.log.AuditCategory;
import org.geoint.gf.audit.log.AuditLogger;

/**
 * Logs audits using a {@link java.util.logging.Logger Logger} under the logger
 * name <i>org.geoint.gf.audit</i>.
 *
 * Configure the JULAuditLogger using the standard JUL methods (the
 * logging.properties file in your glassfish domain). It's recommended to
 * configure GF to use a separate log file for these security audit log records.
 *
 */
public class JULAuditLogger implements AuditLogger {

    private static final String PARENT_LOGGER = "org.geoint.gf.audit";
    private static final String DEFAULT_FORMATTER
            = STIGAuditFormatter.class.getName();
    private static final Logger logger = Logger.getLogger(PARENT_LOGGER);

//    private static final String PROP_LOG_PATTERN
//            = "org.geoint.gf.audit.file.pattern";
//    private static final String PROP_LOG_COUNT
//            = "org.geoint.gf.audit.file.count";
//    private static final String PROP_LOG_APPEND
//            = "org.geoint.gf.audit.file.append";
//    private static final String PROP_LOG_LIMIT
//            = "org.geoint.gf.audit.file.limit";
//    private static final String PROP_LOG_LEVEL
//            = "org.geoint.gf.audit.file.level";
//    private static final String PROP_LOG_FORMATTER
//            = "org.geoint.gf.audit.file.formatter";
//    private static final String DEFAULT_PATTERN = "%t/gf-audit.%g.log";
//    private static final String DEFAULT_LIMIT = "200000";
//    private static final String DEFAULT_COUNT = "5";
//    private static final String DEFAULT_APPEND = "true";
//    private static final String DEFAULT_LEVEL = Level.INFO.getName();
//    static {
//        try {
//            final FileHandler fh = new FileHandler(
//                    System.getProperties().getProperty(PROP_LOG_PATTERN,
//                            DEFAULT_PATTERN),
//                    Integer.valueOf(
//                            System.getProperties().getProperty(PROP_LOG_LIMIT,
//                                    DEFAULT_LIMIT)
//                    ),
//                    Integer.valueOf(
//                            System.getProperties().getProperty(PROP_LOG_COUNT,
//                                    DEFAULT_COUNT)
//                    ),
//                    Boolean.valueOf(
//                            System.getProperties().getProperty(PROP_LOG_APPEND,
//                                    DEFAULT_APPEND)
//                    )
//            );
//
//            Level level = Level.parse(
//                    System.getProperties().getProperty(PROP_LOG_LEVEL,
//                            DEFAULT_LEVEL)
//            );
//            fh.setLevel(level);
//            logger.setLevel(level);
//            logger.addHandler(fh);
//
//            try {
//                Class formatterType = Class.forName(System.getProperties().getProperty(PROP_LOG_FORMATTER, DEFAULT_FORMATTER));
//                fh.setFormatter((Formatter) formatterType.newInstance());
//            } catch (ClassNotFoundException | InstantiationException | IllegalAccessException ex) {
//                //woops, that formatter can't be used...failback to the 
//                //standard formatter 
//                fh.setFormatter(new STIGAuditFormatter());
//                logger.log(Level.WARNING, "Problems adding custom log formatter "
//                        + "to the audit logger, using default "
//                        + "SimpleAuditFormatter", ex);
//            }
//
//            logger.log(Level.INFO, "Started AuditLogger");
//        } catch (IOException | SecurityException ex) {
//            //use the GF managed logger
//            logger.log(Level.SEVERE,
//                    "Unable to setup GF Audit module logging", ex);
//        }
//    }
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
