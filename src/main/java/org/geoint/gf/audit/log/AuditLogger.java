package org.geoint.gf.audit.log;

import org.geoint.gf.audit.log.jul.JULAuditLogger;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 */
public interface AuditLogger {

    /**
     * JVM property used to specify which logger to use.
     */
    public static final String JVM_AUDIT_LOGGER = "audit.logger.class";

    /**
     * Returns the configured configured audit logger.
     *
     * @return audit logger
     */
    public static AuditLogger logger() {
        String type = System.getProperty(JVM_AUDIT_LOGGER);
        if (type != null) {
            try {
                Class<?> loggerClass = Class.forName(type);
                if (!AuditLogger.class.isAssignableFrom(loggerClass)) {
                    return (AuditLogger) loggerClass.newInstance();
                }
            } catch (ClassNotFoundException | InstantiationException | IllegalAccessException ex) {
                Logger.getLogger("org.geoint.gf.audit").log(Level.SEVERE,
                        "Unable to load Audit logger", ex);
            }
        }
        return new JULAuditLogger();
    }

    void debug(String message);

    void system(String systemMessage);

    void log(AuditCategory category, String username, String message,
            AuditAttribute... attributes);

    void log(AuditCategory auditCategory, String username,
            String string, Throwable ex, AuditAttribute... attributes);

    void error(AuditCategory auditCategory, String username, String error,
            AuditAttribute... attributes);

    void error(AuditCategory auditCategory, String username,
            String error, Throwable ex, AuditAttribute... attributes);

}
