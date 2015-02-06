package org.geoint.gf.audit.log;

import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.login.LoginException;

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

    void log(AuditCategory category, String message);

    void log(AuditCategory auditCategory, String string, LoginException ex);

    void error(AuditCategory auditCategory, String error);

    void error(AuditCategory auditCategory, String error, Exception ex);

}
