package org.geoint.gf.audit.log;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.TimeZone;
import java.util.logging.Formatter;
import java.util.logging.LogRecord;

/**
 * Format which contains all the required information from the DISA Application
 * Server STIG.
 */
public class STIGAuditFormatter extends Formatter {

    private final SimpleDateFormat dateFormatter = new SimpleDateFormat("dd/MMM/yyyy:HH:mm:ss Z");

    @Override
    public String format(LogRecord record) {
        Calendar cal = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
        cal.setTimeInMillis(record.getMillis());

        StringBuilder sb = new StringBuilder();
        sb.append("[").append(dateFormatter.format(cal.getTime())).append("] ");
        sb.append(this.formatMessage(record));

        Throwable thrown = record.getThrown();
        if (thrown != null) {
            sb.append(thrown.getMessage()).append(" \\ \n");
            for (StackTraceElement e : thrown.getStackTrace()) {
                sb.append("\t ").append(e.toString()).append(" \\ \n");
            }
        } else {
            sb.append("\n");
        }
        return sb.toString();
    }

}
