package org.geoint.gf.audit;

import com.sun.appserv.security.AppservRealm;
import com.sun.enterprise.security.auth.realm.AuthenticationHandler;
import com.sun.enterprise.security.auth.realm.BadRealmException;
import com.sun.enterprise.security.auth.realm.IASRealm;
import com.sun.enterprise.security.auth.realm.InvalidOperationException;
import com.sun.enterprise.security.auth.realm.NoSuchRealmException;
import com.sun.enterprise.security.auth.realm.NoSuchUserException;
import com.sun.enterprise.security.auth.realm.Realm;
import com.sun.enterprise.security.auth.realm.User;
import com.sun.enterprise.security.util.IASSecurityException;
import org.geoint.gf.audit.log.AuditCategory;
import org.geoint.gf.audit.log.AuditLogger;
import java.util.Enumeration;
import java.util.Properties;

/**
 *
 */
public class AuditRealmDecorator extends AppservRealm {

    private final static AuditLogger logger = AuditLogger.logger();
    private final static String PROP_DECORATED_REALM = "audit.realm.decorated";
    private final static String PROP_DECORATED_LOGIN = "audit.login.decorated";

    private IASRealm realm;
    private String delegateLoginModule;

    public String getDelegateLoginModule() {
        return delegateLoginModule;
    }

    public String getDelegateRealm() {
        return realm.getName();
    }

    @Override
    protected void init(final Properties parameters)
            throws BadRealmException, NoSuchRealmException {
        delegateLoginModule = parameters.getProperty(PROP_DECORATED_LOGIN);

        //instantiate the delegative realm
        final String delegateType = parameters.getProperty(PROP_DECORATED_REALM);
        if (delegateType == null) {
            logger.error(AuditCategory.SYSTEM, "Delegate realm could not be "
                    + "found.");
            return;
        }
        try {
            realm = (IASRealm) Realm.instantiate("Audited Realm", delegateType, parameters);
            logger.debug("Delegating realm calls to " + realm.getAuthType());
        } catch (Exception ex) {
            logger.error(AuditCategory.SYSTEM, "Unable to load delegate JAAS "
                    + "realm " + delegateType, ex);
        }
    }

    @Override
    public String getAuthType() {
        return "Auditing Realm: " + getDecoratedRealm().getAuthType();
    }

    @Override
    public Enumeration getGroupNames(String string)
            throws InvalidOperationException, NoSuchUserException {
        return getDecoratedRealm().getGroupNames(string);
    }

    @Override
    public void persist() throws BadRealmException {
        if (getDecoratedRealm().supportsUserManagement()) {
            logger.log(AuditCategory.USER_MGT, "saving changes to users");
            getDecoratedRealm().persist();
        }
    }

    @Override
    public boolean supportsUserManagement() {
        return getDecoratedRealm().supportsUserManagement();
    }

    @Override
    public void updateUser(String name, String newName, char[] password,
            String[] groups)
            throws NoSuchUserException, BadRealmException, IASSecurityException {
        if (getDecoratedRealm().supportsUserManagement()) {
            StringBuilder sb = new StringBuilder();
            sb.append("updating user '").append(name).append("' ");
            if (!name.contentEquals(newName)) {
                sb.append("new username: '").append(newName).append("' ");
            }
            sb.append("groups: ").append(groups);
            logger.log(AuditCategory.USER_MGT, sb.toString());
            getDecoratedRealm().updateUser(name, newName, password, groups);
        }
    }

    @Override
    public void updateUser(String name, String newName, String password,
            String[] groups)
            throws NoSuchUserException, BadRealmException, IASSecurityException {
        if (getDecoratedRealm().supportsUserManagement()) {
            StringBuilder sb = new StringBuilder();
            sb.append("updating user '").append(name).append("' ");
            if (!name.contentEquals(newName)) {
                sb.append("new username: '").append(newName).append("' ");
            }
            sb.append("groups: ").append(groups);
            logger.log(AuditCategory.USER_MGT, sb.toString());
            getDecoratedRealm().updateUser(name, newName, password, groups);
        }
    }

    @Override
    public void removeUser(String name) throws NoSuchUserException, BadRealmException {
        if (getDecoratedRealm().supportsUserManagement()) {
            StringBuilder sb = new StringBuilder();
            sb.append("deleting user '").append(name).append("'");
            logger.log(AuditCategory.USER_MGT, sb.toString());
            getDecoratedRealm().removeUser(name);
        }
    }

    @Override
    public void addUser(String name, String password, String[] groupList) throws BadRealmException, IASSecurityException {
        if (getDecoratedRealm().supportsUserManagement()) {
            StringBuilder sb = new StringBuilder();
            sb.append("adding user '").append(name).append("'");
            sb.append("groups: ").append(groupList);
            logger.log(AuditCategory.USER_MGT, sb.toString());
            getDecoratedRealm().addUser(name, password, groupList);
        }
    }

    @Override
    public void addUser(String name, char[] password, String[] groupList) throws BadRealmException, IASSecurityException {
        if (getDecoratedRealm().supportsUserManagement()) {
            StringBuilder sb = new StringBuilder();
            sb.append("adding user '").append(name).append("'");
            sb.append("groups: ").append(groupList);
            logger.log(AuditCategory.USER_MGT, sb.toString());
            getDecoratedRealm().addUser(name, password, groupList);
        }
    }

    @Override
    public void refresh() throws BadRealmException {
        getDecoratedRealm().refresh();
    }

    @Override
    public Enumeration getGroupNames() throws BadRealmException {
        return getDecoratedRealm().getGroupNames();
    }

    @Override
    public User getUser(String name) throws NoSuchUserException, BadRealmException {
        return getDecoratedRealm().getUser(name);
    }

    @Override
    public Enumeration getUserNames() throws BadRealmException {
        return getDecoratedRealm().getUserNames();
    }

    @Override
    public AuthenticationHandler getAuthenticationHandler() {
        return getDecoratedRealm().getAuthenticationHandler();
    }

    @Override
    public void refresh(String configName) throws BadRealmException {
        getDecoratedRealm().refresh(configName);
    }

    @Override
    public synchronized void setProperty(String name, String value) {
        getDecoratedRealm().setProperty(name, value);
    }

    @Override
    public String toString() {
        return "Audit realm, auditing " + getDecoratedRealm().getAuthType();
    }

    private IASRealm getDecoratedRealm() {
        return realm;
    }
}
