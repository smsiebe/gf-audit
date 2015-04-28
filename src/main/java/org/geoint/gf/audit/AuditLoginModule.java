package org.geoint.gf.audit;

import com.sun.enterprise.security.BasePasswordLoginModule;
import com.sun.enterprise.security.auth.login.common.PasswordCredential;
import org.geoint.gf.audit.log.AuditCategory;
import org.geoint.gf.audit.log.AuditLogger;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.login.LoginException;

/**
 * Decorates a Glassfish login module to provide better auditing.
 *
 *
 */
public class AuditLoginModule extends BasePasswordLoginModule {

    private final static AuditLogger auditLogger = AuditLogger.logger();
    private final static Logger logger
            = Logger.getLogger(AuditLoginModule.class.getName());

    @Override
    protected void authenticateUser() throws LoginException {

        if (this.getUsername() == null || this.getUsername().contentEquals("")) {
            throw new LoginException("No login attempted.");
        }

        if (!(_currentRealm instanceof AuditRealmDecorator)) {
            final String error = "Unable to authenticate user, glassfish "
                    + "audit model " + AuditLoginModule.class.getName() + " must "
                    + "be used with the AduitRealmDecorator realm.";
            logger.log(Level.SEVERE, error);
            throw new LoginException(error);
        }

        AuditRealmDecorator realm = (AuditRealmDecorator) _currentRealm;

        String delegateLoginModule = realm.getDelegateLoginModule();
        Class lmClass;
        try {
            lmClass = Class.forName(delegateLoginModule);
            BasePasswordLoginModule mod
                    = (BasePasswordLoginModule) lmClass.newInstance();

            //we need to add a new Principal so standard sun.* login modules
            //retrieve the delegated realm
            List<Object> principals = new ArrayList<>();
            List<Object> principalHolder = new ArrayList<>();
            Set<Object> creds = _subject.getPrivateCredentials();

            Iterator i = creds.iterator();
            while (i.hasNext()) {
                PasswordCredential privCred = (PasswordCredential) i.next();
                i.remove();
                if (principals.isEmpty() && privCred instanceof PasswordCredential) {
                    principals.add(new PasswordCredential(privCred.getUser(),
                            privCred.getPassword(), realm.getDelegateRealm(),
                            privCred.getTargetName()));
                    //purposely fall through to re-add principal
                }
                principalHolder.add(privCred);
            }

            //add back any other principals AFTER the new audit principal
            principals.addAll(principalHolder);
            _subject.getPrivateCredentials().addAll(principals);

            mod.initialize(_subject, null, _sharedState, _options);

            mod.login();
            this.commitUserAuthentication(mod.getGroupsList());

            auditLogger.log(AuditCategory.AUTHENTICATION, this.username(),
                    "Login successsed");

        } catch (LoginException ex) {
            auditLogger.log(AuditCategory.AUTHENTICATION, this.username(),
                    "Login failed.", ex);
            throw ex; //re-throw to fail login
        } catch (Exception ex) {
            final String error = "Unable to initialize JAAS Login module "
                    + delegateLoginModule;
            auditLogger.error(AuditCategory.SYSTEM, this.username(),
                    error, ex);
            throw new LoginException(error);
        }
    }

    private String username() {
        if (this.getUsername() != null
                && !this.getUsername().contentEquals("unknown")) {
            return this.getUsername();
        }

        if (this.getUserPrincipal() != null) {
            final String principalName = this.getUserPrincipal().getName();
            if (principalName != null) {
                return principalName;
            }
        }

        return null;
    }
}
