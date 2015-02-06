package org.geoint.gf.audit;

import com.sun.enterprise.security.BasePasswordLoginModule;
import com.sun.enterprise.security.auth.login.common.PasswordCredential;
import gov.ic.geoint.gf.audit.log.AuditCategory;
import gov.ic.geoint.gf.audit.log.AuditLogger;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import javax.security.auth.login.LoginException;

/**
 * Decorates a Glassfish login module to provide better auditing.
 *
 *
 */
public class AuditLoginModule extends BasePasswordLoginModule {

    private final static AuditLogger logger = AuditLogger.logger();

    @Override
    protected void authenticateUser() throws LoginException {

        if (this.getUsername() == null || this.getUsername().contentEquals("")) {
            throw new LoginException("No login attempted.");
        }

        logger.debug("in the login audit module");
        if (!(_currentRealm instanceof AuditRealmDecorator)) {
            final String error = "AuditPasswordLoginModule must "
                    + "be used with the AduitRealmDecorator realm.";
            logger.error(AuditCategory.SYSTEM, error);
            throw new LoginException(error);
        }
        AuditRealmDecorator realm = (AuditRealmDecorator) _currentRealm;

        String delegateLoginModule = realm.getDelegateLoginModule();
        logger.debug("using delegate " + delegateLoginModule);
        Class lmClass;
        try {
            lmClass = Class.forName(delegateLoginModule);
            logger.debug("initializing delegate LM " + lmClass.getName());
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

            logger.debug("attempting to login");
            mod.login();
            this.commitUserAuthentication(mod.getGroupsList());
            logger.log(AuditCategory.AUTHENTICATION, "Login successsed for " + this.getUsername());

        } catch (LoginException ex) {
            logger.log(AuditCategory.AUTHENTICATION, "Login failed for "
                    + this.getUsername(), ex);
            throw ex; //re-throw to fail login
        } catch (Exception ex) {
            final String error = "Unable to initialize JAAS Login module "
                    + delegateLoginModule;
            logger.error(AuditCategory.SYSTEM, error, ex);
            throw new LoginException(error);
        }
    }
}
