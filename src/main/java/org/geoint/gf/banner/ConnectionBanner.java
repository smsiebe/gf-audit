
package org.geoint.gf.banner;

import java.net.URL;
import org.glassfish.api.admingui.ConsoleProvider;
import org.jvnet.hk2.annotations.Service;

/**
 *
 */
@Service
public class ConnectionBanner implements ConsoleProvider{

    @Override
    public URL getConfiguration() {
        return null;
    }

}
