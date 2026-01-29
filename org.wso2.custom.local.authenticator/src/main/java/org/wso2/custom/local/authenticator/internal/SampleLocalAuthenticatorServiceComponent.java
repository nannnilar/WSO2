package org.wso2.custom.local.authenticator.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.*;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.custom.local.authenticator.SampleLocalAuthenticator;

import java.util.Arrays;

@Component(
        name = "org.wso2.carbon.custom.local.authenticator",
        immediate = true
)
public class SampleLocalAuthenticatorServiceComponent {

    private static Log log = LogFactory.getLog(SampleLocalAuthenticatorServiceComponent.class);

    private static RealmService realmService;

    @Activate
    protected void activate(ComponentContext ctxt) {

        try {
            SampleLocalAuthenticator sampleLocalAuthenticator = new SampleLocalAuthenticator();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(),
                    sampleLocalAuthenticator, null);
            BundleContext bundleContext = ctxt.getBundleContext();
            ServiceReference<?>[] refs = bundleContext.getServiceReferences(
                    ApplicationAuthenticator.class.getName(), null);

            log.info("Service Reference: " + Arrays.toString(refs));
            if (refs != null) {
                log.info("Total ApplicationAuthenticator services: " + refs.length);
                for (ServiceReference<?> ref : refs) {
                    Object service = bundleContext.getService(ref);
                    log.info("Authenticator registered: " + service.getClass().getName());
                }
            } else {
                log.warn("No ApplicationAuthenticator services found!");
            }
            log.info("SampleLocalAuthenticator is activated");

            if (log.isDebugEnabled()) {
                log.info("SampleLocalAuthenticator bundle is activated");
            }
        } catch (Throwable e) {
            log.error("SampleLocalAuthenticator bundle activation Failed", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        if (log.isDebugEnabled()) {
            log.info("SampleLocalAuthenticator bundle is deactivated");
        }
    }

    public static RealmService getRealmService() {

        return realmService;
    }

    @Reference(name = "realm.service",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        log.debug("Setting the Realm Service");
        SampleLocalAuthenticatorServiceComponent.realmService = realmService;
    }

    protected void unsetRealmService(RealmService realmService) {

        log.debug("UnSetting the Realm Service");
        SampleLocalAuthenticatorServiceComponent.realmService = null;
    }
}
