package org.wso2.carbon.identity.custom.federated.authenticator.otp.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.custom.federated.authenticator.otp.BankSMSFederatedAuthenticator;

@Component(
        name = "org.wso2.carbon.identity.custom.federated.authenticator.otp",
        immediate = true
)
public class BankSMSAuthenticatorServiceComponent {

    private static final Log log = LogFactory.getLog(BankSMSAuthenticatorServiceComponent.class);

    @Activate
    protected void activate(ComponentContext ctxt) {
        try {
            BankSMSFederatedAuthenticator bankSMSFederatedAuthenticator = new BankSMSFederatedAuthenticator();
            ctxt.getBundleContext().registerService(FederatedApplicationAuthenticator.class.getName(), bankSMSFederatedAuthenticator, null);
            log.info("Bank SMS Federated Authenticator is successfully activated and registered");
            if (log.isDebugEnabled()) {
                log.debug("Bank SMS Federated Authenticator bundle is activated");
            }
        } catch (Throwable e) {
            log.fatal(" Error while activating Bank SMS federated authenticator ", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        if (log.isDebugEnabled()) {
            log.debug("Bank SMS federated Authenticator bundle is deactivated");
        }
    }
}
