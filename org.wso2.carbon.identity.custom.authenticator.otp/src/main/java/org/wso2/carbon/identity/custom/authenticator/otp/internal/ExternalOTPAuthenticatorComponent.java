package org.wso2.carbon.identity.custom.authenticator.otp.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.*;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.custom.authenticator.otp.ExternalOTPAuthenticator;

@Component(
        name = "org.wso2.carbon.identity.custom.authenticator.otp",
        immediate = true
)
public class ExternalOTPAuthenticatorComponent {

    private static final Log log = LogFactory.getLog(ExternalOTPAuthenticatorComponent.class);

    @Activate
    protected void activate(ComponentContext ctxt) {
        try {
            // Register the custom authenticator as an OSGi service
            ExternalOTPAuthenticator authenticator = new ExternalOTPAuthenticator();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(), authenticator, null);
            log.info("External OTP Authenticator successfully activated and registered.");
        } catch (Throwable e) {
            log.error("Error activating External OTP Authenticator.", e);
        }
    }
}
