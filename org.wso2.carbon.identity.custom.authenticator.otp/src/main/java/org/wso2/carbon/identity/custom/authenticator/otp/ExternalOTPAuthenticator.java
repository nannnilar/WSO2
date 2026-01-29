package org.wso2.carbon.identity.custom.authenticator.otp;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedIdPData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.AuthenticationStep;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UniqueIDUserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.common.AuthenticationResult;
import org.wso2.carbon.identity.custom.authenticator.otp.internal.ExternalOTPAuthenticatorComponent;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class ExternalOTPAuthenticator extends AbstractApplicationAuthenticator implements LocalApplicationAuthenticator {

    private static final long serialVersionUID = -2331498751502447605L;
    private static final Log log = LogFactory.getLog(ExternalOTPAuthenticator.class);

    // Request parameters
    private static final String OTP_SUBMITTED = "otp-submitted";
    private static final String OTP_CODE = "otp-code";
//    private static final String USER_IDENTIFIER = "user-identifier";

    // JSP page to display (must be created)
    private static final String OTP_LOGIN_PAGE = "/customotp.jsp";

    @Override
    public String getFriendlyName() {
        return "External OTP"; // Name shown in the WSO2 IS Console
    }

    @Override
    public String getName() {
        return "ExternalOTPAuthenticator"; // Internal unique name
    }

    @Override
    public boolean canHandle(HttpServletRequest request) {
        // This authenticator handles the request if the user has submitted the OTP
        log.info("Can handle ExternalOTPAuthenticator: " + request.getParameter(OTP_SUBMITTED));
        return request.getParameter(OTP_SUBMITTED) != null;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest httpServletRequest) {
        return "";
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        // 1. Get the authenticated user
        AuthenticatedUser user = context.getLastAuthenticatedUser();
        if (user == null) {
            throw new AuthenticationFailedException("No authenticated user found in context for OTP generation.");
        }
        String identifier = user.getUserName();
        ExternalOTPService otpService = new ExternalOTPService();
        if (otpService.sendOtp(user, context)) {
            log.info("OTP successfully requested from external service for user: " + identifier);

            try {
                // Correct redirect to custom JSP
                String otpPage = "/authenticationendpoint/customotp.jsp";

                String queryParams = "sessionDataKey=" + context.getContextIdentifier() +
                        "&authenticator=" + getName() +
                        "&identifier=" + identifier;

                String redirectURL = FrameworkUtils.appendQueryParamsStringToUrl(otpPage, queryParams);
                response.sendRedirect(redirectURL);

            } catch (IOException e) {
                throw new AuthenticationFailedException("Error while redirecting to OTP login page.", e);
            }
        }

    }
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        final String OTP_CODE = "otp-code";
        final String USER_IDENTIFIER = "identifier";

        log.info("=== OTP Authentication started ===");

        // 1️⃣ Read OTP from form
        String otpCode = request.getParameter(OTP_CODE);
        log.debug("Received OTP from request: " + otpCode);

        if (otpCode == null || otpCode.trim().isEmpty()) {
            log.error("OTP code is missing in the request.");
            throw new AuthenticationFailedException("OTP code is missing.");
        }

        // 2️⃣ Read user identifier
        String identifier = request.getParameter(USER_IDENTIFIER);
        log.debug("User identifier from request parameter: " + identifier);

        if (identifier == null) {
            identifier = (String) context.getProperty(USER_IDENTIFIER);
            log.debug("User identifier from context property: " + identifier);
        }

        if (identifier == null) {
            log.error("User identifier missing in OTP request.");
            throw new AuthenticationFailedException("User identifier missing in OTP request.");
        }

        // 3️⃣ Verify OTP using external service
        ExternalOTPService otpService = new ExternalOTPService();
        boolean isValid = otpService.verifyOtp(context, otpCode);
        log.info("OTP verification result for user '" + identifier + "': " + isValid);

        if (isValid) {
            log.info("OTP successfully verified for user: " + identifier);

            // 4️⃣ Retrieve or create authenticated user
            AuthenticatedUser authenticatedUser = context.getSubject();
            if (authenticatedUser == null) {
                authenticatedUser = AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(identifier);
                log.debug("Created AuthenticatedUser object for user: " + identifier);
            } else {
                log.debug("Retrieved AuthenticatedUser from context: " + authenticatedUser.getAuthenticatedSubjectIdentifier());
            }

            // 5️⃣ Mark authentication success
            context.setSubject(authenticatedUser);
            context.setProperty("OTP_VERIFIED", true);

            log.info("Authentication context updated, OTP step marked as verified.");

        } else {
            log.error("OTP verification failed for user: " + identifier);
            throw new AuthenticationFailedException("Invalid OTP code.");
        }

        log.info("=== OTP Authentication finished ===");
    }


    protected String getLoginPageURL(AuthenticationContext context) {
        return ConfigurationFacade.getInstance().getAuthenticationEndpointURL() + OTP_LOGIN_PAGE;
    }

    public String getPageUrl() {
        return "customotp.jsp";
    }
}
