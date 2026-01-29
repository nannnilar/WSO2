package org.wso2.carbon.identity.custom.federated.authenticator.otp;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
//import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFlowException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.application.common.model.Property;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.List;

public class BankSMSFederatedAuthenticator extends AbstractApplicationAuthenticator
        implements FederatedApplicationAuthenticator {

    public static final String AUTHENTICATOR_NAME = "BankSMSAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Bank SMS Authenticator";

    // Config Properties
    public static final String OTP_GATEWAY_URL = "OtpGatewayUrl";
    public static final String OTP_VERIFY_URL = "OtpVerifyUrl";
    public static final String KEY_URL = "KeyUrl";
    public static final String CHANNEL = "Channel";
    public static final String APP_ID = "ApplicationId";
    public static final String RESEND_COOLDOWN = "ResendCooldown";

    @Override
    public boolean canHandle(HttpServletRequest request) {
        String otp = request.getParameter("otp");
        return otp != null;
    }

    @Override
    public void initiateAuthenticationRequest(HttpServletRequest request,
                                              HttpServletResponse response,
                                              AuthenticationContext context)
            throws AuthenticationFailedException {

        AuthenticatedUser user = context.getLastAuthenticatedUser();
        if (user == null) {
            throw new AuthenticationFailedException("No authenticated user found to generate OTP.");
        }

        String gatewayUrl = context.getAuthenticatorProperties().get(OTP_GATEWAY_URL);
        String channel = context.getAuthenticatorProperties().get(CHANNEL);
        String appId = context.getAuthenticatorProperties().get(APP_ID);

        SMSServiceClient otpService = new SMSServiceClient();
        boolean sent = otpService.sendOtp(user, context);

        if (!sent) {
            throw new AuthenticationFailedException("Failed to send OTP using SMS Gateway API.");
        }

        try {
            String queryParams = context.getContextIdIncludedQueryParams();

            String loginPage = "/authenticationendpoint/sms_otp.jsp";
            response.sendRedirect(IdentityUtil.getServerURL(loginPage, false, false) + queryParams);

            response.sendRedirect(IdentityUtil.getServerURL(loginPage, false, false) + queryParams);
        } catch (Exception e) {
            throw new AuthenticationFailedException("Failed to redirect to OTP page", e);
        }
    }

    @Override
    public void processAuthenticationResponse(HttpServletRequest request,
                                              HttpServletResponse response,
                                              AuthenticationContext context)
            throws AuthenticationFailedException, InvalidCredentialsException {

        String otp = request.getParameter("otp");
        String verifyUrl = context.getAuthenticatorProperties().get(OTP_VERIFY_URL);
        String keyUrl = context.getAuthenticatorProperties().get(KEY_URL);

        if (StringUtils.isBlank(otp)) {
            throw new InvalidCredentialsException("OTP cannot be empty");
        }

        SMSServiceClient otpService = new SMSServiceClient();
        boolean valid;

        try {
            valid = otpService.verifyOtp(context, otp);
        } catch (Exception e) {
            throw new AuthenticationFailedException("Error occurred while verifying OTP.", e);
        }

        if (!valid) {
            throw new InvalidCredentialsException("Invalid OTP");
        }

        context.setSubject(context.getLastAuthenticatedUser());
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {
        return request.getParameter("sessionDataKey");
    }

    @Override
    public String getName() {
        return AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {
        return AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public List<Property> getConfigurationProperties() {
        List<Property> configProperties = new ArrayList<>();

        configProperties.add(createProperty(OTP_GATEWAY_URL, "OTP Gateway URL",
                "URL to send OTP generation request", true));

        configProperties.add(createProperty(OTP_VERIFY_URL, "OTP Verify URL",
                "URL used to verify OTP", true));

        configProperties.add(createProperty(KEY_URL, "Key URL",
                "Shared key endpoint used for OTP signing", false));

        configProperties.add(createProperty(CHANNEL, "Channel",
                "SMS channel name", true));

        configProperties.add(createProperty(APP_ID, "Application ID",
                "Banking App ID for SMS gateway", true));

        configProperties.add(createProperty(RESEND_COOLDOWN, "Resend Cooldown (seconds)",
                "Time to wait before resending OTP", false));

        return configProperties;
    }

    private Property createProperty(String name, String displayName, String description, boolean required) {
        Property p = new Property();
        p.setName(name);
        p.setDisplayName(displayName);
        p.setDescription(description);
        p.setRequired(required);
        return p;
    }
}
