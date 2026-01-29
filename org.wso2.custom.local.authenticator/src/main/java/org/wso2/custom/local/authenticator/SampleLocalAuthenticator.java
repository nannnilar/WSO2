package org.wso2.custom.local.authenticator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UniqueIDUserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.common.AuthenticationResult;
import org.wso2.custom.local.authenticator.internal.SampleLocalAuthenticatorServiceComponent;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

public class SampleLocalAuthenticator extends AbstractApplicationAuthenticator implements LocalApplicationAuthenticator {

    private static final Log log = LogFactory.getLog(SampleLocalAuthenticator.class);
    private static final String MOBILE_CLAIM_URL = "http://wso2.org/claims/telephone";
    private static final String USERNAME = "username";
    private static final String PASSWORD = "password";

    @Override
    public boolean canHandle(HttpServletRequest httpServletRequest) {

        String userName = httpServletRequest.getParameter(USERNAME);
        String password = httpServletRequest.getParameter(PASSWORD);
        log.info("[SampleLocalAuthenticator] canHandle() called - username: " + userName);
        return userName != null && password != null;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        log.info("[SampleLocalAuthenticator] initiateAuthenticationRequest() triggered");
        String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
        // This is the default WSO2 IS login page. If you can create your custom login page you can use that instead.
        String queryParams =
                FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                        context.getCallerSessionKey(),
                        context.getContextIdentifier());

        try {
            String retryParam = "";

            if (context.isRetrying()) {
                retryParam = "&authFailure=true&authFailureMsg=login.fail.message";
            }

            response.sendRedirect(response.encodeRedirectURL(loginPage + ("?" + queryParams)) +
                    "&authenticators=BasicAuthenticator:" + "LOCAL" + retryParam);
        } catch (IOException e) {
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest httpServletRequest, HttpServletResponse
            httpServletResponse, AuthenticationContext authenticationContext) throws AuthenticationFailedException {

        log.info("[SampleLocalAuthenticator] processAuthenticationResponse() called");
        String username = httpServletRequest.getParameter(USERNAME);
        String password = httpServletRequest.getParameter(PASSWORD);

        Optional<org.wso2.carbon.user.core.common.User> user = Optional.empty();

        boolean isAuthenticated = false;

        // Check the authentication
        try {
            int tenantId = IdentityTenantUtil.getTenantIdOfUser(username);
            UserRealm userRealm = SampleLocalAuthenticatorServiceComponent.getRealmService()
                    .getTenantUserRealm(tenantId);
            if (userRealm != null) {
                UniqueIDUserStoreManager userStoreManager = (UniqueIDUserStoreManager) userRealm.getUserStoreManager();

                // This custom local authenticator is using the telephone number as the username.
                // Therefore the login identifier claim is http://wso2.org/claims/telephone.
                AuthenticationResult authenticationResult = userStoreManager.
                        authenticateWithID(MOBILE_CLAIM_URL, username, password, UserCoreConstants.DEFAULT_PROFILE);
                if (AuthenticationResult.AuthenticationStatus.SUCCESS == authenticationResult
                        .getAuthenticationStatus()) {
                    user = authenticationResult.getAuthenticatedUser();
                    isAuthenticated = true;
                }
            } else {
                throw new AuthenticationFailedException("Cannot find the user realm for the given tenant: " + tenantId,
                        User.getUserFromUserName(username));
            }
        } catch (IdentityRuntimeException e) {
            if (log.isDebugEnabled()) {
                log.debug("BasicAuthentication failed while trying to get the tenant ID of the user " + username, e);
            }
            throw new AuthenticationFailedException(e.getMessage(), e);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("BasicAuthentication failed while trying to authenticate the user " + username, e);
            }
            throw new AuthenticationFailedException(e.getMessage(), e);
        }

        // If the authentication fails, throws the invalid client credential exception.
        if (!isAuthenticated) {
            if (log.isDebugEnabled()) {
                log.debug("User authentication failed due to invalid credentials");
            }
            throw new InvalidCredentialsException("User authentication failed due to invalid credentials",
                    User.getUserFromUserName(username));
        }

        // When the user is successfully authenticated, add the user to the authentication context to be used later in
        // the process.
        if (user != null) {
            username = user.get().getUsername();
        }
        authenticationContext.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username));
    }

    @Override
    public String getContextIdentifier(HttpServletRequest httpServletRequest) {

        return httpServletRequest.getParameter("sessionDataKey");
    }

    @Override
    public String getName() {

        return "SampleLocalAuthenticator";
    }

    @Override
    public String getFriendlyName() {

        return "SampleLocalAuthenticator";
    }
}
