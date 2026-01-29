package org.wso2.carbon.identity.custom.federated.authenticator.otp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class SMSServiceClient {

    private static final Log log = LogFactory.getLog(SMSServiceClient.class);

    public static final String OTP_GATEWAY_URL = "OtpGatewayUrl";
    public static final String OTP_VERIFY_URL = "OtpVerifyUrl";
    public static final String KEY_URL = "KeyUrl";
    public static final String CHANNEL = "Channel";
    public static final String APP_ID = "ApplicationId";
    public static final String RESEND_COOLDOWN = "ResendCooldown";

    private static final String CTX_REFERENCE_ID = "referenceId";
    private static final String CTX_CHANNEL = "channel";
    private static final String CTX_MOBILE = "mobileNo";
    private static final String CTX_USER_ID = "userId";
    private static final String CTX_USER_NAME = "userName";

    private final ObjectMapper mapper = new ObjectMapper();

    private static final RequestConfig DEFAULT_REQUEST_CONFIG = RequestConfig.custom()
            .setConnectTimeout((int) Duration.ofSeconds(10).toMillis())
            .setConnectionRequestTimeout((int) Duration.ofSeconds(10).toMillis())
            .setSocketTimeout((int) Duration.ofSeconds(15).toMillis())
            .build();

    public boolean sendOtp(AuthenticatedUser user, AuthenticationContext context) {
        if (context == null) {
            log.error("AuthenticationContext is null - cannot send OTP.");
            return false;
        }

        String gatewayUrl = getAuthenticatorProperty(context, OTP_GATEWAY_URL);
        String channelCfg = getAuthenticatorProperty(context, CHANNEL);
        String appIdCfg = getAuthenticatorProperty(context, APP_ID);

        if (isBlank(gatewayUrl)) {
            log.error("OTP gateway URL is not configured in authenticator properties.");
            return false;
        }

        // Resolve mobile number and user info
        String mobileNo = resolveMobileFromUserOrContext(user, context);
        String username = resolveUsernameFromUserOrContext(user, context);
        String userId = resolveUserIdFromUserOrContext(user, context);

        if (isBlank(mobileNo)) {
            log.warn("Mobile number not found in user claims or context; aborting OTP send.");
            return false;
        }

        String requestId = UUID.randomUUID().toString();

        Map<String, Object> payload = new HashMap<>();
        payload.put("requestId", requestId);
        payload.put("keyUrl", getAuthenticatorProperty(context, KEY_URL, ""));
        payload.put("channel", defaultIfBlank(channelCfg, "QRPublic"));
        payload.put("mobileNo", mobileNo);
        payload.put("userId", defaultIfBlank(userId, ""));
        payload.put("userName", defaultIfBlank(username, ""));
        payload.put("applicationId", defaultIfBlank(appIdCfg, "WSO2-APP"));

        String jsonPayload;
        try {
            jsonPayload = mapper.writeValueAsString(payload);
        } catch (Exception e) {
            log.error("Failed to serialize OTP request payload.", e);
            return false;
        }

        if (log.isDebugEnabled()) {
            log.debug("Sending OTP to gateway: " + gatewayUrl + " payload=" + jsonPayload);
        } else {
            log.info("Sending OTP to gateway endpoint.");
        }

        try (CloseableHttpClient httpClient = HttpClients.custom()
                .setDefaultRequestConfig(DEFAULT_REQUEST_CONFIG)
                .build()) {

            HttpPost httpPost = new HttpPost(gatewayUrl);
            httpPost.setEntity(new StringEntity(jsonPayload, StandardCharsets.UTF_8));
            httpPost.setHeader("Accept", "application/json");
            httpPost.setHeader("Content-Type", "application/json");

            try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
                int status = response.getStatusLine().getStatusCode();
                String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

                log.info("Send OTP response status=" + status + ", body=" + safeLog(body));

                if (status == 200 || status == 202) {
                    // Optionally parse response to extract referenceId returned by API
                    String returnedRef = extractReferenceIdFromResponse(body);
                    context.setProperty(CTX_REFERENCE_ID, returnedRef != null ? returnedRef : requestId);
                    context.setProperty(CTX_CHANNEL, defaultIfBlank(channelCfg, "QRPublic"));
                    context.setProperty(CTX_MOBILE, mobileNo);
                    context.setProperty(CTX_USER_ID, userId);
                    context.setProperty(CTX_USER_NAME, username);
                    return true;
                } else {
                    log.warn("Unexpected HTTP status from Send OTP endpoint: " + status);
                    return false;
                }
            }

        } catch (IOException ioe) {
            log.error("IOException while calling Send OTP endpoint", ioe);
            return false;
        }
    }

    public boolean verifyOtp(AuthenticationContext context, String otpCode) {
        if (context == null) {
            log.error("AuthenticationContext is null - cannot verify OTP.");
            return false;
        }

        if (isBlank(otpCode)) {
            log.warn("Empty OTP received for verification.");
            return false;
        }

        String verifyUrl = getAuthenticatorProperty(context, OTP_VERIFY_URL);
        if (isBlank(verifyUrl)) {
            log.error("OTP verify URL not configured in authenticator properties.");
            return false;
        }

        String referenceId = (String) context.getProperty(CTX_REFERENCE_ID);
        String channel = (String) context.getProperty(CTX_CHANNEL);
        String mobileNo = (String) context.getProperty(CTX_MOBILE);
        String userId = (String) context.getProperty(CTX_USER_ID);
        String username = (String) context.getProperty(CTX_USER_NAME);

        if (isBlank(referenceId) || isBlank(username)) {
            log.error("Missing required OTP metadata in AuthenticationContext. referenceId or userName is null.");
            return false;
        }

        Map<String, Object> payload = new HashMap<>();
        payload.put("referenceId", referenceId);
        payload.put("channel", defaultIfBlank(channel, "QRPublic"));
        payload.put("mobileNo", mobileNo);
        payload.put("userId", userId);
        payload.put("userName", username);
        payload.put("otpCode", otpCode);
        payload.put("keyUrl", getAuthenticatorProperty(context, KEY_URL, ""));

        String jsonPayload;
        try {
            jsonPayload = mapper.writeValueAsString(payload);
        } catch (Exception e) {
            log.error("Failed to serialize Verify OTP payload.", e);
            return false;
        }

        log.info("Calling OTP Verify endpoint.");

        try (CloseableHttpClient httpClient = HttpClients.custom()
                .setDefaultRequestConfig(DEFAULT_REQUEST_CONFIG)
                .build()) {

            HttpPost httpPost = new HttpPost(verifyUrl);
            httpPost.setEntity(new StringEntity(jsonPayload, StandardCharsets.UTF_8));
            httpPost.setHeader("Accept", "application/json");
            httpPost.setHeader("Content-Type", "application/json");

            try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
                int status = response.getStatusLine().getStatusCode();
                String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

                log.info("Verify OTP response status=" + status + ", body=" + safeLog(body));

                if (status == 200 || status == 202) {
                    // Optionally inspect response body for explicit success flag
                    Boolean ok = parseSuccessFromResponse(body);
                    return ok != null ? ok : true;
                } else {
                    log.warn("OTP verification failed with HTTP status: " + status);
                    return false;
                }
            }

        } catch (IOException ioe) {
            log.error("IOException while calling Verify OTP endpoint", ioe);
            return false;
        }
    }

    private String getAuthenticatorProperty(AuthenticationContext ctx, String key) {
        return getAuthenticatorProperty(ctx, key, null);
    }

    private String getAuthenticatorProperty(AuthenticationContext ctx, String key, String defaultValue) {
        if (ctx == null || key == null) {
            return defaultValue;
        }
        Map<String, String> authProps = ctx.getAuthenticatorProperties();
        if (authProps == null) {
            return defaultValue;
        }
        String v = authProps.get(key);
        return v != null ? v : defaultValue;
    }

    @SuppressWarnings("unchecked")
    private String resolveMobileFromUserOrContext(AuthenticatedUser user, AuthenticationContext context) {
        // 1) check context first (if another step stored it)
        Object ctxMobile = context.getProperty(CTX_MOBILE);
        if (ctxMobile instanceof String && !isBlank((String) ctxMobile)) {
            return (String) ctxMobile;
        }

        // 2) try user attributes map (two possible shapes)
        if (user != null) {
            try {
                Object attrs = user.getUserAttributes();
                if (attrs instanceof Map) {
                    Map<?, ?> m = (Map<?, ?>) attrs;
                    // Try key as claim URI first
                    Object v = m.get("http://wso2.org/claims/telephone");
                    if (v == null) {
                        v = m.get("http://wso2.org/claims/mobile");
                    }
                    if (v == null) {
                        // if Map<ClaimMapping,String>, try searching ClaimMapping keys
                        for (Object key : m.keySet()) {
                            String keyStr = key == null ? null : key.toString();
                            if ("http://wso2.org/claims/telephone".equalsIgnoreCase(keyStr) ||
                                    "http://wso2.org/claims/mobile".equalsIgnoreCase(keyStr)) {
                                v = m.get(key);
                                break;
                            }
                        }
                    }
                    if (v != null) {
                        return v.toString();
                    }
                }
            } catch (Exception e) {
                log.debug("Error while extracting mobile from AuthenticatedUser attributes", e);
            }
        }

        // fallback - none found
        return null;
    }

    private String resolveUsernameFromUserOrContext(AuthenticatedUser user, AuthenticationContext ctx) {
        if (ctx != null) {
            Object uname = ctx.getProperty(CTX_USER_NAME);
            if (uname instanceof String && !isBlank((String) uname)) {
                return (String) uname;
            }
        }
        if (user != null) {
            try {
                return user.getUserName();
            } catch (Exception ignored) {}
        }
        return null;
    }

    private String resolveUserIdFromUserOrContext(AuthenticatedUser user, AuthenticationContext ctx) {
        if (ctx != null) {
            Object uid = ctx.getProperty(CTX_USER_ID);
            if (uid instanceof String && !isBlank((String) uid)) {
                return (String) uid;
            }
        }
        if (user != null) {
            try {
                String id = user.getUserId();
                return isBlank(id) ? null : id;
            } catch (Exception ignored) {}
        }
        return null;
    }

    private String extractReferenceIdFromResponse(String responseBody) {
        if (isBlank(responseBody)) return null;
        try {
            JsonNode root = mapper.readTree(responseBody);
            if (root.has("referenceId")) {
                return root.get("referenceId").asText();
            }
        } catch (Exception e) {
            log.debug("Unable to parse referenceId from response: " + safeLog(responseBody), e);
        }
        return null;
    }

    private Boolean parseSuccessFromResponse(String responseBody) {
        if (isBlank(responseBody)) return null;
        try {
            JsonNode root = mapper.readTree(responseBody);
            // Common patterns: { "success": true } or { "status":"OK" }
            if (root.has("success")) {
                return root.get("success").asBoolean();
            }
            if (root.has("status")) {
                String s = root.get("status").asText();
                return "OK".equalsIgnoreCase(s) || "SUCCESS".equalsIgnoreCase(s);
            }
        } catch (Exception e) {
            log.debug("Unable to parse success flag from response: " + safeLog(responseBody), e);
        }
        return null;
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }

    private static String defaultIfBlank(String value, String defaultVal) {
        return isBlank(value) ? defaultVal : value;
    }

    private String safeLog(String body) {
        if (body == null) return null;
        if (body.length() > 1000) {
            return body.substring(0, 1000) + "...(truncated)";
        }
        return body;
    }
}
