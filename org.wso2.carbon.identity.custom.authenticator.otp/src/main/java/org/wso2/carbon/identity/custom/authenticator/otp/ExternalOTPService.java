package org.wso2.carbon.identity.custom.authenticator.otp;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class ExternalOTPService {

    private static final Log log = LogFactory.getLog(ExternalOTPService.class);

    private static final String SEND_OTP_URL = "https://qrapi-statement-public-uat.abdev.net/api/v1/OTP/GenerateOTP";
    private static final String VERIFY_OTP_URL = "https://qrapi-statement-public-uat.abdev.net/api/v1/OTP/VerifyOTP";
    private static final String MOBILE_CLAIM_URL = "http://wso2.org/claims/telephone";

    private final ObjectMapper mapper = new ObjectMapper();

    public boolean sendOtp(AuthenticatedUser user, AuthenticationContext context) {
        if (user == null) {
            log.error("Authenticated user is null. Cannot send OTP.");
            return false;
        }

        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpPost httpPost = new HttpPost(SEND_OTP_URL);

            String username = user.getUserName();
            String userId = user.getUserId();
            String mobileNo = "";
            Map<ClaimMapping, String> attributes = user.getUserAttributes();

            log.info("User Attributes " + attributes.toString());
            Object mobileClaim = user.getUserAttributes().get(MOBILE_CLAIM_URL);
            if (mobileClaim != null) {
                mobileNo = mobileClaim.toString();
            } else {
                log.warn("Mobile number claim not found for user: " + username + ". Using test number.");
                mobileNo = "+959266005911"; // fallback test number
            }

            Map<String, String> requestBody = new HashMap<>();
            String requestId = UUID.randomUUID().toString();
            requestBody.put("requestId", requestId);
            requestBody.put("keyUrl", "");
            requestBody.put("channel", "QRPubic");
            requestBody.put("mobileNo", mobileNo);
//            requestBody.put("userId", userId != null ? userId : username);
            requestBody.put("userId", "");
            requestBody.put("userName", username);
            requestBody.put("applicationId", "WSO2-APP");

            String jsonPayload = mapper.writeValueAsString(requestBody);

            httpPost.setEntity(new StringEntity(jsonPayload, StandardCharsets.UTF_8));
            httpPost.setHeader("Accept", "application/json");
            httpPost.setHeader("Content-type", "application/json");

            log.info("Json Payload: " +jsonPayload);
            try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
                int statusCode = response.getStatusLine().getStatusCode();
                String responseBody = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
                log.info("SEND OTP API Response Status: " + statusCode + ", Body: " + responseBody);

                if (statusCode == 200 || statusCode == 202){
                    context.setProperty("referenceId", requestId);
                    context.setProperty("channel", "");
                    context.setProperty("mobileNo", mobileNo);
                    context.setProperty("userId", userId);
                    context.setProperty("userName", username);
                }

                return true;
            }

        } catch (IOException | UserIdNotFoundException e) {
            log.error("Error calling external SEND OTP API.", e);
            return false;
        }
    }

    public boolean verifyOtp(AuthenticationContext context, String otpCode) {

        log.info("Starting OTP verification process...");

        // Retrieve values saved during the SEND OTP step
        String referenceId = (String) context.getProperty("referenceId");
        String channel = (String) context.getProperty("channel");
        String mobileNo = (String) context.getProperty("mobileNo");
        String userId = (String) context.getProperty("userId");
        String userName = (String) context.getProperty("userName");

        log.info("VERIFY OTP Context Data: " +
                "referenceId=" + referenceId + ", " +
                "channel=" + channel + ", " +
                "mobileNo=" + mobileNo + ", " +
                "userId=" + userId + ", " +
                "userName=" + userName);

        if (referenceId == null || userName == null) {
            log.error("Missing required OTP metadata in AuthenticationContext.");
            return false;
        }

        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {

            HttpPost httpPost = new HttpPost(VERIFY_OTP_URL);

            // Build verification payload
            Map<String, String> requestBody = new HashMap<>();
            requestBody.put("referenceId", referenceId);
            requestBody.put("channel", channel != null ? channel : "QRPubic");
            requestBody.put("mobileNo", mobileNo);
            requestBody.put("userId", userId);
            requestBody.put("userName", userName);
            requestBody.put("otpCode", otpCode);

            String jsonPayload = mapper.writeValueAsString(requestBody);
            log.info("VERIFY OTP Payload: " + jsonPayload);

            httpPost.setEntity(new StringEntity(jsonPayload, StandardCharsets.UTF_8));
            httpPost.setHeader("Accept", "application/json");
            httpPost.setHeader("Content-type", "application/json");

            try (CloseableHttpResponse response = httpClient.execute(httpPost)) {

                int statusCode = response.getStatusLine().getStatusCode();
                String responseBody = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

                log.info("VERIFY OTP API Response Status: " + statusCode + ", Body: " + responseBody);

                // Success codes (depends on your API)
                return statusCode == 200 || statusCode == 202;
            }

        } catch (Exception e) {
            log.error("Exception while calling external VERIFY OTP API", e);
            return false;
        }
    }

}
