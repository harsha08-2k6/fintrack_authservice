package com.spendwise.auth.service;

import jakarta.annotation.PostConstruct;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.LocalDateTime;

@Service
public class AuthEmailServiceImpl implements AuthEmailService {

    private static final Logger log = LoggerFactory.getLogger(AuthEmailServiceImpl.class);

    private final JavaMailSender mailSender;
    private final AuthEmailTemplateBuilder templateBuilder;

    @Value("${fintrack.mail.enabled:${SMTP_ENABLED:true}}")
    private boolean mailEnabled;

    @Value("${fintrack.mail.from-email:${SMTP_FROM_EMAIL:tsivaharshavardhanreddy08@gmail.com}}")
    private String fromEmail;

    @Value("${fintrack.mail.from-name:${SMTP_FROM_NAME:FinTrack Security}}")
    private String fromName;

    @Value("${fintrack.auth.reset-token-ttl-minutes:30}")
    private int tokenTtlMinutes;

    @Value("${RESEND_API_KEY:${fintrack.mail.resend-api-key:}}")
    private String resendApiKey;

    @Value("${BREVO_API_KEY:${fintrack.mail.brevo-api-key:}}")
    private String brevoApiKey;

    @Value("${GOOGLE_SCRIPT_MAIL_URL:${fintrack.mail.google-script-url:}}")
    private String googleScriptUrl;

    public AuthEmailServiceImpl(JavaMailSender mailSender, AuthEmailTemplateBuilder templateBuilder) {
        this.mailSender = mailSender;
        this.templateBuilder = templateBuilder;
    }

    @PostConstruct
    public void init() {
        if (googleScriptUrl != null && !googleScriptUrl.isBlank()) {
            String masked = googleScriptUrl.length() > 35 
                    ? googleScriptUrl.substring(0, 35) + "..." 
                    : googleScriptUrl;
            log.info("📧 Google Apps Script Email Relay is ACTIVE. Target: {}", masked);
        } else {
            log.info("📧 Google Apps Script Email Relay is NOT set (GOOGLE_SCRIPT_MAIL_URL is empty)");
        }
    }

    @Override
    @Async("authEmailExecutor")
    public void sendPasswordResetEmailAsync(String recipientEmail, String recipientName, String rawToken) {
        boolean hasRelay = (googleScriptUrl != null && !googleScriptUrl.isBlank())
                || (brevoApiKey != null && !brevoApiKey.isBlank())
                || (resendApiKey != null && !resendApiKey.isBlank());

        if (!mailEnabled && !hasRelay) {
            log.info("Email delivery disabled by configuration. Password reset email skipped for {}", maskEmail(recipientEmail));
            return;
        }

        try {
            AuthEmailTemplateBuilder.EmailContent emailContent = templateBuilder.buildPasswordResetEmail(
                    recipientName, rawToken, tokenTtlMinutes);

            // 1. Try Google Apps Script Webhook (Port 443 - uses your real Gmail, no restrictions)
            if (sendViaGoogleScript(recipientEmail, emailContent.getSubject(), emailContent.getHtmlBody(), emailContent.getTextBody())) {
                return;
            }

            // 2. Try Brevo HTTPS API (Port 443 - delivers to any recipient)
            if (sendViaBrevo(recipientEmail, recipientName, emailContent.getSubject(), emailContent.getHtmlBody())) {
                return;
            }

            // 3. Try Resend HTTPS API (Port 443)
            if (sendViaResend(recipientEmail, emailContent.getSubject(), emailContent.getHtmlBody())) {
                return;
            }

            // 4. Fallback to standard SMTP if enabled
            if (mailEnabled) {
                sendMimeMessageWithRetry(recipientEmail, emailContent.getSubject(), emailContent.getHtmlBody(), emailContent.getTextBody());
                log.info("Password reset email dispatched successfully via SMTP to {}", maskEmail(recipientEmail));
            }
        } catch (Exception e) {
            log.error("Failed to deliver password reset email to {}: {}", maskEmail(recipientEmail), e.getMessage());
        }
    }

    @Override
    @Async("authEmailExecutor")
    public void sendPasswordChangedAlertAsync(String recipientEmail, String recipientName) {
        boolean hasRelay = (googleScriptUrl != null && !googleScriptUrl.isBlank())
                || (brevoApiKey != null && !brevoApiKey.isBlank())
                || (resendApiKey != null && !resendApiKey.isBlank());

        if (!mailEnabled && !hasRelay) {
            return;
        }

        try {
            AuthEmailTemplateBuilder.EmailContent emailContent = templateBuilder.buildPasswordChangedAlert(
                    recipientName, LocalDateTime.now());

            if (sendViaGoogleScript(recipientEmail, emailContent.getSubject(), emailContent.getHtmlBody(), emailContent.getTextBody())) {
                return;
            }

            if (sendViaBrevo(recipientEmail, recipientName, emailContent.getSubject(), emailContent.getHtmlBody())) {
                return;
            }

            if (sendViaResend(recipientEmail, emailContent.getSubject(), emailContent.getHtmlBody())) {
                return;
            }

            if (mailEnabled) {
                sendMimeMessageWithRetry(recipientEmail, emailContent.getSubject(), emailContent.getHtmlBody(), emailContent.getTextBody());
                log.info("Password changed security alert sent to {}", maskEmail(recipientEmail));
            }
        } catch (Exception e) {
            log.warn("Failed to send password changed alert to {}: {}", maskEmail(recipientEmail), e.getMessage());
        }
    }

    private boolean sendViaGoogleScript(String to, String subject, String htmlBody, String textBody) {
        if (googleScriptUrl == null || googleScriptUrl.isBlank()) {
            return false;
        }
        try {
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .followRedirects(HttpClient.Redirect.ALWAYS)
                    .build();

            String safeText = (textBody != null && !textBody.isBlank()) ? textBody : subject;

            // Provide multiple aliases (to, email, recipient, subject, html, htmlBody, message, body, text) so any Google Script variation parses correctly
            String jsonPayload = "{\"to\":\"" + to + "\"," +
                    "\"email\":\"" + to + "\"," +
                    "\"recipient\":\"" + to + "\"," +
                    "\"subject\":" + quoteJson(subject) + "," +
                    "\"html\":" + quoteJson(htmlBody) + "," +
                    "\"htmlBody\":" + quoteJson(htmlBody) + "," +
                    "\"message\":" + quoteJson(htmlBody) + "," +
                    "\"body\":" + quoteJson(safeText) + "," +
                    "\"text\":" + quoteJson(safeText) + "}";

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(googleScriptUrl.trim()))
                    .timeout(Duration.ofSeconds(20))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() >= 200 && response.statusCode() < 400) {
                log.info("✅ Email successfully delivered via Google Script Webhook to {}", maskEmail(to));
                return true;
            } else {
                log.warn("Google Script Webhook returned status {}: {}", response.statusCode(), response.body());
                return false;
            }
        } catch (Exception e) {
            log.warn("Google Script Webhook dispatch failed: {}", e.getMessage());
            return false;
        }
    }

    private boolean sendViaBrevo(String to, String toName, String subject, String htmlBody) {
        if (brevoApiKey == null || brevoApiKey.isBlank()) {
            return false;
        }
        try {
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();

            String safeToName = (toName != null && !toName.isBlank()) ? toName : "User";

            String jsonPayload = "{\"sender\":{\"name\":\"" + fromName + "\",\"email\":\"" + fromEmail + "\"}," +
                    "\"to\":[{\"email\":\"" + to + "\",\"name\":\"" + safeToName + "\"}]," +
                    "\"subject\":" + quoteJson(subject) + "," +
                    "\"htmlContent\":" + quoteJson(htmlBody) + "}";

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://api.brevo.com/v3/smtp/email"))
                    .timeout(Duration.ofSeconds(15))
                    .header("api-key", brevoApiKey.trim())
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() >= 200 && response.statusCode() < 300) {
                log.info("✅ Email successfully delivered via Brevo HTTPS API to {}", maskEmail(to));
                return true;
            } else {
                log.warn("Brevo API returned status {}: {}", response.statusCode(), response.body());
                return false;
            }
        } catch (Exception e) {
            log.warn("Brevo HTTPS API dispatch failed: {}", e.getMessage());
            return false;
        }
    }

    private boolean sendViaResend(String to, String subject, String htmlBody) {
        if (resendApiKey == null || resendApiKey.isBlank()) {
            return false;
        }
        try {
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();

            String sender = "FinTrack Security <onboarding@resend.dev>";

            String jsonPayload = "{\"from\":\"" + sender + "\"," +
                    "\"to\":[\"" + to + "\"]," +
                    "\"subject\":" + quoteJson(subject) + "," +
                    "\"html\":" + quoteJson(htmlBody) + "}";

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://api.resend.com/emails"))
                    .timeout(Duration.ofSeconds(15))
                    .header("Authorization", "Bearer " + resendApiKey.trim())
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() >= 200 && response.statusCode() < 300) {
                return true;
            } else {
                log.warn("Resend HTTPS API returned status {}: {}", response.statusCode(), response.body());
                return false;
            }
        } catch (Exception e) {
            log.warn("Resend HTTPS API dispatch failed: {}", e.getMessage());
            return false;
        }
    }

    private String quoteJson(String text) {
        if (text == null) return "\"\"";
        StringBuilder sb = new StringBuilder("\"");
        for (char c : text.toCharArray()) {
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < ' ') {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append("\"");
        return sb.toString();
    }

    private void sendMimeMessageWithRetry(String to, String subject, String htmlBody, String textBody) throws Exception {
        int maxAttempts = 2;
        Exception lastException = null;

        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                MimeMessage message = mailSender.createMimeMessage();
                MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

                helper.setFrom(fromEmail, fromName);
                helper.setTo(to);
                helper.setSubject(subject);
                helper.setText(textBody, htmlBody);

                mailSender.send(message);
                return;
            } catch (Exception ex) {
                lastException = ex;
                log.warn("Attempt {}/{} to send email to {} failed: {}", attempt, maxAttempts, maskEmail(to), ex.getMessage());
                if (attempt < maxAttempts) {
                    try {
                        Thread.sleep(1500L);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                    }
                }
            }
        }

        if (lastException != null) {
            throw lastException;
        }
    }

    private String maskEmail(String email) {
        if (email == null || !email.contains("@")) return "unknown";
        String[] parts = email.split("@", 2);
        String name = parts[0];
        if (name.length() <= 2) {
            return name.charAt(0) + "*@" + parts[1];
        }
        return name.charAt(0) + "****" + name.charAt(name.length() - 1) + "@" + parts[1];
    }
}
