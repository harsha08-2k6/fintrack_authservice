package com.spendwise.auth.service;

import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
public class AuthEmailServiceImpl implements AuthEmailService {

    private static final Logger log = LoggerFactory.getLogger(AuthEmailServiceImpl.class);

    private final JavaMailSender mailSender;
    private final AuthEmailTemplateBuilder templateBuilder;

    @Value("${fintrack.mail.enabled:true}")
    private boolean mailEnabled;

    @Value("${fintrack.mail.from-email:tsivaharshavardhanreddy08@gmail.com}")
    private String fromEmail;

    @Value("${fintrack.mail.from-name:FinTrack Security}")
    private String fromName;

    @Value("${fintrack.auth.reset-token-ttl-minutes:30}")
    private int tokenTtlMinutes;

    public AuthEmailServiceImpl(JavaMailSender mailSender, AuthEmailTemplateBuilder templateBuilder) {
        this.mailSender = mailSender;
        this.templateBuilder = templateBuilder;
    }

    @Override
    @Async("authEmailExecutor")
    public void sendPasswordResetEmailAsync(String recipientEmail, String recipientName, String rawToken) {
        if (!mailEnabled) {
            log.info("SMTP delivery disabled by configuration. Password reset email skipped for {}", maskEmail(recipientEmail));
            return;
        }

        try {
            AuthEmailTemplateBuilder.EmailContent emailContent = templateBuilder.buildPasswordResetEmail(
                    recipientName, rawToken, tokenTtlMinutes);

            sendMimeMessageWithRetry(recipientEmail, emailContent.getSubject(), emailContent.getHtmlBody(), emailContent.getTextBody());
            log.info("Password reset email dispatched successfully to {}", maskEmail(recipientEmail));
        } catch (Exception e) {
            log.error("Failed to deliver password reset email to {}: {}", maskEmail(recipientEmail), e.getMessage());
        }
    }

    @Override
    @Async("authEmailExecutor")
    public void sendPasswordChangedAlertAsync(String recipientEmail, String recipientName) {
        if (!mailEnabled) {
            return;
        }

        try {
            AuthEmailTemplateBuilder.EmailContent emailContent = templateBuilder.buildPasswordChangedAlert(
                    recipientName, LocalDateTime.now());

            sendMimeMessageWithRetry(recipientEmail, emailContent.getSubject(), emailContent.getHtmlBody(), emailContent.getTextBody());
            log.info("Password changed security alert sent to {}", maskEmail(recipientEmail));
        } catch (Exception e) {
            log.warn("Failed to send password changed alert to {}: {}", maskEmail(recipientEmail), e.getMessage());
        }
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
