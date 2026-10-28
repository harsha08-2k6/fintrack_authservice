package com.spendwise.auth.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;

class AuthEmailTemplateBuilderTest {

    private AuthEmailTemplateBuilder builder;

    @BeforeEach
    void setUp() {
        builder = new AuthEmailTemplateBuilder();
        ReflectionTestUtils.setField(builder, "frontendUrl", "http://localhost:5173");
    }

    @Test
    @DisplayName("EscapeHtml should sanitize dangerous XSS characters")
    void testEscapeHtml() {
        String unsafe = "<script>alert('pwned');</script>&\"test\"";
        String safe = builder.escapeHtml(unsafe);

        assertFalse(safe.contains("<script>"));
        assertTrue(safe.contains("&lt;script&gt;"));
        assertTrue(safe.contains("&amp;"));
        assertTrue(safe.contains("&quot;"));
        assertTrue(safe.contains("&#39;"));
    }

    @Test
    @DisplayName("Password reset email should contain reset URL, CTA button, 30 min expiry and plain-text fallback")
    void testBuildPasswordResetEmail() {
        String token = "abcd1234efgh5678ijkl9012mnop3456";
        AuthEmailTemplateBuilder.EmailContent content = builder.buildPasswordResetEmail(
                "Siva Harsha", token, 30);

        assertNotNull(content);
        assertEquals("Reset your FinTrack password", content.getSubject());

        // HTML checks
        assertTrue(content.getHtmlBody().contains("Siva Harsha"));
        assertTrue(content.getHtmlBody().contains("http://localhost:5173/reset-password?token=" + token));
        assertTrue(content.getHtmlBody().contains("30 minutes"));
        assertTrue(content.getHtmlBody().contains("Reset Password &rarr;"));
        assertTrue(content.getHtmlBody().contains("Security Notice"));

        // Plain text fallback checks
        assertNotNull(content.getTextBody());
        assertTrue(content.getTextBody().contains("http://localhost:5173/reset-password?token=" + token));
        assertTrue(content.getTextBody().contains("30 minutes"));
        assertTrue(content.getTextBody().contains("FinTrack Corporate Security Team"));
    }

    @Test
    @DisplayName("Password changed alert should inform user of successful security update")
    void testBuildPasswordChangedAlert() {
        AuthEmailTemplateBuilder.EmailContent content = builder.buildPasswordChangedAlert(
                "Siva Harsha", LocalDateTime.of(2026, 10, 24, 21, 30));

        assertNotNull(content);
        assertEquals("Security Alert: FinTrack password changed", content.getSubject());
        assertTrue(content.getHtmlBody().contains("Your Password Was Successfully Updated"));
        assertTrue(content.getHtmlBody().contains("Did not make this change?"));
        assertTrue(content.getTextBody().contains("Security Alert: Password Updated"));
    }
}
