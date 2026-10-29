package com.spendwise.auth.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.*;

class JwtServiceTest {

    private static final String VALID_TEST_KEY = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";

    @Test
    @DisplayName("Should successfully generate token and extract claims with valid 256-bit key")
    void testGenerateAndValidateToken() {
        JwtService jwtService = new JwtService();
        ReflectionTestUtils.setField(jwtService, "secretKey", VALID_TEST_KEY);
        ReflectionTestUtils.setField(jwtService, "jwtExpiration", 3600000L);

        String token = jwtService.generateToken(10L, "testuser", "test@domain.com", "ROLE_USER");
        assertNotNull(token);
        assertFalse(token.isBlank());

        assertEquals("testuser", jwtService.extractUsername(token));
        assertTrue(jwtService.isTokenValid(token, "testuser"));
        assertFalse(jwtService.isTokenValid(token, "otheruser"));
    }

    @Test
    @DisplayName("Should fail securely with IllegalStateException when JWT_SECRET is missing")
    void testMissingSecretFailsSecurely() {
        JwtService jwtService = new JwtService();
        ReflectionTestUtils.setField(jwtService, "secretKey", "");
        ReflectionTestUtils.setField(jwtService, "jwtExpiration", 3600000L);

        Exception ex = assertThrows(IllegalStateException.class, () -> {
            jwtService.generateToken(10L, "testuser", "test@domain.com", "ROLE_USER");
        });
        assertTrue(ex.getMessage().contains("Mandatory JWT_SECRET is not configured"));
    }

    @Test
    @DisplayName("Should fail securely when JWT_SECRET has insufficient key length (<256 bits)")
    void testWeakSecretFailsSecurely() {
        JwtService jwtService = new JwtService();
        // Base64 for 8 bytes (64 bits) - insufficient for HS256
        ReflectionTestUtils.setField(jwtService, "secretKey", "dG9vc21hbGw=");
        ReflectionTestUtils.setField(jwtService, "jwtExpiration", 3600000L);

        Exception ex = assertThrows(IllegalStateException.class, () -> {
            jwtService.generateToken(10L, "testuser", "test@domain.com", "ROLE_USER");
        });
        assertTrue(ex.getMessage().contains("insufficiently strong"));
    }
}

