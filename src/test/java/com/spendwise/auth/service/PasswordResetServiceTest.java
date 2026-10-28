package com.spendwise.auth.service;

import com.spendwise.auth.dto.ForgotPasswordRequest;
import com.spendwise.auth.dto.ResetPasswordRequest;
import com.spendwise.auth.entity.PasswordResetToken;
import com.spendwise.auth.entity.User;
import com.spendwise.auth.repository.PasswordResetTokenRepository;
import com.spendwise.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PasswordResetServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordResetTokenRepository tokenRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private AuthEmailService authEmailService;

    private PasswordResetService resetService;

    @BeforeEach
    void setUp() {
        resetService = new PasswordResetService(userRepository, tokenRepository, passwordEncoder, authEmailService);
        ReflectionTestUtils.setField(resetService, "tokenTtlMinutes", 30);
    }

    @Test
    @DisplayName("Forgot password for existing user generates hashed token and dispatches email")
    void testProcessForgotPasswordExistingUser() {
        User user = User.builder()
                .id(1L)
                .username("harsha")
                .email("harsha@fintrack.com")
                .fullName("Siva Harsha")
                .password("encoded_pass")
                .build();

        when(tokenRepository.countByIpAddressAndCreatedAtAfter(anyString(), any())).thenReturn(0L);
        when(userRepository.findByEmail("harsha@fintrack.com")).thenReturn(Optional.of(user));
        when(tokenRepository.countByUserIdAndCreatedAtAfter(eq(1L), any())).thenReturn(0L);

        resetService.processForgotPassword(new ForgotPasswordRequest("harsha@fintrack.com"), "127.0.0.1");

        // Verifies previous tokens invalidated
        verify(tokenRepository, times(1)).invalidateAllActiveTokensForUser(eq(1L), any());

        // Verifies token saved with SHA-256 hash (64 hex characters)
        ArgumentCaptor<PasswordResetToken> tokenCaptor = ArgumentCaptor.forClass(PasswordResetToken.class);
        verify(tokenRepository, times(1)).save(tokenCaptor.capture());
        PasswordResetToken saved = tokenCaptor.getValue();
        assertEquals(1L, saved.getUserId());
        assertNotNull(saved.getTokenHash());
        assertEquals(64, saved.getTokenHash().length());
        assertFalse(saved.isConsumed());
        assertTrue(saved.getExpiresAt().isAfter(LocalDateTime.now()));

        // Verifies email sent with raw token
        verify(authEmailService, times(1)).sendPasswordResetEmailAsync(
                eq("harsha@fintrack.com"), eq("Siva Harsha"), anyString());
    }

    @Test
    @DisplayName("Forgot password for non-existent user returns cleanly without sending email (prevents enumeration)")
    void testProcessForgotPasswordNonExistentUser() {
        when(tokenRepository.countByIpAddressAndCreatedAtAfter(anyString(), any())).thenReturn(0L);
        when(userRepository.findByEmail("unknown@fintrack.com")).thenReturn(Optional.empty());

        assertDoesNotThrow(() ->
                resetService.processForgotPassword(new ForgotPasswordRequest("unknown@fintrack.com"), "127.0.0.1")
        );

        verify(tokenRepository, never()).save(any());
        verify(authEmailService, never()).sendPasswordResetEmailAsync(anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("Token validation returns true for active unconsumed token, false for invalid/expired")
    void testValidateToken() {
        String rawToken = "my_secret_token_1234567890123456";
        String hash = resetService.hashToken(rawToken);

        PasswordResetToken validToken = new PasswordResetToken(1L, hash, LocalDateTime.now().plusMinutes(20), "127.0.0.1");
        when(tokenRepository.findByTokenHash(hash)).thenReturn(Optional.of(validToken));

        assertTrue(resetService.validateToken(rawToken));

        // Expired token
        PasswordResetToken expiredToken = new PasswordResetToken(1L, hash, LocalDateTime.now().minusMinutes(5), "127.0.0.1");
        when(tokenRepository.findByTokenHash(hash)).thenReturn(Optional.of(expiredToken));
        assertFalse(resetService.validateToken(rawToken));

        // Consumed token
        PasswordResetToken consumedToken = new PasswordResetToken(1L, hash, LocalDateTime.now().plusMinutes(20), "127.0.0.1");
        consumedToken.setConsumed(true);
        when(tokenRepository.findByTokenHash(hash)).thenReturn(Optional.of(consumedToken));
        assertFalse(resetService.validateToken(rawToken));

        // Unknown token
        when(tokenRepository.findByTokenHash(anyString())).thenReturn(Optional.empty());
        assertFalse(resetService.validateToken("non_existent_token"));
    }

    @Test
    @DisplayName("Reset password updates user credentials, consumes token, and sends security alert")
    void testResetPasswordSuccess() {
        String rawToken = "valid_reset_token_32_characters!";
        String hash = resetService.hashToken(rawToken);

        PasswordResetToken token = new PasswordResetToken(10L, hash, LocalDateTime.now().plusMinutes(15), "127.0.0.1");
        User user = User.builder()
                .id(10L)
                .username("corporate_user")
                .email("user@corporate.com")
                .fullName("Corporate User")
                .password("old_bcrypt_password")
                .build();

        when(tokenRepository.findByTokenHash(hash)).thenReturn(Optional.of(token));
        when(userRepository.findById(10L)).thenReturn(Optional.of(user));
        when(passwordEncoder.encode(anyString())).thenReturn("new_bcrypt_hash");

        ResetPasswordRequest req = new ResetPasswordRequest(rawToken, "NewSecurePassword123#");
        resetService.resetPassword(req);

        // Token consumed
        assertTrue(token.isConsumed());
        assertNotNull(token.getConsumedAt());
        verify(tokenRepository, times(1)).save(token);

        // Password updated with BCrypt
        assertEquals("new_bcrypt_hash", user.getPassword());
        verify(userRepository, times(1)).save(user);

        // Security notification sent
        verify(authEmailService, times(1)).sendPasswordChangedAlertAsync(eq("user@corporate.com"), eq("Corporate User"));
    }

    @Test
    @DisplayName("Reset password rejects weak passwords that do not meet corporate security policy")
    void testResetPasswordRejectsWeakPassword() {
        String rawToken = "valid_reset_token_32_characters!";
        String hash = resetService.hashToken(rawToken);

        PasswordResetToken token = new PasswordResetToken(10L, hash, LocalDateTime.now().plusMinutes(15), "127.0.0.1");
        when(tokenRepository.findByTokenHash(hash)).thenReturn(Optional.of(token));

        // Too short, no special char
        ResetPasswordRequest req = new ResetPasswordRequest(rawToken, "weak");

        ResponseStatusException ex = assertThrows(ResponseStatusException.class, () ->
                resetService.resetPassword(req)
        );

        assertTrue(ex.getMessage().contains("Password must contain at least 8 characters"));
        verify(userRepository, never()).save(any());
        assertFalse(token.isConsumed());
    }

    @Test
    @DisplayName("Token single-use: Reusing an already consumed token fails")
    void testReusingConsumedTokenFails() {
        String rawToken = "already_used_token_123456789012";
        String hash = resetService.hashToken(rawToken);

        PasswordResetToken consumedToken = new PasswordResetToken(10L, hash, LocalDateTime.now().plusMinutes(15), "127.0.0.1");
        consumedToken.setConsumed(true);
        when(tokenRepository.findByTokenHash(hash)).thenReturn(Optional.of(consumedToken));

        ResetPasswordRequest req = new ResetPasswordRequest(rawToken, "NewStrongPassword123#");

        ResponseStatusException ex = assertThrows(ResponseStatusException.class, () ->
                resetService.resetPassword(req)
        );

        assertTrue(ex.getMessage().contains("invalid or has expired"));
        verify(userRepository, never()).save(any());
    }
}
