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
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
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
    @DisplayName("1. Registered email generates a valid reset token and triggers email mechanism")
    void testProcessForgotPasswordExistingUser() {
        User user = User.builder()
                .id(1L)
                .username("harsha")
                .email("harsha@fintrack.com")
                .fullName("Siva Harsha")
                .password("encoded_pass")
                .build();

        when(tokenRepository.countByIpAddressAndCreatedAtAfter(anyString(), any())).thenReturn(0L);
        when(userRepository.findByEmailIgnoreCase("harsha@fintrack.com")).thenReturn(Optional.of(user));
        when(tokenRepository.countByUserIdAndCreatedAtAfter(eq(1L), any())).thenReturn(0L);

        String resetUrl = resetService.processForgotPassword(new ForgotPasswordRequest("harsha@fintrack.com"), "127.0.0.1");
        assertNotNull(resetUrl);
        assertTrue(resetUrl.contains("/reset-password?token="));

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
    @DisplayName("2. Unregistered email throws 404 NOT_FOUND, sends no email, and creates no token")
    void testProcessForgotPasswordUnregisteredEmailThrows404() {
        when(tokenRepository.countByIpAddressAndCreatedAtAfter(anyString(), any())).thenReturn(0L);
        when(userRepository.findByEmailIgnoreCase("unregistered@fintrack.com")).thenReturn(Optional.empty());

        ResponseStatusException ex = assertThrows(ResponseStatusException.class, () ->
                resetService.processForgotPassword(new ForgotPasswordRequest("unregistered@fintrack.com"), "127.0.0.1")
        );

        assertEquals(HttpStatus.NOT_FOUND, ex.getStatusCode());
        assertEquals("No account is registered with this email address", ex.getReason());

        // Verifies zero tokens saved and zero emails sent
        verify(tokenRepository, never()).save(any());
        verify(authEmailService, never()).sendPasswordResetEmailAsync(anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("3. Email with leading/trailing whitespace is trimmed and handled consistently")
    void testProcessForgotPasswordWithWhitespace() {
        User user = User.builder()
                .id(2L)
                .username("whitespace_user")
                .email("clean@fintrack.com")
                .fullName("Whitespace User")
                .password("encoded_pass")
                .build();

        when(tokenRepository.countByIpAddressAndCreatedAtAfter(anyString(), any())).thenReturn(0L);
        when(userRepository.findByEmailIgnoreCase("clean@fintrack.com")).thenReturn(Optional.of(user));
        when(tokenRepository.countByUserIdAndCreatedAtAfter(eq(2L), any())).thenReturn(0L);

        // Input contains leading and trailing spaces
        String resetUrl = resetService.processForgotPassword(new ForgotPasswordRequest("   clean@fintrack.com   "), "127.0.0.1");
        assertNotNull(resetUrl);

        verify(userRepository, times(1)).findByEmailIgnoreCase("clean@fintrack.com");
        verify(authEmailService, times(1)).sendPasswordResetEmailAsync(eq("clean@fintrack.com"), anyString(), anyString());
    }

    @Test
    @DisplayName("4. Email case differences (uppercase) match registered account case-insensitively")
    void testProcessForgotPasswordCaseInsensitive() {
        User user = User.builder()
                .id(3L)
                .username("mixedcase_user")
                .email("user@fintrack.com")
                .fullName("Mixed Case User")
                .password("encoded_pass")
                .build();

        when(tokenRepository.countByIpAddressAndCreatedAtAfter(anyString(), any())).thenReturn(0L);
        when(userRepository.findByEmailIgnoreCase("user@fintrack.com")).thenReturn(Optional.of(user));
        when(tokenRepository.countByUserIdAndCreatedAtAfter(eq(3L), any())).thenReturn(0L);

        // Input in uppercase
        String resetUrl = resetService.processForgotPassword(new ForgotPasswordRequest("USER@FINTRACK.COM"), "127.0.0.1");
        assertNotNull(resetUrl);

        verify(userRepository, times(1)).findByEmailIgnoreCase("user@fintrack.com");
        verify(authEmailService, times(1)).sendPasswordResetEmailAsync(eq("user@fintrack.com"), anyString(), anyString());
    }

    @Test
    @DisplayName("5. Database lookup failure throws exception and does not report success or send email")
    void testProcessForgotPasswordDatabaseLookupFailure() {
        when(tokenRepository.countByIpAddressAndCreatedAtAfter(anyString(), any())).thenReturn(0L);
        when(userRepository.findByEmailIgnoreCase("db_error@fintrack.com")).thenThrow(new DataAccessException("DB connection error") {});

        assertThrows(DataAccessException.class, () ->
                resetService.processForgotPassword(new ForgotPasswordRequest("db_error@fintrack.com"), "127.0.0.1")
        );

        verify(tokenRepository, never()).save(any());
        verify(authEmailService, never()).sendPasswordResetEmailAsync(anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("6. IP rate limiting blocks excessive requests (> 10 per hour)")
    void testProcessForgotPasswordIpRateLimitExceeded() {
        when(tokenRepository.countByIpAddressAndCreatedAtAfter(eq("192.168.1.50"), any())).thenReturn(10L);

        ResponseStatusException ex = assertThrows(ResponseStatusException.class, () ->
                resetService.processForgotPassword(new ForgotPasswordRequest("rate_limit@fintrack.com"), "192.168.1.50")
        );

        assertEquals(HttpStatus.TOO_MANY_REQUESTS, ex.getStatusCode());
        verify(userRepository, never()).findByEmailIgnoreCase(anyString());
        verify(authEmailService, never()).sendPasswordResetEmailAsync(anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("7. User rate limiting blocks excessive requests (> 5 per hour)")
    void testProcessForgotPasswordUserRateLimitExceeded() {
        User user = User.builder()
                .id(5L)
                .username("active_user")
                .email("user_limit@fintrack.com")
                .fullName("Active User")
                .password("encoded_pass")
                .build();

        when(tokenRepository.countByIpAddressAndCreatedAtAfter(anyString(), any())).thenReturn(0L);
        when(userRepository.findByEmailIgnoreCase("user_limit@fintrack.com")).thenReturn(Optional.of(user));
        when(tokenRepository.countByUserIdAndCreatedAtAfter(eq(5L), any())).thenReturn(5L);

        ResponseStatusException ex = assertThrows(ResponseStatusException.class, () ->
                resetService.processForgotPassword(new ForgotPasswordRequest("user_limit@fintrack.com"), "127.0.0.1")
        );

        assertEquals(HttpStatus.TOO_MANY_REQUESTS, ex.getStatusCode());
        verify(tokenRepository, never()).save(any());
        verify(authEmailService, never()).sendPasswordResetEmailAsync(anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("8. Token validation returns true for active unconsumed token, false for invalid/expired")
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
    @DisplayName("9. Reset password updates user credentials, consumes token, and sends security alert")
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
    @DisplayName("10. Reset password rejects weak passwords that do not meet corporate security policy")
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
    @DisplayName("11. Token single-use: Reusing an already consumed token fails")
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
