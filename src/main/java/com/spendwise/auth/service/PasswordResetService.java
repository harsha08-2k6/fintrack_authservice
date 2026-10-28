package com.spendwise.auth.service;

import com.spendwise.auth.dto.ForgotPasswordRequest;
import com.spendwise.auth.dto.ResetPasswordRequest;
import com.spendwise.auth.entity.PasswordResetToken;
import com.spendwise.auth.entity.User;
import com.spendwise.auth.repository.PasswordResetTokenRepository;
import com.spendwise.auth.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.HexFormat;
import java.util.Optional;

@Service
public class PasswordResetService {

    private static final Logger log = LoggerFactory.getLogger(PasswordResetService.class);
    private static final String PASSWORD_PATTERN = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%!^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?]).{8,}$";

    private final UserRepository userRepository;
    private final PasswordResetTokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthEmailService authEmailService;
    private final SecureRandom secureRandom = new SecureRandom();

    @Value("${fintrack.auth.reset-token-ttl-minutes:30}")
    private int tokenTtlMinutes;

    public PasswordResetService(
            UserRepository userRepository,
            PasswordResetTokenRepository tokenRepository,
            PasswordEncoder passwordEncoder,
            AuthEmailService authEmailService
    ) {
        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.authEmailService = authEmailService;
    }

    @Transactional
    public void processForgotPassword(ForgotPasswordRequest request, String ipAddress) {
        String cleanEmail = request.getEmail().trim().toLowerCase();

        // Check IP rate limit (maximum 10 requests per hour per IP)
        if (ipAddress != null && tokenRepository.countByIpAddressAndCreatedAtAfter(ipAddress, LocalDateTime.now().minusHours(1)) >= 10) {
            log.warn("Password reset rate limit exceeded for IP: {}", ipAddress);
            return; // Return silently to prevent timing / enumeration attacks
        }

        Optional<User> userOpt = userRepository.findByEmail(cleanEmail);
        if (userOpt.isEmpty()) {
            log.info("Password reset requested for non-existent address (enumeration prevented)");
            return;
        }

        User user = userOpt.get();

        // Check user rate limit (maximum 5 requests per hour per user)
        if (tokenRepository.countByUserIdAndCreatedAtAfter(user.getId(), LocalDateTime.now().minusHours(1)) >= 5) {
            log.warn("Password reset rate limit exceeded for user: {}", user.getId());
            return;
        }

        // 1. Invalidate any existing active tokens for this user
        tokenRepository.invalidateAllActiveTokensForUser(user.getId(), LocalDateTime.now());

        // 2. Generate a cryptographically secure 32-byte random token
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        String rawToken = HexFormat.of().formatHex(randomBytes);

        // 3. Store only the SHA-256 hash of the token
        String tokenHash = hashToken(rawToken);
        LocalDateTime expiresAt = LocalDateTime.now().plusMinutes(tokenTtlMinutes);

        PasswordResetToken resetToken = new PasswordResetToken(user.getId(), tokenHash, expiresAt, ipAddress);
        tokenRepository.save(resetToken);

        // 4. Send reset email asynchronously with raw token
        authEmailService.sendPasswordResetEmailAsync(user.getEmail(), user.getFullName(), rawToken);
    }

    public boolean validateToken(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            return false;
        }

        String tokenHash = hashToken(rawToken.trim());
        return tokenRepository.findByTokenHash(tokenHash)
                .map(PasswordResetToken::isValid)
                .orElse(false);
    }

    @Transactional
    public void resetPassword(ResetPasswordRequest request) {
        if (request.getToken() == null || request.getToken().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password reset token is required");
        }

        String tokenHash = hashToken(request.getToken().trim());
        PasswordResetToken token = tokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "The password reset link is invalid or has expired. Please request a new one."));

        if (!token.isValid()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "The password reset link is invalid or has expired. Please request a new one.");
        }

        // Validate password policy
        String newPassword = request.getNewPassword();
        if (newPassword == null || !newPassword.matches(PASSWORD_PATTERN)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Password must contain at least 8 characters, 1 uppercase letter, 1 lowercase letter, 1 number, and 1 special character");
        }

        User user = userRepository.findById(token.getUserId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User associated with this token no longer exists"));

        // Atomically consume token
        token.setConsumed(true);
        token.setConsumedAt(LocalDateTime.now());
        tokenRepository.save(token);

        // Invalidate any other active tokens
        tokenRepository.invalidateAllActiveTokensForUser(user.getId(), LocalDateTime.now());

        // Update password with BCrypt hash
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        log.info("Password successfully reset for user ID: {}", user.getId());

        // Send security notification email
        authEmailService.sendPasswordChangedAlertAsync(user.getEmail(), user.getFullName());
    }

    public String hashToken(String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedhash = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(encodedhash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }
}
