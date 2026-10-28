package com.spendwise.auth.service;

public interface AuthEmailService {

    void sendPasswordResetEmailAsync(String recipientEmail, String recipientName, String rawToken);

    void sendPasswordChangedAlertAsync(String recipientEmail, String recipientName);
}
