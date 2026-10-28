package com.spendwise.auth.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Component
public class AuthEmailTemplateBuilder {

    @Value("${fintrack.auth.frontend-url:http://localhost:5173}")
    private String frontendUrl;

    public static class EmailContent {
        private final String subject;
        private final String htmlBody;
        private final String textBody;

        public EmailContent(String subject, String htmlBody, String textBody) {
            this.subject = subject;
            this.htmlBody = htmlBody;
            this.textBody = textBody;
        }

        public String getSubject() { return subject; }
        public String getHtmlBody() { return htmlBody; }
        public String getTextBody() { return textBody; }
    }

    public EmailContent buildPasswordResetEmail(String recipientName, String rawToken, int ttlMinutes) {
        String safeName = escapeHtml(recipientName != null && !recipientName.isBlank() ? recipientName : "FinTrack User");
        String resetUrl = frontendUrl.replaceAll("/+$", "") + "/reset-password?token=" + rawToken;

        String subject = "Reset your FinTrack password";

        String contentHtml = "" +
                "<div style=\"text-align: left; margin-bottom: 24px;\">" +
                "  <span style=\"display: inline-block; background-color: #ECFDF5; color: #059669; border: 1px solid #A7F3D0; padding: 5px 14px; border-radius: 9999px; font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 14px;\">" +
                "    Account Security" +
                "  </span>" +
                "  <h2 style=\"color: #0F172A; font-size: 22px; font-weight: 800; margin: 0 0 12px 0; line-height: 1.3;\">" +
                "    Password Reset Request" +
                "  </h2>" +
                "  <p style=\"color: #475569; font-size: 15px; line-height: 1.6; margin: 0 0 16px 0;\">" +
                "    Hello <strong>" + safeName + "</strong>," +
                "  </p>" +
                "  <p style=\"color: #475569; font-size: 15px; line-height: 1.6; margin: 0 0 20px 0;\">" +
                "    We received a request to reset the password for your FinTrack corporate account. Click the button below to choose a new password:" +
                "  </p>" +
                "</div>" +

                "<!-- Primary CTA Button Table -->" +
                "<table role=\"presentation\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\" style=\"margin: 28px 0; width: 100%;\">" +
                "  <tr>" +
                "    <td align=\"center\">" +
                "      <table role=\"presentation\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\">" +
                "        <tr>" +
                "          <td align=\"center\" bgcolor=\"#10B981\" style=\"border-radius: 8px; box-shadow: 0 4px 14px rgba(16, 185, 129, 0.35);\">" +
                "            <a href=\"" + resetUrl + "\" target=\"_blank\" style=\"display: inline-block; padding: 14px 32px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; font-size: 15px; color: #FFFFFF; font-weight: 700; text-decoration: none; border-radius: 8px; letter-spacing: 0.2px;\">" +
                "              Reset Password &rarr;" +
                "            </a>" +
                "          </td>" +
                "        </tr>" +
                "      </table>" +
                "    </td>" +
                "  </tr>" +
                "</table>" +

                "<!-- Expiration and Security Box -->" +
                "<div style=\"background-color: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 12px; padding: 18px 20px; margin: 24px 0;\">" +
                "  <table role=\"presentation\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\" style=\"width: 100%;\">" +
                "    <tr>" +
                "      <td style=\"padding-bottom: 8px;\">" +
                "        <strong style=\"color: #0F172A; font-size: 14px;\">&#9200; Link Expiration:</strong>" +
                "        <span style=\"color: #64748B; font-size: 14px;\"> This link is valid for <strong>" + ttlMinutes + " minutes</strong> and can only be used once.</span>" +
                "      </td>" +
                "    </tr>" +
                "    <tr>" +
                "      <td>" +
                "        <strong style=\"color: #0F172A; font-size: 14px;\">&#128274; Security Notice:</strong>" +
                "        <span style=\"color: #64748B; font-size: 14px;\"> If you did not request a password reset, you can safely ignore this email. Your current password remains secure.</span>" +
                "      </td>" +
                "    </tr>" +
                "  </table>" +
                "</div>" +

                "<!-- Plain Text Link Fallback -->" +
                "<div style=\"margin-top: 24px; padding-top: 16px; border-top: 1px solid #F1F5F9;\">" +
                "  <p style=\"color: #94A3B8; font-size: 12px; line-height: 1.5; margin: 0 0 6px 0;\">" +
                "    If the button above does not work, copy and paste this link into your web browser:" +
                "  </p>" +
                "  <p style=\"word-break: break-all; margin: 0;\">" +
                "    <a href=\"" + resetUrl + "\" target=\"_blank\" style=\"color: #059669; font-size: 12px; text-decoration: underline; font-weight: 600;\">" +
                "      " + resetUrl + "" +
                "    </a>" +
                "  </p>" +
                "</div>";

        String textBody = "FinTrack - Password Reset Request\n\n" +
                "Hello " + recipientName + ",\n\n" +
                "We received a request to reset your FinTrack password.\n" +
                "Click the link below (or paste it into your browser) to choose a new password:\n\n" +
                resetUrl + "\n\n" +
                "This link will expire in " + ttlMinutes + " minutes and is valid for single use only.\n\n" +
                "If you did not request this reset, you can safely ignore this email. Your password will remain unchanged.\n\n" +
                "Regards,\n" +
                "FinTrack Corporate Security Team\n" +
                frontendUrl;

        return new EmailContent(subject, wrapHtml("Reset your password", contentHtml), textBody);
    }

    public EmailContent buildPasswordChangedAlert(String recipientName, LocalDateTime changeTime) {
        String safeName = escapeHtml(recipientName != null && !recipientName.isBlank() ? recipientName : "FinTrack User");
        String formattedDate = changeTime != null ? changeTime.format(DateTimeFormatter.ofPattern("MMM dd, yyyy 'at' hh:mm a")) : "Recently";

        String subject = "Security Alert: FinTrack password changed";

        String contentHtml = "" +
                "<div style=\"text-align: left; margin-bottom: 24px;\">" +
                "  <span style=\"display: inline-block; background-color: #ECFDF5; color: #059669; border: 1px solid #A7F3D0; padding: 5px 14px; border-radius: 9999px; font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 14px;\">" +
                "    Security Confirmation" +
                "  </span>" +
                "  <h2 style=\"color: #0F172A; font-size: 22px; font-weight: 800; margin: 0 0 12px 0; line-height: 1.3;\">" +
                "    Your Password Was Successfully Updated" +
                "  </h2>" +
                "  <p style=\"color: #475569; font-size: 15px; line-height: 1.6; margin: 0 0 16px 0;\">" +
                "    Hello <strong>" + safeName + "</strong>," +
                "  </p>" +
                "  <p style=\"color: #475569; font-size: 15px; line-height: 1.6; margin: 0 0 20px 0;\">" +
                "    This is a confirmation that the password for your FinTrack account was successfully updated on <strong>" + formattedDate + "</strong>." +
                "  </p>" +
                "</div>" +

                "<div style=\"background-color: #FEF2F2; border: 1px solid #FECACA; border-radius: 12px; padding: 18px 20px; margin: 24px 0;\">" +
                "  <p style=\"color: #DC2626; font-size: 14px; font-weight: 700; margin: 0 0 6px 0;\">" +
                "    &#9888; Did not make this change?" +
                "  </p>" +
                "  <p style=\"color: #991B1B; font-size: 13px; line-height: 1.5; margin: 0;\">" +
                "    If you did not authorize this change, please immediately reset your password using the login page or contact your organization administrator." +
                "  </p>" +
                "</div>";

        String textBody = "FinTrack Security Alert: Password Updated\n\n" +
                "Hello " + recipientName + ",\n\n" +
                "Your FinTrack password was successfully updated on " + formattedDate + ".\n\n" +
                "If you did not make this change, please contact security immediately.\n\n" +
                "FinTrack Security Team";

        return new EmailContent(subject, wrapHtml("Password Changed", contentHtml), textBody);
    }

    private String wrapHtml(String preheader, String bodyContent) {
        return "<!DOCTYPE html>\n" +
                "<html lang=\"en\">\n" +
                "<head>\n" +
                "  <meta charset=\"UTF-8\">\n" +
                "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n" +
                "  <meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\">\n" +
                "  <title>FinTrack Notification</title>\n" +
                "  <!--[if mso]><style>table,td,th{font-family:Arial,sans-serif!important;}</style><![endif]-->\n" +
                "</head>\n" +
                "<body style=\"margin: 0; padding: 0; background-color: #F4F7F6; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; -webkit-font-smoothing: antialiased; color: #0F172A;\">\n" +
                "  <!-- Hidden Preheader -->\n" +
                "  <div style=\"display: none; font-size: 1px; color: #FFFFFF; line-height: 1px; max-height: 0px; max-width: 0px; opacity: 0; overflow: hidden;\">\n" +
                "    " + escapeHtml(preheader) + "\n" +
                "  </div>\n" +
                "  \n" +
                "  <!-- Outer Container -->\n" +
                "  <table role=\"presentation\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\" width=\"100%\" style=\"background-color: #F4F7F6; min-width: 100%;\">\n" +
                "    <tr>\n" +
                "      <td align=\"center\" style=\"padding: 36px 16px 48px;\">\n" +
                "        \n" +
                "        <!-- Main Card (Max 600px) -->\n" +
                "        <table role=\"presentation\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\" width=\"100%\" style=\"max-width: 600px; background-color: #FFFFFF; border-radius: 16px; border: 1px solid #E2E8F0; overflow: hidden; box-shadow: 0 10px 25px -5px rgba(15, 23, 42, 0.08), 0 8px 10px -6px rgba(15, 23, 42, 0.04);\">\n" +
                "          \n" +
                "          <!-- Header Bar with Wordmark -->\n" +
                "          <tr>\n" +
                "            <td style=\"background: linear-gradient(170deg, #090E17 0%, #0F172A 60%, #0D1B2A 100%); padding: 24px 32px; border-bottom: 2px solid #10B981;\">\n" +
                "              <table role=\"presentation\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\" width=\"100%\">\n" +
                "                <tr>\n" +
                "                  <td align=\"left\" valign=\"middle\">\n" +
                "                    <span style=\"display: inline-block; width: 32px; height: 32px; background: linear-gradient(135deg, #10B981 0%, #059669 100%); border-radius: 8px; text-align: center; line-height: 32px; color: #FFFFFF; font-weight: 800; font-size: 16px; margin-right: 10px; vertical-align: middle; box-shadow: 0 2px 8px rgba(16, 185, 129, 0.35);\">&#9650;</span>\n" +
                "                    <span style=\"color: #FFFFFF; font-size: 20px; font-weight: 800; letter-spacing: -0.5px; vertical-align: middle;\">Fin<span style=\"color: #10B981;\">Track</span></span>\n" +
                "                    <span style=\"color: #94A3B8; font-size: 11px; font-weight: 600; margin-left: 8px; text-transform: uppercase; letter-spacing: 0.5px; vertical-align: middle;\">Security</span>\n" +
                "                  </td>\n" +
                "                  <td align=\"right\" valign=\"middle\">\n" +
                "                    <span style=\"background-color: rgba(16, 185, 129, 0.15); color: #10B981; border: 1px solid rgba(16, 185, 129, 0.35); font-size: 11px; font-weight: 700; padding: 4px 10px; border-radius: 9999px; text-transform: uppercase; letter-spacing: 0.5px;\">Live Engine</span>\n" +
                "                  </td>\n" +
                "                </tr>\n" +
                "              </table>\n" +
                "            </td>\n" +
                "          </tr>\n" +
                "          \n" +
                "          <!-- Body Area -->\n" +
                "          <tr>\n" +
                "            <td style=\"padding: 32px 32px 28px;\">\n" +
                "              " + bodyContent + "\n" +
                "            </td>\n" +
                "          </tr>\n" +
                "          \n" +
                "          <!-- Footer Area -->\n" +
                "          <tr>\n" +
                "            <td style=\"background-color: #F8FAFC; padding: 24px 32px; border-top: 1px solid #E2E8F0; text-align: center;\">\n" +
                "              <p style=\"color: #64748B; font-size: 12px; line-height: 1.5; margin: 0 0 8px 0;\">\n" +
                "                This is an automated security transmission from <strong>FinTrack</strong>.<br>\n" +
                "                Corporate Financial Expense Analytics &amp; Budget Reconciliation System.\n" +
                "              </p>\n" +
                "              <p style=\"color: #94A3B8; font-size: 11px; line-height: 1.5; margin: 0;\">\n" +
                "                Never share your password, reset link, or multi-factor authentication codes with anyone.\n" +
                "              </p>\n" +
                "            </td>\n" +
                "          </tr>\n" +
                "          \n" +
                "        </table>\n" +
                "        \n" +
                "      </td>\n" +
                "    </tr>\n" +
                "  </table>\n" +
                "</body>\n" +
                "</html>";
    }

    public String escapeHtml(String input) {
        if (input == null) return "";
        return input.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }
}
