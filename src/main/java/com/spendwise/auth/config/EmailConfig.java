package com.spendwise.auth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.Properties;
import java.util.concurrent.Executor;

@Configuration
public class EmailConfig {

    @Value("${fintrack.mail.host:smtp.gmail.com}")
    private String host;

    @Value("${fintrack.mail.port:587}")
    private int port;

    @Value("${fintrack.mail.username:}")
    private String username;

    @Value("${fintrack.mail.password:}")
    private String password;

    @Value("${fintrack.mail.auth:true}")
    private boolean auth;

    @Value("${fintrack.mail.starttls.enable:true}")
    private boolean starttlsEnable;

    @Value("${fintrack.mail.starttls.required:true}")
    private boolean starttlsRequired;

    @Value("${fintrack.mail.connection-timeout-ms:10000}")
    private int connectionTimeout;

    @Value("${fintrack.mail.timeout-ms:10000}")
    private int timeout;

    @Value("${fintrack.mail.write-timeout-ms:10000}")
    private int writeTimeout;

    @Bean
    public JavaMailSender javaMailSender() {
        JavaMailSenderImpl sender = new JavaMailSenderImpl();
        sender.setHost(host);
        sender.setPort(port);
        sender.setUsername(username);
        sender.setPassword(password);

        Properties props = sender.getJavaMailProperties();
        props.put("mail.transport.protocol", "smtp");
        props.put("mail.smtp.auth", String.valueOf(auth));
        props.put("mail.smtp.starttls.enable", String.valueOf(starttlsEnable));
        props.put("mail.smtp.starttls.required", String.valueOf(starttlsRequired));
        props.put("mail.smtp.connectiontimeout", String.valueOf(connectionTimeout));
        props.put("mail.smtp.timeout", String.valueOf(timeout));
        props.put("mail.smtp.writetimeout", String.valueOf(writeTimeout));

        return sender;
    }

    @Bean(name = "authEmailExecutor")
    public Executor authEmailExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(2);
        executor.setMaxPoolSize(10);
        executor.setQueueCapacity(100);
        executor.setThreadNamePrefix("auth-email-worker-");
        executor.initialize();
        return executor;
    }
}
