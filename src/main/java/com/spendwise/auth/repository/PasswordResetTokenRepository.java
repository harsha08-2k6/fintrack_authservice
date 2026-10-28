package com.spendwise.auth.repository;

import com.spendwise.auth.entity.PasswordResetToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {

    Optional<PasswordResetToken> findByTokenHash(String tokenHash);

    List<PasswordResetToken> findByUserIdAndConsumedFalse(Long userId);

    long countByUserIdAndCreatedAtAfter(Long userId, LocalDateTime after);

    long countByIpAddressAndCreatedAtAfter(String ipAddress, LocalDateTime after);

    @Modifying
    @Query("UPDATE PasswordResetToken t SET t.consumed = true, t.consumedAt = :now WHERE t.userId = :userId AND t.consumed = false")
    void invalidateAllActiveTokensForUser(@Param("userId") Long userId, @Param("now") LocalDateTime now);
}
