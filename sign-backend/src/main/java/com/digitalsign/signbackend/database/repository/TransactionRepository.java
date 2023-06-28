package com.digitalsign.signbackend.database.repository;

import com.digitalsign.signbackend.database.entity.TransactionEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TransactionRepository extends JpaRepository<TransactionEntity, Long> {
}
