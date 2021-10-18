package com.we.auth.repos;

import com.we.auth.models.EmailVerification;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

import java.util.List;

@RepositoryRestResource(collectionResourceRel = "email_verification", path = "email-verification")
public interface EmailVerificationRepository
        extends MongoRepository<EmailVerification, String> {
    EmailVerification findByEmail(String email);
    List<EmailVerification> findAllByEmail(String email);
    void deleteAll(Iterable<? extends EmailVerification> entities);
}
