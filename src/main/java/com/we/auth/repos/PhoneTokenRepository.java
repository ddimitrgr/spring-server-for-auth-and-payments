package com.we.auth.repos;

import com.we.auth.models.PhoneInfo;
import com.we.auth.models.PhoneToken;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

import java.util.List;
import java.util.Optional;

@RepositoryRestResource(collectionResourceRel = "phoneToken")
public interface PhoneTokenRepository
        extends MongoRepository<PhoneToken, String> {

    Optional<PhoneToken> findById(String id);
    List<PhoneToken> findByPhoneInfo(PhoneInfo pi);
    List<PhoneToken> findByPhoneInfoIn(List<PhoneInfo> lpi);
}
