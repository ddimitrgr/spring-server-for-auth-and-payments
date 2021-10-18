package com.we.auth.repos;

import com.we.auth.models.PhoneInfo;
import com.we.auth.models.User;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

import java.util.List;
import java.util.Optional;

@RepositoryRestResource(collectionResourceRel = "phoneInfo")
public interface PhoneInfoRepository
        extends MongoRepository<PhoneInfo, String> {

    Optional<PhoneInfo> findById(String id);
    List<PhoneInfo> findByUser(User user);
}
