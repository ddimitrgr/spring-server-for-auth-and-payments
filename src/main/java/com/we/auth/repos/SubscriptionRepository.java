package com.we.auth.repos;

import com.we.auth.models.Subscription;
import com.we.auth.models.User;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

@RepositoryRestResource(collectionResourceRel = "subscription")
public interface SubscriptionRepository extends MongoRepository<Subscription, String>
{
    Optional<Subscription> findById(String id);
    Optional<Subscription> findByExternalId(String externalId);
    List<Subscription> findByOwner(User owner);
    List<Subscription> findByUser(User user);
    Stream<Subscription> findByUserAndActiveIsTrueOrderByCurrentPeriodEndAsc(User user);
    default Optional<Subscription> findLastSubForUser(User user) {
        return findByUserAndActiveIsTrueOrderByCurrentPeriodEndAsc(user).findFirst();
    }
}