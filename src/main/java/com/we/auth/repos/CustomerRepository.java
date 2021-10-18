package com.we.auth.repos;

import com.we.auth.models.Customer;
import com.we.auth.models.User;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

import java.util.List;
import java.util.Optional;

@RepositoryRestResource(collectionResourceRel = "customer")
public interface CustomerRepository extends MongoRepository<Customer, String>
{
    Optional<Customer> findById(String id);
    List<Customer> findByExternalId(String externalId);
    List<Customer> findByUser(User user);
}
