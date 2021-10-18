package com.we.auth.repos;

import com.we.auth.models.Role;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

@RepositoryRestResource(collectionResourceRel = "role", path = "role")
public interface RoleRepository extends MongoRepository<Role, String> {

    Role findByRole(String role);

}
