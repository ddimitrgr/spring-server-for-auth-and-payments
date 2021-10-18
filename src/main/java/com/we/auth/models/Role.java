package com.we.auth.models;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.IndexDirection;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.io.Serializable;
import java.util.UUID;

@Document(collection = "role")
@Accessors(chain = true) @Getter @Setter @NoArgsConstructor
public class Role implements Serializable {

    @Id
    String id = UUID.randomUUID().toString();
    @Indexed(unique = true, direction = IndexDirection.DESCENDING, dropDups = true)
    public String role;
}
