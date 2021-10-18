package com.we.auth.models;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import java.util.UUID;

@Document(collection="customer")
@Accessors(chain = true) @Getter @Setter @NoArgsConstructor
public class Customer
{
    public enum Provider { Stripe }

    @Id String id = UUID.randomUUID().toString();
    @DBRef User user;
    @NotBlank String externalId;
    // TODO: Role ?
    @NotNull boolean active = true;
    @NotNull Provider provider = Provider.Stripe;
}
