package com.we.auth.models;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import java.util.Date;
import java.util.UUID;

@Document(collection="emailVerification")
public class EmailVerification {
    @Id
    public String id = UUID.randomUUID().toString();
    @NotBlank
    @Email
    public String email;
    public Date expiration;
}
