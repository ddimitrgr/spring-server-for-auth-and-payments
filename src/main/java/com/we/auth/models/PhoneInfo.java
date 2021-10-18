package com.we.auth.models;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;

import javax.validation.constraints.NotNull;
import java.util.UUID;

@Document(collection="phoneInfo")
@Accessors(chain = true) @Getter @Setter @NoArgsConstructor
public class PhoneInfo {
    @Id String id = UUID.randomUUID().toString();
    @DBRef User user;
    @NotNull(message = "Please enter a phone number.") String phoneNumber;
    @NotNull boolean verified = false;

    public boolean belongsTo(User user) { return getUser().getId().equals(user.getId()); }

}
