package com.we.auth.models;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import java.io.Serializable;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Document(collection="user")
@Accessors(chain = true) @Getter @Setter @NoArgsConstructor
public class User implements Serializable, UserDetails
{
    @Id String id = UUID.randomUUID().toString();

    @Indexed(unique = true, dropDups = true)
    @NotBlank(message = "Required")
    @Email(message = "Enter a valid email address")
    String email;

    @NotBlank(message = "Required")
    String password;

    @NotBlank(message = "Required")
    String firstName;

    @NotBlank(message = "Required")
    String lastName;


    @NotNull boolean active = false;
    @NotNull boolean visible =  false;
    @NotNull boolean suspended = false;
    @NotNull boolean emailVerified = false;

    @DBRef
    Set<Role> roles;

    ///////////////////////////////////////////////////////////////////////////////////////

    @JsonIgnore
    @Transient
    public Collection<GrantedAuthority> getAuthorities() {
        return new HashSet<>();
    }

    @JsonIgnore
    @Transient
    public String getUsername() {
        return id;
    }

    @JsonIgnore
    @Transient
    public boolean	isAccountNonExpired() {
        return true;
    }

    @JsonIgnore
    @Transient
    public boolean isAccountNonLocked() {
        return true;
    }

    @JsonIgnore
    @Transient
    public boolean	isCredentialsNonExpired() {
        return true;
    }

    @JsonIgnore
    @Transient
    public boolean isEnabled() {
        return active;
    }
}
