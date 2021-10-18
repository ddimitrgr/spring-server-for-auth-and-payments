package com.we.auth.models;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.Accessors;

import javax.validation.constraints.NotNull;
import java.util.Date;

@Accessors(chain = true) @Getter
@Setter
@NoArgsConstructor
public class ExtendedUser extends User {
    @NotNull boolean subscribed = false;
    String subscriptionPlan;
    Date subscriptionEnd;
}
