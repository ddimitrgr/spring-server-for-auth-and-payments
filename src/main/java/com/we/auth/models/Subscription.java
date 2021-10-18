package com.we.auth.models;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import java.util.Calendar;
import java.util.Date;
import java.util.UUID;

@Accessors(chain = true) @NoArgsConstructor @Getter @Setter
public class Subscription {
    @Id
    String id = UUID.randomUUID().toString();
    @DBRef
    User owner;
    @DBRef
    User user;
    @NotBlank String plan;
    @NotNull Date start;
    @NotNull Date currentPeriodStart;
    @NotNull Date currentPeriodEnd;
    @NotNull Customer.Provider provider = null;
    @NotNull String externalId = null;
    @NotNull boolean active = true;
    @NotNull boolean cancelled = false;

    @JsonIgnore
    public boolean isSubscribed() {
        if (!isActive())
            return false;
        else {
            // If cancelled check currentPeriodEnd as well.
            boolean isStillActive = !isCancelled()
                    || !getCurrentPeriodEnd().before(Calendar.getInstance().getTime());
            if (!isStillActive)
                setActive(false);
            return isActive();
        }
    }

    public Subscription fromStripe(com.stripe.model.Subscription sub) {
        if (sub.getStatus().equals("canceled"))
            cancel(sub);
        Calendar st = Calendar.getInstance();
        st.setTimeInMillis(sub.getStart().longValue() * 1000);
        Calendar cuSt = Calendar.getInstance();
        cuSt.setTimeInMillis(sub.getCurrentPeriodStart().longValue() * 1000);
        Calendar cuEn = Calendar.getInstance();
        cuEn.setTimeInMillis(sub.getCurrentPeriodEnd().longValue() * 1000);
        return setProvider(Customer.Provider.Stripe)
                .setExternalId(sub.getId())
                .setStart(st.getTime())
                .setCurrentPeriodStart(cuSt.getTime())
                .setCurrentPeriodEnd(cuEn.getTime());
    }

    public Subscription cancel(com.stripe.model.Subscription sub) {
        Calendar cuEn = Calendar.getInstance();
        cuEn.setTimeInMillis(sub.getCurrentPeriodEnd().longValue() * 1000);
        return setCancelled(true).setCurrentPeriodEnd(cuEn.getTime());
    }
}