package com.we.auth.models;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.springframework.data.annotation.Id;

import javax.validation.constraints.NotNull;

@Accessors(chain = true) @Getter @Setter @NoArgsConstructor
public class CreditCardStore {
    @Id String tokenId;
    @NotNull(message = "Enter you name as it appears on the card.")
    String name;
    @NotNull(message = "Enter the address of the credit card owner.")
    String addressLine1;
    String addressLine2;
    @NotNull(message = "City is required.")
    String addressCity;
    @NotNull(message = "State is required.")
    String addressState;
    @NotNull(message = "Country is required.")
    String addressCountry;
}
