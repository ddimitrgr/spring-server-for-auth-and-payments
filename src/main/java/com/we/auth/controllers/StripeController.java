package com.we.auth.controllers;

import com.stripe.Stripe;
import com.stripe.exception.StripeException;
import com.stripe.model.*;
import com.we.auth.models.ExtendedUser;
import com.we.auth.models.User;
import com.we.auth.repos.CustomerRepository;
import com.we.auth.repos.SubscriptionRepository;
import com.we.auth.repos.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.PostConstruct;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController @RequestMapping("/payments")
public class StripeController {

    @Autowired UserRepository userRepository;
    @Autowired CustomerRepository customerRepository;
    @Autowired SubscriptionRepository subscriptionRepository;
    @Value("${stripe.clientSecret}") String stripeClientSecret;

    @PostConstruct
    public void init() {
        Stripe.apiKey = stripeClientSecret;
    }


    @RequestMapping(value = "plans", method = RequestMethod.GET)
    public ResponseEntity<?> listPlans(
            @AuthenticationPrincipal ExtendedUser user)
            throws StripeException
    {
        ProductCollection pc1 = Product.list(null);
        PlanCollection pc2 = Plan.list(null);
        Map<String, Object> o = new HashMap();
        o.put("products", pc1.getData());
        o.put("plans", pc2.getData());
        return new ResponseEntity<>(o, HttpStatus.OK);
    }

    @RequestMapping(value = "customer/from/source/{sourceId}", method = RequestMethod.POST)
    public ResponseEntity<com.we.auth.models.Customer> newCustomerFromToken(
            @PathVariable String sourceId,
            @AuthenticationPrincipal ExtendedUser user)
            throws StripeException
    {
        Optional<User> ou = userRepository.findById(user.getId());
        Map<String, Object> params = new HashMap<>();
        params.put("email", user.getEmail());
        params.put("source", sourceId);
        Customer customer = Customer.create(params);
        com.we.auth.models.Customer c = new com.we.auth.models.Customer()
                        .setActive(true).setExternalId(customer.getId())
                        .setProvider(com.we.auth.models.Customer.Provider.Stripe)
                        .setUser(ou.get());
        customerRepository.save(c);
        return new ResponseEntity<>(c, HttpStatus.CREATED);
    }

    @RequestMapping(value = "customer/{id}/subscribe/{planId}", method = RequestMethod.POST)
    @Transactional
    public ResponseEntity<com.we.auth.models.Subscription> subscribe(
            @PathVariable String id,
            @PathVariable String planId,
            @AuthenticationPrincipal ExtendedUser user)
            throws StripeException
    {
        Optional<User> ou = userRepository.findById(user.getId());
        List<com.we.auth.models.Customer> lc =
                customerRepository.findByUser(ou.get());
        if (lc.isEmpty())
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        Optional<com.we.auth.models.Customer> oc =
                lc.stream().filter(c -> c.getId().equals(id)).findFirst();
        if (!oc.isPresent())
            return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        Map<String, Object> item = new HashMap<>();
        item.put("plan", planId);
        Map<String, Object> items = new HashMap<>();
        items.put("0", item);
        Map<String, Object> params = new HashMap<>();
        params.put("customer", oc.get().getExternalId());
        params.put("items", items);
        com.we.auth.models.Subscription o =
                new com.we.auth.models.Subscription()
                        .fromStripe(Subscription.create(params))
                .setPlan(planId)
                .setUser(ou.get())
                .setOwner(ou.get());
        subscriptionRepository.save(o);
        return new ResponseEntity<>(o, HttpStatus.CREATED);
    }

    @RequestMapping(value = "customer/{id}/charges", method = RequestMethod.GET)
    public ResponseEntity<?> listCharges(
            @PathVariable String id,
            @AuthenticationPrincipal ExtendedUser user)
            throws StripeException
    {
        List<com.we.auth.models.Customer> lc =
                customerRepository.findByUser(user);
        if (lc.isEmpty())
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        Optional<com.we.auth.models.Customer> oc =
                lc.stream().filter(c -> c.getId().equals(id)).findFirst();
        if (!oc.isPresent())
            return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        Map<String, Object> opts = new HashMap<>();
        opts.put("customer", oc.get().getExternalId());
        ChargeCollection cc = Charge.list(opts);
        return new ResponseEntity<>(cc.getData(), HttpStatus.OK);
    }

    @RequestMapping(value = "subscription/{id}/cancel", method = RequestMethod.POST)
    @Transactional
    public ResponseEntity<?> subscriptionCancel(
            @PathVariable("id") String id,
            @AuthenticationPrincipal ExtendedUser user)
            throws StripeException
    {
        Optional<com.we.auth.models.Subscription> oSub = subscriptionRepository.findById(id);
        if (oSub.isPresent()) {
            if (oSub.get().getOwner().getId().equals(user.getId())) {
                Subscription stripeSub = Subscription.retrieve(oSub.get().getExternalId()).cancel(new HashMap<>());
                subscriptionRepository.save(oSub.get().cancel(stripeSub));
                return new ResponseEntity<>(oSub.get(), HttpStatus.OK);
            }
            return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        }
        return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }

    @RequestMapping(value = "subscription/{id}/query", method = RequestMethod.POST)
    @Transactional
    public ResponseEntity<?> subscriptionQuery(
            @PathVariable("id") String id,
            @AuthenticationPrincipal ExtendedUser user)
            throws StripeException
    {
        // Query Stripe for the value of currentSubscriptionEnd field.
        Optional<com.we.auth.models.Subscription> oSub = subscriptionRepository.findById(id);
        if (oSub.isPresent()) {
            if (oSub.get().getOwner().getId().equals(user.getId())) {
                Subscription stripeSub = Subscription.retrieve(oSub.get().getExternalId());
                subscriptionRepository.save(oSub.get().fromStripe(stripeSub));
                return new ResponseEntity<>(oSub.get(), HttpStatus.OK);
            }
            return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        }
        return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }

}