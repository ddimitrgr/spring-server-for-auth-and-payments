package com.we.auth;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.org.apache.xpath.internal.operations.Bool;
import com.we.auth.controllers.AuthController;
import com.we.auth.controllers.PhoneController;
import com.we.auth.models.*;
import com.we.auth.repos.*;
import com.we.auth.services.OurUserDetailsService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.apache.commons.beanutils.PropertyUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.ResultHandler;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.*;
import java.util.logging.Logger;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


@FixMethodOrder
@RunWith(SpringRunner.class)
@SpringBootTest
public class AuthApplicationTests {

    static final Logger log = Logger.getLogger(AuthApplicationTests.class.getName());

    @Value("${our.secret.signing.key}") String signingKey;
    @Value("${access.token.duration}") int accessTokenDuration;
    @Value("${refresh.token.duration}") int refreshTokenDuration;
    @Value("${testUser.email}") String email;
    @Value("${twilio.testUser.phoneNumber}") String phone;

    final String stripeTokenForTesting = "tok_visa";
    final String firstName = "John";
    final String lastName = "Doe";
    String password = "random";
    String changedPassword = "random_changed";
    String resetPassword = "random_reset";

    String token;
    String refresh;
    String id;

    MockMvc mockMvc;
    MockHttpSession mockHttpSession;

    @Autowired WebApplicationContext wac;
    @Autowired FilterChainProxy filterChainProxy;
    @Autowired UserRepository userRepository;
    @Autowired RoleRepository roleRepository;
    @Autowired EmailVerificationRepository emailVerificationRepository;
    @Autowired CustomerRepository customerRepository;
    @Autowired SubscriptionRepository subscriptionRepository;
    @Autowired PhoneInfoRepository phoneInfoRepository;
    @Autowired PhoneTokenRepository phoneTokenRepository;
    @Autowired OurUserDetailsService ourUserDetailsService;

    @Before
    public void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(wac).addFilters(filterChainProxy).build();
        mockHttpSession = new MockHttpSession();
    }

    @After
    public void tearDown() {
        userRepository.deleteAll();
        emailVerificationRepository.deleteAll();
        customerRepository.deleteAll();
        subscriptionRepository.deleteAll();
        phoneInfoRepository.deleteAll();
        phoneTokenRepository.deleteAll();
    }

    ResultHandler httpPrinter(String verb, String path) {
        return (MvcResult result) -> {
            log.info(result.getResponse().getStatus() + " " + verb + " " + path);
        };
    }

    static public MockHttpServletResponse RestUserLogin(MockMvc mockMvc, String email, String password) throws Exception {
        ObjectMapper om = new ObjectMapper();
        AuthController.UserLogin ul = new AuthController.UserLogin();
        ul.email = email;
        ul.password = password;
        RequestBuilder rb =
                post("/accounts/login").content(om.writeValueAsString(ul))
                        .contentType(MediaType.APPLICATION_JSON);
        MockHttpServletResponse r = mockMvc.perform(rb)
                .andReturn().getResponse();
        log.info(String.format("RestUserLogin: ", r.getContentAsString()));
        return r;
    }

    static public MockHttpServletResponse RestRefreshToken(MockMvc mockMvc, String token) throws Exception {
        log.info(String.format("RestRefreshToken() token = %s", token));
        String url = String.format("/accounts/token/refresh/%s", token);
        log.info(String.format("RestRefreshToken() url = %s", url));
        MockHttpServletRequestBuilder rb = post(url).contentType(MediaType.APPLICATION_JSON);
        return mockMvc.perform(rb).andReturn().getResponse();
    }

    static public MockHttpServletResponse RestGetUrl(MockMvc mockMvc, String url, String token) throws Exception {
        MockHttpServletRequestBuilder rb = get(url).contentType(MediaType.APPLICATION_JSON);
        log.info("RestGetUrl: after builder !");
        if (token != null)
            rb = rb.header("authorization", "Bearer " + token);
        log.info("RestGetUrl: exiting !");
        try {
            MockHttpServletResponse r = mockMvc.perform(rb).andReturn().getResponse();
            log.info("RestGetUrl: response =");
            log.info(r.toString());
            return r;

        } catch (Exception e) {
            log.info("Exception @ RestGetUrl = ");
            e.printStackTrace();
            return null;
        }
    }

    static public String RestUserRegister(MockMvc mockMvc,
                                          String email, String password,
                                          String firstName, String lastName, boolean acceptTermsOfService) throws Exception {
        ObjectMapper om = new ObjectMapper();
        User u = new User()
                .setEmail(email).setPassword(password)
                .setFirstName(firstName).setLastName(lastName);
        AuthController.UserRegister ur = new AuthController.UserRegister();
        ur.email = email;
        ur.password = password;
        ur.firstName = firstName;
        ur.lastName = lastName;
        ur.acceptTermsOfService = acceptTermsOfService;
        RequestBuilder rb =
                post("/accounts/register").content(om.writeValueAsString(ur))
                        .contentType(MediaType.APPLICATION_JSON);
        MockHttpServletResponse r = mockMvc.perform(rb)
                .andExpect(status().isCreated())
                .andReturn().getResponse();
        Map<String, String> resp = new ObjectMapper().readValue(r.getContentAsString(), Map.class);
        return resp.get("id");
    }

    static public int RestEmailVerify(MockMvc mockMvc, String id, String token) throws Exception {
        String url = String.format("/accounts/email/verify/%s/%s", id, token);
        RequestBuilder rb = get(url).contentType(MediaType.APPLICATION_JSON);
        MockHttpServletResponse r = mockMvc.perform(rb)
                .andExpect(status().isOk())
                .andReturn().getResponse();
        return r.getStatus();
    }


    public int RestChangePassword(String oldPassword, String password, String token) {
        String path = "/accounts/password/change";
        ObjectMapper om = new ObjectMapper();
        AuthController.PasswordChange change = new AuthController.PasswordChange();
        change.oldPassword = oldPassword;
        change.password = password;
        try {
            RequestBuilder rb = post(path)
                    .content(om.writeValueAsString(change))
                    .contentType(MediaType.APPLICATION_JSON)
                    .header("authorization", "Bearer " + token);
            MockHttpServletResponse r = mockMvc.perform(rb).andReturn().getResponse();
            return r.getStatus();
        } catch(Exception e) {
            e.printStackTrace();
            return -1;
        }
    }

    public int RestResetPassword(String email) {
        String path = "/accounts/password/reset";
        ObjectMapper om = new ObjectMapper();
        AuthController.PasswordReset reset = new AuthController.PasswordReset();
        reset.email = email;
        try {
            RequestBuilder rb = post(path)
                    .content(om.writeValueAsString(reset))
                    .contentType(MediaType.APPLICATION_JSON);
            MockHttpServletResponse r = mockMvc.perform(rb).andReturn().getResponse();
            return r.getStatus();
        } catch(Exception e) {
            e.printStackTrace();
            return -1;
        }
    }

    public int RestResetSetNewPassword(String verificationId, String password)
            throws Exception
    {
        String path = "/accounts/password/reset/new/"+ verificationId;
        ObjectMapper om = new ObjectMapper();
        AuthController.PasswordResetNew resetNew = new AuthController.PasswordResetNew();
        resetNew.password = password;
        RequestBuilder rb = post(path)
                .content(om.writeValueAsString(resetNew))
                .contentType(MediaType.APPLICATION_JSON);
        MockHttpServletResponse r = mockMvc.perform(rb).andReturn().getResponse();
        return r.getStatus();
    }

    String createUser(String email, String password, String firstName, String lastName) {
        User u = new User().setActive(true).setEmailVerified(true)
                .setFirstName(firstName).setLastName(lastName)
                .setEmail(email).setPassword(password);
        ourUserDetailsService.saveUser(u);
        return u.getId();
    }

    String saveUser(String email, String password) {
        User u = ourUserDetailsService.findUserByEmail(email);
        u.setPassword(password);
        ourUserDetailsService.saveUser(u);
        return u.getId();
    }

    Map<String, String> loginUser(String email, String password) throws Exception {
        MockHttpServletResponse r = RestUserLogin(mockMvc, email, password);
        return new ObjectMapper().readValue(r.getContentAsString(), Map.class);
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    PhoneToken createNewPhoneToken(String phoneId) throws Exception {
        String url = "/validation/phone/token/create/" + phoneId;
        String json =
                mockMvc.perform(post(url).header("authorization", "Bearer " + token))
                        .andDo(httpPrinter("POST", url))
                        .andExpect(status().isCreated())
                        .andReturn().getResponse().getContentAsString();
        log.info(String.format("New phone token: %s", json));
        return new ObjectMapper().readValue(json, PhoneToken.class);
    }

    PhoneToken createNewPhone(String phone) throws Exception {
        ObjectMapper om = new ObjectMapper();
        PhoneController.NewPhoneInfo npi = new PhoneController.NewPhoneInfo();
        npi.setPhoneNumber(phone);
        String bd = om.writeValueAsString(npi);
        String json =
                mockMvc.perform(
                        post("/validation/phone")
                                .header("authorization", "Bearer " + token)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(bd)
                )
                        .andDo(httpPrinter("POST", "/validation/phone"))
                        .andExpect(status().isCreated())
                        .andReturn().getResponse().getContentAsString();
        return om.readValue(json, PhoneToken.class);
    }

    void verifyNewPhone(PhoneToken pt) throws Exception {
        ObjectMapper om = new ObjectMapper();
        PhoneController.ExternalPhoneToken ept =
                new PhoneController.ExternalPhoneToken();
        Optional<PhoneToken> optInDatabase = phoneTokenRepository.findById(pt.getId());
        ept.setCode(optInDatabase.get().getToken());
        ept.setId(pt.getId());
        String bd = om.writeValueAsString(ept);
        mockMvc.perform(
                post("/validation/phone/token/verify", bd)
                        .header("authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(bd)
        )
                .andDo(httpPrinter("POST", "/validation/phone/token/verify"))
                .andExpect(status().isOk());
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    Customer createCustomer(String stripeToken, String token) throws Exception {
        String path = "/payments/customer/from/source/" + stripeToken;
        String json =
                mockMvc.perform(post(path).header("authorization", "Bearer " + token))
                        .andDo(httpPrinter("POST", path))
                        .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
        ObjectMapper om = new ObjectMapper();
        return om.readValue(json, Customer.class);
    }

    Map<String, Object> listPlans() throws Exception {
        String json =
                mockMvc.perform(get("/payments/plans").header("authorization", "Bearer " + token))
                        .andDo(httpPrinter("GET", "/payments/plans"))
                        .andExpect(status().isOk()).andReturn()
                        .getResponse().getContentAsString();
        ObjectMapper om = new ObjectMapper();
        return om.readValue(json, new TypeReference<HashMap<String, Object>>() {
        });
    }

    Subscription subscribe(String id, String planId) throws Exception {
        String path = "/payments/customer/" + id + "/subscribe/" + planId;
        String json =
                mockMvc.perform(post(path).header("authorization", "Bearer " + token))
                        .andDo(httpPrinter("POST", path))
                        .andExpect(status().isCreated()).andReturn()
                        .getResponse().getContentAsString();
        ObjectMapper om = new ObjectMapper();
        return om.readValue(json, Subscription.class);
    }

    Subscription cancelSubscription(String id) throws Exception {
        String path = "/payments/subscription/" + id + "/cancel";
        String json =
                mockMvc.perform(post(path).header("authorization", "Bearer " + token))
                        .andDo(httpPrinter("POST", path))
                        .andExpect(status().isOk()).andReturn()
                        .getResponse().getContentAsString();
        ObjectMapper om = new ObjectMapper();
        return om.readValue(json, Subscription.class);
    }

    Subscription subscriptionQuery(String id) throws Exception {
        String path = "/payments/subscription/" + id + "/query";
        String json =
                mockMvc.perform(post(path).header("authorization", "Bearer " + token))
                        .andDo(httpPrinter("POST", path))
                        .andExpect(status().isOk()).andReturn()
                        .getResponse().getContentAsString();
        ObjectMapper om = new ObjectMapper();
        return om.readValue(json, Subscription.class);
    }

    List<Object> listCharges(String id) throws Exception {
        String path = "/payments/customer/" + id + "/charges";
        String json =
                mockMvc.perform(get(path).header("authorization", "Bearer " + token))
                        .andDo(httpPrinter("GET", path))
                        .andExpect(status().isOk()).andReturn()
                        .getResponse().getContentAsString();
        ObjectMapper om = new ObjectMapper();
        return om.readValue(json, new TypeReference<List<Object>>() {});
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    @Test
    public void testRegister_1() throws Exception {
        id = RestUserRegister(mockMvc, email, password, firstName, lastName, true);
        User u = ourUserDetailsService.findUserByEmail(email);
        EmailVerification v = emailVerificationRepository.findByEmail(email);
        assert u.getId().equals(id);
        assert !u.isEmailVerified();
        assert !u.isActive();
        assert v.email.equals(email);

        int verificationHttpStatusCode = RestEmailVerify(mockMvc, u.getId(), v.id);

        assert verificationHttpStatusCode == HttpStatus.OK.value();
        assert !u.isEmailVerified();
        assert !u.isActive();
    }

    @Test
    public void testLogin_2() throws Exception {
        if (id == null)
            id = createUser(email, password, firstName, lastName);
        // Test forbidden
        assert RestGetUrl(mockMvc, "/accounts/profile", null).getStatus() == HttpStatus.FORBIDDEN.value();
        // Login
        Map<String, String> jwt = loginUser(email, password);
        token = jwt.get("access");
        refresh = jwt.get("refresh");
        log.info("testLogin() refresh = ");
        log.info(refresh);
        Claims claims = (Claims) Jwts.parser().setSigningKey(signingKey).parse(token).getBody();
        int du = (Integer) claims.get("exp") - (Integer) claims.get("iat");
        log.info(String.format("Jwt token                 = %s", token));
        log.info(String.format("Jwt expiration in seconds = %d", du));
        log.info(String.format("Jwt expiration expected   = %d", accessTokenDuration));
        for (Map.Entry<String, Object> entry : claims.entrySet())
            log.info(String.format("Jwt claim key / value =  %s / %s", entry.getKey(), entry.getValue()));
        assert claims.getSubject().equals(id);
        assert claims.get("email").equals(email);
        assert claims.get("id").equals(id);
        assert !claims.get("subExists", Boolean.class);
        assert du == accessTokenDuration;
        // Test access
        MockHttpServletResponse resp = RestGetUrl(mockMvc, "/accounts/profile", token);
        assert resp.getStatus() == HttpStatus.OK.value();
        // Refresh token
        MockHttpServletResponse resp2 = RestRefreshToken(mockMvc, refresh);
        assert resp.getStatus() == HttpStatus.OK.value();
        log.info("resp2.getContentAsString() =");
        log.info(resp2.getContentAsString());
        String newToken = (String) new ObjectMapper().readValue(resp2.getContentAsString(), Map.class).get("access");
        log.info("newToken =");
        log.info(newToken);
        // Test access
        MockHttpServletResponse resp3 = RestGetUrl(mockMvc, "/accounts/profile", newToken);
        assert resp3.getStatus() == HttpStatus.OK.value();
    }

    @Test
    public void testPasswordChange_3() throws Exception {
        if (id == null)
            id = createUser(email, password, firstName, lastName);

        // Fail
        MockHttpServletResponse r = null;
        int unAuthFail = RestChangePassword(password, changedPassword, "");
        assert unAuthFail != HttpStatus.OK.value();
        // Fail login
        r = RestUserLogin(mockMvc, email, changedPassword);
        assert r.getStatus() != HttpStatus.OK.value();

        // Fail
        r = RestUserLogin(mockMvc, email, password);
        Map<String, String> jwt = new ObjectMapper().readValue(r.getContentAsString(), Map.class);
        String token = jwt.get("access");
        int wrongPasswordFail = RestChangePassword("other", changedPassword, token);
        assert wrongPasswordFail != HttpStatus.OK.value();
        // Fail login
        r = RestUserLogin(mockMvc, email, changedPassword);
        assert r.getStatus() != HttpStatus.OK.value();

        // Succeed
        int success = RestChangePassword(password, changedPassword, token);
        assert success == HttpStatus.OK.value();
        // Login with new password
        r = RestUserLogin(mockMvc, email, changedPassword);
        assert r.getStatus() == HttpStatus.OK.value();
        password = changedPassword;
    }

    @Test
    public void testPasswordReset_4() throws Exception {
        if (id == null)
            id = createUser(email, password, firstName, lastName);
        MockHttpServletResponse r = null;
        int resetStatus = RestResetPassword(email);
        assert resetStatus == HttpStatus.OK.value();
        EmailVerification ev = emailVerificationRepository.findByEmail(email);
        assert RestResetSetNewPassword(ev.id, resetPassword) == HttpStatus.OK.value();

        // Fail login with old password
        r = RestUserLogin(mockMvc, email, password);
        assert r.getStatus() != HttpStatus.OK.value();

        // Succeed login with new password
        r = RestUserLogin(mockMvc, email, resetPassword);
        assert r.getStatus() == HttpStatus.OK.value();
        password = resetPassword;
    }

    @Test
    public void testPhoneVerify_5() throws Exception {
        if (id == null)
            id = createUser(email, password, firstName, lastName);
        Map<String, String> jwt = loginUser(email, password);
        token = jwt.get("access");
        /* Test 1: user attempts to verify */
        /*  1) Create new phone and token   */
        PhoneToken pt = createNewPhone(phone);
        /*  2) Verify token  */
        verifyNewPhone(pt);
        pt = phoneTokenRepository.findByPhoneInfo(pt.getPhoneInfo()).get(0);
        assert pt.getPhoneInfo().isVerified();
        /* Test 2: user didn't receive token and re-tries */
        /*  3) Un-verify phone  */
        pt.getPhoneInfo().setVerified(false);
        phoneInfoRepository.save(pt.getPhoneInfo());
        /*  4) New token  */
        pt = createNewPhoneToken(pt.getPhoneInfo().getId());
        /*  5) Verify token  */
        verifyNewPhone(pt);
        pt = phoneTokenRepository.findByPhoneInfo(pt.getPhoneInfo()).get(0);
        assert pt.getPhoneInfo().isVerified();
    }

    @Test
    public void testStripePayments_6() throws Exception {
        // Make sure at least one plan is registered in the Stripe dashboard

        if (id == null)
            id = createUser(email, password, firstName, lastName);
        Map<String, String> jwt = loginUser(email, password);
        token = (String) jwt.get("access");

        // List of plans from Stripe
        Map<String, Object> p = listPlans();
        List<Object> listOfStripePlans = (List) p.get("plans");
        Map selectedPlan = (Map) listOfStripePlans.get(0);
        String selectedPlanId = (String) selectedPlan.get("id");
        assert listOfStripePlans.size() > 0;

        // Process a stripe token (front-end submits that) to
        // create a com.we.auth.models.Customer object for a user
        Customer c = createCustomer(stripeTokenForTesting, token);

        // Existing charges
        List<Object> lcBefore = listCharges(c.getId());

        // Subscribe + make first charge
        Subscription s = subscribe(c.getId(), selectedPlanId);

        // Charges after a charge was made
        List<Object> lc = listCharges(c.getId());
        Object chargeObject = lc.get(lc.size() - 1);
        String customerIdFromStripeChargeObject = (String) PropertyUtils.getProperty(chargeObject, "customer");
        Integer amountFromStripeChargeObject = (Integer) PropertyUtils.getProperty(chargeObject, "amount");
        Integer amountFromStripePlanObject = (Integer) selectedPlan.get("amount");

        // Test charge and subscription
        assert lc.size() == lcBefore.size() + 1;
        assert customerIdFromStripeChargeObject.equals(c.getExternalId());
        assert (int)amountFromStripeChargeObject == (int)amountFromStripePlanObject;
        assert !s.isCancelled();
        assert s.isSubscribed();
        Map<String, String> newLogin = loginUser(email, password);
        Claims claims = (Claims) Jwts.parser().setSigningKey(signingKey).parse(newLogin.get("access")).getBody();
        assert claims.get("subExists", Boolean.class);
        assert claims.get("subPlan").equals(selectedPlanId);
        assert claims.get("subEnd", Long.class) > 0;

        // Cancel subscription
        s = cancelSubscription(s.getId());

        // Test: (subscription is cancelled) + (subscription still active)
        com.stripe.model.Subscription stripeObject = com.stripe.model.Subscription.retrieve(s.getExternalId());
        assert stripeObject.getStatus().equals("canceled");
        assert s.getCurrentPeriodEnd().getTime() == stripeObject.getCurrentPeriodEnd().longValue()*1000;
        assert s.isCancelled();
        assert s.isSubscribed();
        newLogin = loginUser(email, password);
        claims = (Claims) Jwts.parser().setSigningKey(signingKey).parse(newLogin.get("access")).getBody();
        assert claims.get("subExists", Boolean.class);

        // Query Stripe for value of currentPeriodEnd: object should not be altered
        Subscription sNew = subscriptionQuery(s.getId());

        assert s.getExternalId().equals(sNew.getExternalId());
        assert s.getStart().getTime() == sNew.getStart().getTime();
        assert s.getCurrentPeriodStart().getTime() == sNew.getCurrentPeriodStart().getTime();
        assert s.getCurrentPeriodEnd().getTime() == sNew.getCurrentPeriodEnd().getTime();
        assert s.isCancelled() == sNew.isCancelled();
        assert s.isSubscribed() == sNew.isSubscribed();
    }

    @Test
    public void testCorsConfig_7() throws Exception {
        /*
            Send OPTIONS request => Response should include Access-Control-Allow-Origin

            curl -XOPTIONS -H "Access-Control-Request-Method: GET" \
                -H "Origin: http://localhost" https://localhost:8080/actuator/health
         */
        String path = "/actuator/health";
        String frontEndOrigin = "https://www.random-oauth2-client.com";
        String headerAllowOrigin = "Access-Control-Allow-Origin";
        RequestBuilder rb = options(path)
                .header("Origin", frontEndOrigin)
                .header("Access-Control-Request-Method", "GET");
        MockHttpServletResponse r = mockMvc.perform(rb)
                .andDo(httpPrinter("GET", path)).andReturn().getResponse();
        log.info(String.format("testCorsConfig() -> %s = %s", headerAllowOrigin, r.getHeader(headerAllowOrigin)));
        assert r.getStatus() == HttpStatus.OK.value();
        assert r.getHeader(headerAllowOrigin).equals(frontEndOrigin);
    }
}