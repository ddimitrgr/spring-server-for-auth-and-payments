package com.we.auth.controllers;

import com.we.auth.AuthApplication;
import com.we.auth.events.OnPasswordResetEvent;
import com.we.auth.events.OnRegistrationEvent;
import com.we.auth.models.*;
import com.we.auth.repos.*;
import com.we.auth.services.OurUserDetailsService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.validation.constraints.AssertTrue;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import java.security.Principal;
import java.util.*;
import java.util.logging.Logger;


@RestController
@RequestMapping("/accounts")
public class AuthController {

    static final Logger log = Logger.getLogger(AuthApplication.class.getName());

    @Value("${access.token.duration}") int accessTokenDuration;
    @Value("${refresh.token.duration}") int refreshTokenDuration;
    @Value("${our.secret.signing.key}") String signingKey;

    @Autowired BCryptPasswordEncoder bCryptPasswordEncoder;
    @Autowired OurUserDetailsService userService;
    @Autowired UserRepository userRepository;
    @Autowired RoleRepository roleRepository;
    @Autowired ApplicationEventPublisher eventPublisher;
    @Autowired EmailVerificationRepository emailVerificationRepository;
    @Autowired SubscriptionRepository subscriptionRepository;
    @Autowired PhoneInfoRepository phoneInfoRepository;
    @Autowired PhoneTokenRepository phoneTokenRepository;
    @Autowired CustomerRepository customerRepository;

    @RequestMapping(value = "profile", method= RequestMethod.GET)
    public ResponseEntity<?> profile(@AuthenticationPrincipal ExtendedUser user) {
        Map<String, List> m = new HashMap<>();
        List<Customer> lcu = customerRepository.findByUser(user);
        List<PhoneInfo> lpi = phoneInfoRepository.findByUser(user);
        List<PhoneToken> lpt = phoneTokenRepository.findByPhoneInfoIn(lpi);
        m.put("credit_cards", lcu);
        m.put("phone_numbers", lpi);
        m.put("phone_tokens", lpt);
        return new ResponseEntity<>(m, HttpStatus.OK);
    }

    @RequestMapping(value = "session", method= RequestMethod.GET)
    public ResponseEntity<ExtendedUser> session(
            @AuthenticationPrincipal org.springframework.security.core.userdetails.User user,
            HttpServletRequest r,
            HttpSession s,
            Principal p)
    {
        SecurityContext sc = SecurityContextHolder.getContext();
        if (user != null) {
            User u = userRepository.findByEmail(user.getUsername());
            ExtendedUser eu = new ExtendedUser();
            BeanUtils.copyProperties(u, eu);
            List<Subscription> ls = subscriptionRepository.findByUser(u);
            Optional<Subscription> os = ls.stream().filter(x -> x.isActive()).findFirst();
            eu.setSubscribed(os.isPresent() && os.get().isSubscribed());
            if (os.isPresent())
                eu.setSubscriptionEnd(os.get().getCurrentPeriodEnd());
            return new ResponseEntity<>(eu, HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    @RequestMapping(value = "password/change", method= RequestMethod.POST)
    public ResponseEntity<?> passwordChange(@AuthenticationPrincipal User user,
                                            @RequestBody PasswordChange change)
    {
        // Password change by authenticated user
        Optional<User> ou = userRepository.findById(user.getId());
        boolean isMatch = bCryptPasswordEncoder.matches(change.oldPassword, ou.get().getPassword());
        if (isMatch) {
            ou.get().setPassword(bCryptPasswordEncoder.encode(change.password));
            userRepository.save(ou.get());
            return new ResponseEntity<>(null, HttpStatus.OK);
        }
        return new ResponseEntity<>(null, HttpStatus.NOT_FOUND);
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////

    @RequestMapping(value = "register", method= RequestMethod.POST)
    public ResponseEntity<User> register(@RequestBody UserRegister userRegister)
            throws EmailAlreadyExistsException, TermsOfServiceNotAcceptedException {
        User userFromDb = userService.findUserByEmail(userRegister.email);
        if (userFromDb != null)
            throw new EmailAlreadyExistsException();
        if (!userRegister.acceptTermsOfService)
            throw new TermsOfServiceNotAcceptedException();

        HashSet<Role> roles = new HashSet<>();
        Role userRole = roleRepository.findByRole("USER");
        roles.add(userRole);
        userFromDb = new User();
        userFromDb.setEmail(userRegister.email);
        userFromDb.setPassword(userRegister.password);
        userFromDb.setFirstName(userRegister.firstName);
        userFromDb.setLastName(userRegister.lastName);
        userFromDb.setRoles(roles);
        eventPublisher.publishEvent(new OnRegistrationEvent(userFromDb));
        userService.saveUser(userFromDb);
        return new ResponseEntity<>(userFromDb, HttpStatus.CREATED);
    }

    @RequestMapping(value = "email/verify/{id}/{token}", method= RequestMethod.GET)
    public ResponseEntity<?> emailVerify(@PathVariable("id") String id, @PathVariable("token") String token) {
        Optional<EmailVerification> evo = emailVerificationRepository.findById(token);
        if (!evo.isPresent())
            return new ResponseEntity<>(null, HttpStatus.NOT_FOUND);
        EmailVerification ev = evo.get();
        Date now = new Date();
        if (ev.expiration.before(now)) {
            emailVerificationRepository.delete(ev);
            return new ResponseEntity<>(null, HttpStatus.FORBIDDEN);
        }
        User u = userService.findUserByEmail(ev.email);
        if (u == null || !u.getId().equals(id))
            return new ResponseEntity<>(null, HttpStatus.NOT_FOUND);
        u.setEmailVerified(true);
        if (!u.isSuspended())
            u.setActive(true);
        this.userRepository.save(u);
        return new ResponseEntity<>(null, HttpStatus.OK);
    }

    @RequestMapping(value = "/login", method = RequestMethod.POST)
    public ResponseEntity<Map<String, String>> login(@RequestBody UserLogin userLogin) throws ServletException {
        log.info(String.format("POST /accounts/login body = %s - %s", userLogin.email, userLogin.password));
        if (userLogin.email == null || userLogin.password == null)
            throw new ServletException("Please fill in username and password");
        User user = userService.findUserByEmail(userLogin.email);
        if (user == null)
            throw new ServletException("User email not found.");
        String storedPasswordHash = user.getPassword();
        if (!bCryptPasswordEncoder.matches(userLogin.password, storedPasswordHash))
            return new ResponseEntity<>(new HashMap<>(), HttpStatus.UNAUTHORIZED);
        Optional<Subscription> oSub = subscriptionRepository.findLastSubForUser(user);
        Calendar accessExp = Calendar.getInstance();
        Calendar refreshExp = Calendar.getInstance();
        accessExp.add(Calendar.SECOND, accessTokenDuration);
        refreshExp.add(Calendar.SECOND, refreshTokenDuration);
        Map<String, String> resp = new HashMap<>();
        JwtBuilder builder = Jwts.builder().setSubject(user.getId())
                .claim("roles", "USER")
                .claim("email", userLogin.email)
                .claim("id", user.getId())
                .claim("fun", "access");
        if (oSub.isPresent())
            builder = builder.claim("subPlan", oSub.get().getPlan())
                    .claim("subExists", oSub.get().isSubscribed())
                    .claim("subEnd", oSub.get().getCurrentPeriodEnd().getTime());
        else
            builder = builder.claim("subExists", false);
        String access = builder.setIssuedAt(new Date())
                .setExpiration(accessExp.getTime())
                .signWith(SignatureAlgorithm.HS256, signingKey).compact();
        String refresh = Jwts.builder().setSubject(user.getId())
                .claim("roles", "USER")
                .claim("email", userLogin.email)
                .claim("id", user.getId())
                .claim("fun", "refresh")
                .setIssuedAt(new Date())
                .setExpiration(refreshExp.getTime())
                .signWith(SignatureAlgorithm.HS256, signingKey).compact();
        resp.put("access", access);
        resp.put("refresh", refresh);
        return new ResponseEntity<>(resp, HttpStatus.OK);
    }

    @RequestMapping(value = "/token/refresh/{token}", method = RequestMethod.POST)
    public Map<String, String> tokenRefresh(@PathVariable("token") String token) throws ServletException {
        log.info("tokenRefresh() enter");
        final Claims claims = (Claims) Jwts.parser().setSigningKey(signingKey).parse(token).getBody();
        long now = Calendar.getInstance().getTime().getTime()/1000;
        long exp = new Long((int) claims.get("exp"));
        log.info(String.format("tokenRefresh() exp / now / fun = %d / %d / %s", exp, now, claims.get("fun")));
        if (claims.get("fun").equals("refresh") && (exp >= now)) {
            String email = (String) claims.get("email");
            String id = (String) claims.get("id");
            log.info("tokenRefresh() preparing token !");
            JwtBuilder builder = Jwts.builder().setSubject(id)
                    .claim("roles", "USER")
                    .claim("email", email)
                    .claim("id", id)
                    .claim("fun", "access");
            User u = new User();
            u.setId(id);
            Optional<Subscription> oSub = subscriptionRepository.findLastSubForUser(u);
            if (oSub.isPresent())
                builder = builder.claim("subPlan", oSub.get().getPlan())
                        .claim("subExists", oSub.get().isSubscribed())
                        .claim("subEnd", oSub.get().getCurrentPeriodEnd().getTime());
            else
                builder = builder.claim("subExists", false);
            Calendar accessExp = Calendar.getInstance();
            accessExp.add(Calendar.SECOND, accessTokenDuration);
            String access = builder
                    .setIssuedAt(new Date())
                    .setExpiration(accessExp.getTime())
                    .signWith(SignatureAlgorithm.HS256, signingKey).compact();
            Map<String, String> r = new HashMap<>();
            r.put("access", access);
            log.info("tokenRefresh() returning token !");
            return r;
        }
        throw new AccessDeniedException("403");
    }

    @RequestMapping(value = "password/reset", method= RequestMethod.POST)
    public ResponseEntity<?> passwordReset(@RequestBody PasswordReset passwordReset)
    {
        User userFromDb = this.userService.findUserByEmail(passwordReset.email);
        if (userFromDb != null) {
            eventPublisher.publishEvent(new OnPasswordResetEvent(userFromDb));
        }
        return new ResponseEntity<>(HttpStatus.OK);
    }

    @RequestMapping(value = "password/reset/new/{link}", method= RequestMethod.POST)
    public ResponseEntity<?> passwordResetSubmitNew(
            @PathVariable("link") String link,
            @RequestBody PasswordResetNew passwordResetNew)
    {
        Optional<EmailVerification> evo = emailVerificationRepository.findById(link);
        if (!evo.isPresent())
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        EmailVerification ev = evo.get();
        Date now = new Date();
        if (ev.expiration.before(now)) {
            emailVerificationRepository.delete(ev);
            return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        }
        User u = userService.findUserByEmail(ev.email);
        if (u == null)
            return new ResponseEntity<>(null, HttpStatus.NOT_FOUND);
        u.setPassword(this.bCryptPasswordEncoder.encode(passwordResetNew.password));
        this.userRepository.save(u);
        return new ResponseEntity<>(HttpStatus.OK);
    }

    @RequestMapping(value = "/test/auth", method = RequestMethod.GET)
    public ResponseEntity<Void> testAuth() {
        return new ResponseEntity<>(HttpStatus.OK);
    }

    ////////////////////////////////////////////////////////////////////////////////////////////

    public static class PasswordChange {
        @NotBlank(message = "Required")
        public String password;
        @NotBlank(message = "Required")
        public String oldPassword;
    }

    public static class PasswordReset {
        @NotBlank(message = "Required")
        @Email(message = "Enter a valid email address")
        public String email;
    }

    public static class PasswordResetNew {
        @NotBlank(message = "Required")
        public String password;
    }

    public static class UserLogin {
        @NotBlank(message = "Required")
        @Email(message = "Enter a valid email address")
        public String email;
        @NotBlank(message = "Required")
        public String password;
    }

    public static class UserRegister {
        @NotBlank(message = "Required")
        public String firstName;
        @NotBlank(message = "Required")
        public String lastName;
        @NotBlank(message = "Required")
        @Email(message = "Enter a valid email address")
        public String email;
        @NotBlank(message = "Required")
        public String password;
        @AssertTrue(message = "Must accept")
        public boolean acceptTermsOfService;
    }

    public static class EmailAlreadyExistsException extends Throwable {
        String message = "This email already exists !";
        public String getMessage() {
            return message;
        }
        public void setMessage(String message) {
            this.message = message;
        }
    }

    public static class TermsOfServiceNotAcceptedException extends Throwable {
        String message = "You must accept the terms of service !";
        public String getMessage() {
            return message;
        }
        public void setMessage(String message) {
            this.message = message;
        }
    }
}
