package com.we.auth.controllers;

import com.we.auth.models.ExtendedUser;
import com.we.auth.models.PhoneInfo;
import com.we.auth.models.PhoneToken;
import com.we.auth.models.User;
import com.we.auth.repos.PhoneInfoRepository;
import com.we.auth.repos.PhoneTokenRepository;
import com.we.auth.repos.UserRepository;
import com.we.auth.services.TwilioService;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import javax.validation.constraints.NotBlank;
import java.text.MessageFormat;
import java.util.List;
import java.util.Optional;

@RestController @RequestMapping("/validation")
public class PhoneController {

    @Autowired TwilioService twilioService;
    @Autowired UserRepository userRepository;
    @Autowired PhoneInfoRepository phoneInfoRepository;
    @Autowired PhoneTokenRepository phoneTokenRepository;

    @Value("${phonetoken.expiration}") int expirationSlack;

    @Value("${twilio.smsTemplate}")
    String smsTemplate;

    @RequestMapping(value = "phone", method= RequestMethod.POST)
    public ResponseEntity<PhoneToken> newPhone(
            @RequestBody NewPhoneInfo npi,
            @AuthenticationPrincipal ExtendedUser user)
    {
        PhoneInfo pi = new PhoneInfo();
        BeanUtils.copyProperties(npi, pi);
        User u = new User();
        u.setId(user.getId());
        phoneInfoRepository.save(pi.setUser(u));
        PhoneToken pt = new PhoneToken(pi, expirationSlack);
        phoneTokenRepository.save(pt);
        // SEND SMS HERE
        String smsCode = pt.getToken();
        String sms = MessageFormat.format(smsTemplate, new String[] {smsCode});
        twilioService.sendSms(pi.getPhoneNumber(), sms);
        pt.setToken(null);
        return new ResponseEntity<>(pt, HttpStatus.CREATED);
    }

    @RequestMapping(value = "phone/token/create/{phoneId}", method= RequestMethod.POST)
    public ResponseEntity<?> newToken(
            @PathVariable("phoneId") String phoneId,
            @AuthenticationPrincipal ExtendedUser user)
    {
        Optional<PhoneInfo> opi = phoneInfoRepository.findById(phoneId);
        if (!opi.isPresent())
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        if (!opi.get().getUser().getId().equals(user.getId()))
            return new ResponseEntity<>(HttpStatus.FORBIDDEN);

        PhoneToken pt = new PhoneToken(opi.get(), expirationSlack);
        phoneTokenRepository.save(pt);
        String smsCode = pt.getToken();
        String sms = MessageFormat.format(smsTemplate, new String[] {smsCode});
        twilioService.sendSms(opi.get().getPhoneNumber(), sms);
        pt.setToken(null);
        return new ResponseEntity<>(pt, HttpStatus.CREATED);
    }

    @RequestMapping(value = "phone/token/verify", method= RequestMethod.POST)
    public ResponseEntity<?> phoneTokenVerify(
            @RequestBody ExternalPhoneToken ept,
            @AuthenticationPrincipal ExtendedUser user)
    {
        PhoneToken pt = phoneTokenRepository.findById(ept.getId()).get();
        if (pt.authenticate(user, ept.getCode(), expirationSlack)) {
            phoneInfoRepository.save(pt.getPhoneInfo().setVerified(true));
            return new ResponseEntity<>(HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.FORBIDDEN);
    }

    @RequestMapping(value = "phone", method= RequestMethod.GET)
    public ResponseEntity<List<PhoneInfo>> list(
            @AuthenticationPrincipal ExtendedUser user)
    {
        if (user == null)
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        User u = userRepository.findByEmail(user.getUsername());
        List<PhoneInfo> pil = phoneInfoRepository.findByUser(u);
        return new ResponseEntity<>(pil, HttpStatus.OK);
    }

    @RequestMapping(value = "phone/{id}", method = RequestMethod.DELETE)
    public ResponseEntity<?> deletePhoneInfo(
            @PathVariable("id") PhoneInfo pi,
            @AuthenticationPrincipal ExtendedUser user)
    {
        if (user == null)
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        User u = userRepository.findByEmail(user.getUsername());
        if (pi == null)
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        if (!pi.belongsTo(u))
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);

        List<PhoneToken> lpt = phoneTokenRepository.findByPhoneInfo(pi);
        phoneTokenRepository.deleteAll(lpt);
        phoneInfoRepository.delete(pi);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    ////////////////////////////////////////////////////////////////////////////////////////////

    @Accessors(chain = true) @Getter @Setter @NoArgsConstructor
    static public class NewPhoneInfo {
        @NotBlank(message = "Required")
        String phoneNumber;
    }

    @Accessors(chain = true) @Getter @Setter @NoArgsConstructor
    static public class ExternalPhoneToken {
        @NotBlank(message = "Required")
        String id;
        @NotBlank(message = "Required")
        String code;
    }
}
