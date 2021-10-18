package com.we.auth.services;

import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.logging.Logger;

@Service
public class TwilioService {

    @Value("${twilio.account}") String account;
    @Value("${twilio.token}") String token;
    @Value("${twilio.messagingServiceSid}") String messagingServiceSid;
    @Value("${twilio.mlSid}") String mlSid;
    @Value("${twilio.service.phoneNumber}") String phoneNumber;
    @Value("${twilio.testUser.phoneNumber}") String testPhoneNumber;

    Logger log;

    public TwilioService() {
        log = Logger.getLogger(TwilioService.class.getName());
    }

    public void sendSms(String to, String message) {
        log.info("Using programmable service with id "+messagingServiceSid);
        log.info("Messaging "+to);
        Twilio.init(account, token);
        PhoneNumber toPn = new com.twilio.type.PhoneNumber(to);
        Message m = Message.creator(toPn, messagingServiceSid, message).create();
        log.info(m.getSid());
    }
}
