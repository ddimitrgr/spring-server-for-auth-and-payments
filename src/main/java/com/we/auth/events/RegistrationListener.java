package com.we.auth.events;

import com.we.auth.models.EmailVerification;
import com.we.auth.models.User;
import com.we.auth.repos.EmailVerificationRepository;
import com.we.auth.services.MailContentBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationListener;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.mail.javamail.MimeMessagePreparator;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.UUID;
import java.util.logging.Logger;

@Component
public class RegistrationListener
        implements ApplicationListener<OnRegistrationEvent>
{
    static final Logger log = Logger.getLogger(RegistrationListener.class.getName());

    @Value("${registration.email.sender}") String messageSender;
    @Value("${registration.email.subject}") String messageSubject;
    @Value("${spa.url}") String spaUrl;
    @Value("${spa.paths.email.verification}") String spaEmailVerificationPath;
    @Value("${verification.email.expiration.minutes}") int verificationExpInMin;

    @Autowired EmailVerificationRepository emailVerificationRepository;
    @Autowired MailContentBuilder mailContentBuilder;
    @Autowired JavaMailSender mailSender;

    @Override
    public void onApplicationEvent(OnRegistrationEvent event) {
        User user = event.user;
        UUID token = UUID.randomUUID();
        EmailVerification ev = new EmailVerification();
        ev.email = event.user.getEmail();
        ev.id = token.toString();
        ev.expiration = new Date();
        long MINUTE = 60000;
        ev.expiration = new Date(ev.expiration.getTime() + verificationExpInMin*MINUTE);
        emailVerificationRepository.save(ev);
        String confirmLink = this.spaUrl + this.spaEmailVerificationPath + "/" + token.toString();
        log.info("confirmRegistration() -> "+confirmLink);
        log.info("confirmRegistration() -> preparing mail");
        MimeMessagePreparator messagePreparator = mimeMessage -> {
            MimeMessageHelper messageHelper = new MimeMessageHelper(mimeMessage);
            messageHelper.setFrom(this.messageSender);
            messageHelper.setTo(user.getEmail());
            messageHelper.setSubject(this.messageSubject);
            messageHelper.setText(
                    this.mailContentBuilder.build(user.getFirstName(), confirmLink, MailContentBuilder.FROM_REGITRATION),
                    true);
        };
        this.mailSender.send(messagePreparator);
        log.info("confirmRegistration() -> mail sent");
    }
}


