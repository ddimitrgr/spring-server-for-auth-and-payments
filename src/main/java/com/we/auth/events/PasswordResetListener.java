package com.we.auth.events;

import com.we.auth.models.EmailVerification;
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
import java.util.List;
import java.util.UUID;
import java.util.logging.Logger;

@Component
public class PasswordResetListener
        implements ApplicationListener<OnPasswordResetEvent>
{
    static final Logger log = Logger.getLogger(PasswordResetListener.class.getName());

    @Value("${registration.email.sender}") String messageSender;
    @Value("${password.reset.email.subject}") String messageSubject;
    @Value("${spa.url}") String spaUrl;
    @Value("${spa.paths.password.reset}") String spaPasswordResetPath;
    @Value("${verification.email.expiration.minutes}") int verificationExpInMin;

    @Autowired EmailVerificationRepository emailVerificationRepository;
    @Autowired MailContentBuilder mailContentBuilder;
    @Autowired JavaMailSender mailSender;

    @Override
    public void onApplicationEvent(OnPasswordResetEvent event) {
        List<EmailVerification> evAllPast = emailVerificationRepository.findAllByEmail(event.user.getEmail());
        emailVerificationRepository.deleteAll(evAllPast);
        EmailVerification ev = new EmailVerification();
        ev.email = event.user.getEmail();
        ev.id = UUID.randomUUID().toString();
        ev.expiration = new Date();
        long MINUTE = 60000;
        ev.expiration = new Date(ev.expiration.getTime() + verificationExpInMin*MINUTE);
        emailVerificationRepository.save(ev);
        String confirmLink = this.spaUrl + this.spaPasswordResetPath + "/" + ev.id;
        log.info("confirmEmail() -> "+confirmLink);
        log.info("confirmEmail() -> preparing email message");
        MimeMessagePreparator messagePreparator = mimeMessage -> {
            MimeMessageHelper messageHelper = new MimeMessageHelper(mimeMessage);
            messageHelper.setFrom(this.messageSender);
            messageHelper.setTo(event.user.getEmail());
            messageHelper.setSubject(this.messageSubject);
            messageHelper.setText(
                    this.mailContentBuilder.build(event.user.getFirstName(), confirmLink, MailContentBuilder.FROM_PASSWORD_RESET),
                    true);
        };
        this.mailSender.send(messagePreparator);
        log.info("confirmEmail() -> mail sent");
    }
}
