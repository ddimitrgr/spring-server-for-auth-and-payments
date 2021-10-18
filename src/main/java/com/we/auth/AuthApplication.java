package com.we.auth;

import com.we.auth.models.Role;
import com.we.auth.repos.RoleRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.annotation.Bean;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.session.data.mongo.JdkMongoSessionConverter;

import java.time.Duration;
import java.util.Properties;
import java.util.logging.Logger;

@SpringBootApplication
public class AuthApplication extends SpringBootServletInitializer {

    static final Logger log = Logger.getLogger(AuthApplication.class.getName());

    @Value("${session.cookie.duration.days}") int sessionExpInDays;
    @Value("${smtp.host}") String emailHost;
    @Value("${smtp.port}") int emailPort;
    @Value("${smtp.username}") String username;
    @Value("${smtp.password}") String password;

    public static void main(String[] args) {
        new SpringApplicationBuilder(AuthApplication.class)
                .web(WebApplicationType.SERVLET).application().run(args);
    }

    @Bean
    public JdkMongoSessionConverter jdkMongoSessionConverter() {
        return new JdkMongoSessionConverter(Duration.ofDays(sessionExpInDays));
    }

    @Bean
    CommandLineRunner init(RoleRepository roleRepository) {
        return args -> {

            Role adminRole = roleRepository.findByRole("ADMIN");
            if (adminRole == null) {
                Role newAdminRole = new Role();
                newAdminRole.role = "ADMIN";
                roleRepository.save(newAdminRole);
            }

            Role userRole = roleRepository.findByRole("USER");
            if (userRole == null) {
                Role newUserRole = new Role();
                newUserRole.role = "USER";
                roleRepository.save(newUserRole);
            }
        };
    }

    @Bean
    public JavaMailSender getJavaMailSender() {
        log.info("Creating JavaMailSender !");

        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        mailSender.setHost(this.emailHost);
        mailSender.setPort(this.emailPort);
        mailSender.setUsername(this.username);
        mailSender.setPassword(this.password);

        Properties props = mailSender.getJavaMailProperties();
        props.put("mail.transport.protocol", "smtp");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");

        // Enable/disable debug output
        props.put("mail.debug", "false");
        return mailSender;
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        return bCryptPasswordEncoder;
    }
}
