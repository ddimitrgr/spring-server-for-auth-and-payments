package com.we.auth.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

@Service
public class MailContentBuilder {

    public static final int FROM_REGITRATION = 0;
    public static final int FROM_PASSWORD_RESET = 1;

    TemplateEngine templateEngine;

    @Autowired
    public MailContentBuilder(TemplateEngine templateEngine) {
        this.templateEngine = templateEngine;
    }

    @Value("${registration.verify.template}")
    String template;

    @Value("${logoFileUrl}")
    String logoFileUrl;

    @Value("${registration.verify.message}")
    String message;

    @Value("${registration.verify.suggestion}")
    String suggestion;

    @Value("${registration.verify.action}")
    String action;

    @Value("${registration.verify.header}")
    String header;

    @Value("${company.name}")
    String companyName;

    /*
        Password Reset parameters
     */
    @Value("${password.reset.message}")
    String passwordResetMessage;

    @Value("${password.reset.suggestion}")
    String passwordResetSuggestion;

    @Value("${password.reset.action}")
    String passwordResetAction;

    @Value("${password.reset.header}")
    String passwordResetHeader;

    public String build(String firstName, String link, int processId) {
        Context context = new Context();
        context.setVariable("firstName", firstName);
        context.setVariable("link", link);
        context.setVariable("logoFileUrl", this.logoFileUrl);
        context.setVariable("companyName", this.companyName);
        if (processId == MailContentBuilder.FROM_REGITRATION) {
            context.setVariable("header", this.header);
            context.setVariable("message", this.message);
            context.setVariable("suggestion", this.suggestion);
            context.setVariable("action", this.action);
        }
        if (processId == MailContentBuilder.FROM_PASSWORD_RESET) {
            context.setVariable("header", this.passwordResetHeader);
            context.setVariable("message", this.passwordResetMessage);
            context.setVariable("suggestion", this.passwordResetSuggestion);
            context.setVariable("action", this.passwordResetAction);
        }
        return templateEngine.process(this.template, context);
    }
}
