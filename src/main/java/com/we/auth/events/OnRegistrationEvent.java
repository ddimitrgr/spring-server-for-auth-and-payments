package com.we.auth.events;
import com.we.auth.models.User;
import org.springframework.context.ApplicationEvent;

public class OnRegistrationEvent extends ApplicationEvent {
    public User user;
    public OnRegistrationEvent(User user) {
        super(user);
        this.user = user;
    }
}

