package com.we.auth.events;

import com.we.auth.models.User;
import org.springframework.context.ApplicationEvent;

public class OnPasswordResetEvent extends ApplicationEvent {
    public User user;
    public OnPasswordResetEvent(User user) {
        super(user);
        this.user = user;
    }
}
