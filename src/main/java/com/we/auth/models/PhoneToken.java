package com.we.auth.models;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;

import javax.validation.constraints.NotNull;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;
import java.util.UUID;

@Document(collection="phoneToken")
@Accessors(chain = true) @Getter @Setter @NoArgsConstructor
public class PhoneToken {

    static int MaxTrials = 5;
    static String Random() {
        Random rnd = new Random();
        int n = 100000 + rnd.nextInt(900000);
        return new Long(n).toString();
    }

    @Id String id = UUID.randomUUID().toString();
    String token = Random();
    @DBRef PhoneInfo phoneInfo;
    @NotNull Date createdAt;
    @NotNull Date expiredAt;
    Date verifiedAt;
    int trials = 0;

    public PhoneToken(PhoneInfo pi, int expirationSlack) {
        Calendar now = Calendar.getInstance();
        Calendar exp = Calendar.getInstance();
        exp.add(Calendar.SECOND, expirationSlack);
        setPhoneInfo(pi).setCreatedAt(now.getTime()).setExpiredAt(exp.getTime());
    }

    public boolean belongsTo(User user) { return phoneInfo.belongsTo(user); }

    public boolean isMatch(String code) { return getToken().equals(code); }

    public boolean authenticate(User user, String code, int expirationSlack) {
        return isMatch(code) && !isExpired(expirationSlack) && belongsTo(user);
    }

    public boolean isExpired(int slack) {
        Calendar cat = Calendar.getInstance();
        cat.setTime(getCreatedAt());
        cat.add(Calendar.SECOND, slack);
        setTrials(1+getTrials());
        return getExpiredAt().before(cat.getTime())
                && 1 + getTrials() < MaxTrials;
    }
}
