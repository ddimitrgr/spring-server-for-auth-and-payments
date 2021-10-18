package com.we.auth.configurations;

import com.we.auth.JwtAuthFilter;
import com.we.auth.JwtAuthProvider;
import com.we.auth.SessionFilter;
import com.we.auth.services.OurUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.session.data.mongo.config.annotation.web.http.EnableMongoHttpSession;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableMongoHttpSession
@EnableWebSecurity
public class JwtSecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${our.secret.signing.key}") public String signingKey;
    @Value("${session.cookie.duration.days}") public int sessionExpInDays;

    @Bean
    public CookieSerializer cookieSerializer() {
        DefaultCookieSerializer serializer = new DefaultCookieSerializer();
        serializer.setCookieName("JSESSIONID");
        serializer.setCookieMaxAge(60 * 60 * 24 * sessionExpInDays);
        return serializer;
    }

    @Autowired BCryptPasswordEncoder bCryptPasswordEncoder;
    @Autowired OurUserDetailsService ourUserDetailsService;
    @Autowired JwtAuthProvider jwtAuthProvider;
    @Autowired JwtAuthFilter jwtAuthFilter;
    @Autowired SessionFilter sessionFilter;

    @Override @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // Allow anyone and anything access.
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.addAllowedOrigin("*");
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
                .antMatchers("/resources/**", "/static/**", "/css/**", "/js/**", "/images/**");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .authenticationProvider(jwtAuthProvider)
                .userDetailsService(ourUserDetailsService)
                .passwordEncoder(bCryptPasswordEncoder);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.addFilterAfter(jwtAuthFilter, LogoutFilter.class)
                .cors()
                .and()
                .authorizeRequests()

                // Public
                .antMatchers("/actuator/health").permitAll()
                .antMatchers("/accounts/register").permitAll()
                .antMatchers("/accounts/password/reset").permitAll()
                .antMatchers("/accounts/password/reset/**").permitAll()
                .antMatchers("/accounts/email/verify/**").permitAll()
                .antMatchers("/accounts/token/refresh/**").permitAll()
                .antMatchers("/accounts/login").permitAll()
                .antMatchers("/payments/plans").permitAll()

                // User
                .anyRequest().authenticated()

                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
                .and()
                .csrf().disable().httpBasic().disable();
    }
}
