package com.cydeo.config;

import com.cydeo.service.SecurityService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
public class SecurityConfig {

    private final SecurityService securityService;

    public SecurityConfig(SecurityService securityService) {
        this.securityService = securityService;
    }
//    @Bean
//    public UserDetailsService userDetailsService(PasswordEncoder encoder) {
//
//        List<UserDetails> users = new ArrayList<>();
//        users.add(new User("mike", encoder.encode("password"),
//                List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))));
//        users.add(new User("ozzy", encoder.encode("password"),
//                List.of(new SimpleGrantedAuthority("ROLE_MANAGER"))));
//
//        return new InMemoryUserDetailsManager(users);
//
//    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        return http
                .authorizeRequests()
                    .antMatchers("/user/**").hasAuthority("Admin")
                    .antMatchers("/project/**").hasAuthority("Manager")
                    .antMatchers("/task/employee/**").hasAuthority("Employee")
                    .antMatchers("/task/**").hasAuthority("Manager")
//                .antMatchers("/task/**").hasAnyAuthority("ROLE_EMPLOYEE", "ROLE_ADMIN")
//                .antMatchers("/task/**").hasAnyRole("EMPLOYEE", "ADMIN")
                .antMatchers(
                        "/",
                        "/login",
                        "/fragments/**",
                        "/assets/**",
                        "/images/**"
                ).permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                    .loginPage("/login")
                    .defaultSuccessUrl("/welcome")
                    .failureUrl("/login?error=true")
                .permitAll()
                .and()
                .logout()
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                    .logoutSuccessUrl("/login")
                .and()
                .rememberMe()
                    .tokenValiditySeconds(120)
                    .key("key")
                    .userDetailsService(this.securityService)
                .and()
                .build();
    }

}
