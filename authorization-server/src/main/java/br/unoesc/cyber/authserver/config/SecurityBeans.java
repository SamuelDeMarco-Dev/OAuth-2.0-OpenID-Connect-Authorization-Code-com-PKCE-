package br.unoesc.cyber.authserver.config;

import java.security.SecureRandom;
import java.time.Clock;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
class SecurityBeans {

    /** BCrypt com custo configurável; o PDF exige no mínimo 12 (§2.3). */
    @Bean
    PasswordEncoder passwordEncoder(AuthServerProperties props) {
        int cost = props.login().bcryptCost();
        if (cost < 12) {
            throw new IllegalStateException("bcrypt-cost deve ser >= 12 (PDF §2.3)");
        }
        return new BCryptPasswordEncoder(cost);
    }

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    SecureRandom secureRandom() {
        return new SecureRandom();
    }
}
