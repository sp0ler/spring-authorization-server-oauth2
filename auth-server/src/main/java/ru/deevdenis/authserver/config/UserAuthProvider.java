package ru.deevdenis.authserver.config;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.Nullable;
import org.springframework.orm.jpa.EntityManagerFactoryInfo;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;
import ru.deevdenis.authserver.entities.AuthUser;
import ru.deevdenis.authserver.repositories.UserRepository;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.sql.DataSource;
import java.io.Serializable;
import java.nio.CharBuffer;
import java.util.Collections;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class UserAuthProvider implements AuthenticationProvider, Serializable {

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;


    @Override
    @Nullable
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String login = authentication.getName();
        String secret = authentication.getCredentials().toString();

        RegisteredClient client = registeredClientRepository.findByClientId(login);

        if (client == null) return null;

        if (passwordEncoder.matches(CharBuffer.wrap(secret), client.getClientSecret())) {
            return UsernamePasswordAuthenticationToken.authenticated(login, secret, Collections.emptyList());
        }

        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.equals(authentication);
    }
}
