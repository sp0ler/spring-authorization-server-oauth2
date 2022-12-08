package ru.deevdenis.authserver.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.stereotype.Component;
import ru.deevdenis.authserver.entities.User;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

@Component
public class UserAuthConverter implements AuthenticationConverter {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override
    @Nullable
    public Authentication convert(HttpServletRequest request) {
        User user;

        try {
            user = MAPPER.readValue(request.getInputStream(), User.class);
        } catch (IOException e) {
            return null;
        }

        return UsernamePasswordAuthenticationToken.unauthenticated(user.getLogin(), user.getPassword());
    }
}
