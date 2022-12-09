package ru.deevdenis.client.controllers;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

@RestController
@RequiredArgsConstructor
public class ClientController {

    @Autowired
    private WebClient webClient;

    @GetMapping("/messages")
    public String getMessages(
            @RegisteredOAuth2AuthorizedClient("messages-client-authorization-code") OAuth2AuthorizedClient authorizedClient)
    {
        String result = webClient.get()
                .uri("http://localhost:8082/messages")
                .attributes(ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
                .retrieve()
                .bodyToMono(String.class)
                .block();

        System.out.println(result);

        return result;
    }

    @GetMapping("/registration")
    public String getRegistration() {
        return "registration";
    }
}
