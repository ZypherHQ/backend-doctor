package com.example.demo.service;

import com.example.demo.entity.UserAccount;
import com.example.demo.repository.UserRepository;
import jakarta.transaction.Transactional;
import java.net.http.HttpClient;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final RestTemplate restTemplate = new RestTemplate();
    private final WebClient webClient = WebClient.builder().baseUrl("https://example.invalid").build();

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Transactional
    public UserAccount create(String name) {
        UserAccount account = new UserAccount();
        account.setName(name);
        UserAccount saved = userRepository.save(account);
        restTemplate.getForObject("https://example.invalid/audit", String.class);
        return saved;
    }

    @Transactional
    private void privateTransaction() {
        userRepository.count();
    }

    public Mono<String> fetchReactive() {
        return webClient.get().uri("/slow").retrieve().bodyToMono(String.class)
            .map(value -> webClient.get().uri("/other").retrieve().bodyToMono(String.class).block());
    }

    public void broadCatch() {
        try {
            HttpClient.newHttpClient();
            userRepository.findByName("x");
        } catch (Exception ignored) {
        }
    }
}
