package com.example.good;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}

@Validated
@RestController
class UserController {
    private final UserService service;

    UserController(UserService service) {
        this.service = service;
    }

    @GetMapping("/users/{id}")
    ResponseEntity<UserResponse> show(@Valid @PathVariable String id) {
        return ResponseEntity.ok(service.find(id));
    }
}

@Service
class UserService {
    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    private final RestTemplate client = new RestTemplateBuilder()
        .setConnectTimeout(Duration.ofSeconds(2))
        .setReadTimeout(Duration.ofSeconds(5))
        .build();

    @Transactional(readOnly = true)
    UserResponse find(String id) {
        try {
            client.getForEntity("https://example.test/status", Void.class);
        }
        catch (RuntimeException ex) {
            logger.warn("Status check failed for user {}", id, ex);
            throw ex;
        }
        return new UserResponse(id, "active");
    }
}

record UserResponse(@NotBlank String id, @NotBlank String status) {}
