package com.example.demo.controller;

import com.example.demo.entity.UserAccount;
import com.example.demo.repository.UserRepository;
import com.example.demo.service.UserService;
import java.util.List;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {
    private final UserRepository userRepository;
    private final UserService userService;

    public UserController(UserRepository userRepository, UserService userService) {
        this.userRepository = userRepository;
        this.userService = userService;
    }

    @GetMapping("/admin/users")
    public List<UserAccount> users() {
        System.out.println("listing users");
        return userRepository.findAll();
    }

    @PostMapping("/users")
    public ResponseEntity<UserAccount> create(@RequestBody CreateUserRequest request) {
        return ResponseEntity.ok(userService.create(request.name()));
    }

    @GetMapping("/users/{id}")
    public ResponseEntity<UserAccount> get(@PathVariable Long id) {
        return ResponseEntity.ok(userRepository.findById(id).orElseThrow());
    }

    public record CreateUserRequest(String name) {
    }
}
