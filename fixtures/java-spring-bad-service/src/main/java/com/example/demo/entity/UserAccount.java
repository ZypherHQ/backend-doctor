package com.example.demo.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import java.util.List;

@Entity
public class UserAccount {
    @Id
    private Long id;
    private String name;

    @OneToMany(fetch = FetchType.EAGER)
    private List<LoginEvent> events;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
