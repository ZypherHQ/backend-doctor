package com.example.demo.repository;

import com.example.demo.entity.UserAccount;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface UserRepository extends JpaRepository<UserAccount, Long> {
    @Query("select u from UserAccount u where u.name = " + "?1")
    List<UserAccount> unsafeQuery(String name);

    Optional<UserAccount> findByName(String name);
}
