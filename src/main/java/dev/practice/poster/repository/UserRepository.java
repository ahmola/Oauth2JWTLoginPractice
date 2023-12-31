package dev.practice.poster.repository;

import dev.practice.poster.model.CustomUser;
import dev.practice.poster.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<CustomUser, Long> {

    Optional<CustomUser> findByUsername(String username);

    @Query("SELECT u.roles FROM CustomUser u WHERE u.username = :username")
    List<ArrayList<Role>> findRolesByUsername(@Param("username") String username);

    @Transactional
    @Modifying
    @Query("DELETE FROM CustomUser u WHERE u.username = ?1")
    void deleteByUsername(String username);
}
