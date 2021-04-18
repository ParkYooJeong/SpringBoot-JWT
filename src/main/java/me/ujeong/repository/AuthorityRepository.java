package me.ujeong.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import me.ujeong.entity.Authority;

public interface AuthorityRepository extends JpaRepository<Authority, String> {
}
