package com.jhjeong.springsecuritybasic.domain.user;

import java.sql.Timestamp;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

@Entity
@Data
@NoArgsConstructor
public class User {

  @Id
  @GeneratedValue
  private Long id;

  private String username;

  private String password;

  private String email;

  @Enumerated(EnumType.STRING)
  private Role role;

  private String provider;

  private String providerId;

  @CreationTimestamp
  private Timestamp createDate;

  @Builder
  public User(String username, String password, String email,
      Role role, String provider, String providerId) {
    this.username = username;
    this.password = password;
    this.email = email;
    this.role = role;
    this.provider = provider;
    this.providerId = providerId;
  }
}
