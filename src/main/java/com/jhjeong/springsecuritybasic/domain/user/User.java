package com.jhjeong.springsecuritybasic.domain.user;

import java.sql.Timestamp;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;

@Entity
@Data
public class User {

  @Id
  @GeneratedValue
  private Long id;

  private String username;

  private String password;

  private String email;

  @Enumerated(EnumType.STRING)
  private Role role;

  @CreationTimestamp
  private Timestamp createDate;
}
