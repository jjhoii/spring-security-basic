package com.jhjeong.springsecuritybasic.domain.user;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public enum Role {

  GUEST("ROLE_GUEST", "손님"),
  USER("ROLE_USER", "일반 사용자"),
  MANAGER("ROLE_MANAGER", "매니저"),
  ADMIN("ROLE_ADMIN", "관리자");

  private final String key;
  private final String title;
}
