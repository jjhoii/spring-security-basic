package com.jhjeong.springsecuritybasic.config.auth;

import com.jhjeong.springsecuritybasic.domain.user.User;
import com.jhjeong.springsecuritybasic.domain.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// 시큐리티 설정에서 loginProcessingUrl 로 등록한 경로로
// 요청이 오면 자동으로 UserDetailsService 타입의 빈의 loadUserByUsername 함수 호출
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

  private final UserRepository userRepository;

  // 시큐리티 session => Authentication => UserDetails
  // 리턴된 User 는 Authentication 내부에 저장
  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    User user = userRepository.findByUsername(username);
    if (user != null) {
      return new PrincipalDetails(user);
    }
    return null;
  }
}
