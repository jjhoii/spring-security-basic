package com.jhjeong.springsecuritybasic.config;

import com.jhjeong.springsecuritybasic.config.oauth.PrincipalOAuth2UserService;
import com.jhjeong.springsecuritybasic.domain.user.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  private final PrincipalOAuth2UserService principalOAuth2UserService;

  // 패스워드 암호화
  @Bean
  public BCryptPasswordEncoder encodePwd() {
    return new BCryptPasswordEncoder();
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.csrf().disable()
        .headers().frameOptions().disable()
        .and()
        .authorizeRequests()
        .antMatchers("/user/**").authenticated()
        .antMatchers("/manager/**")
        .hasAnyRole(Role.MANAGER.name(), Role.ADMIN.name())
        .antMatchers("/admin/**")
        .hasRole(Role.ADMIN.name())
        .anyRequest().permitAll()
        .and()
        .logout().logoutSuccessUrl("/")
        .and()
        .formLogin().loginPage("/login-form").loginProcessingUrl("/login")
        .defaultSuccessUrl("/")
        .and()
        .oauth2Login().loginPage("/login-form") // OAuth2 로그인 페이지 설정. 엑세스 토큰과 사용자 정보까지 한 번에 받아옴
        .userInfoEndpoint()
        .userService(principalOAuth2UserService);
  }
}
