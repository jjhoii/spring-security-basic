package com.jhjeong.springsecuritybasic.config;

import com.jhjeong.springsecuritybasic.domain.user.Role;
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
public class SecurityConfig extends WebSecurityConfigurerAdapter {

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
        .defaultSuccessUrl("/");
  }
}
