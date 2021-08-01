package com.jhjeong.springsecuritybasic.controller;

import com.jhjeong.springsecuritybasic.config.auth.PrincipalDetails;
import com.jhjeong.springsecuritybasic.domain.user.Role;
import com.jhjeong.springsecuritybasic.domain.user.User;
import com.jhjeong.springsecuritybasic.domain.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequiredArgsConstructor
public class IndexController {

  private final UserRepository userRepository;
  private final BCryptPasswordEncoder bCryptPasswordEncoder;

  @GetMapping("/")
  public String index() {
    return "index";
  }

  @GetMapping("/admin")
  public String admin() {
    return "admin";
  }

  @GetMapping("/login-form")
  public String login() {
    return "loginForm";
  }

  @GetMapping("/manager")
  public String manager() {
    return "manager";
  }

  @GetMapping("/join")
  public String joinForm() {
    return "join";
  }

  @PostMapping("/join")
  public String join(User user) {
    user.setRole(Role.USER);
    user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
    userRepository.save(user);

    return "redirect:/login-form";
  }

  @GetMapping("/join-proc")
  public @ResponseBody String joinProc() {
    return "회원가입 완료";
  }

  @GetMapping("/user")
  public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
    System.out.println(principalDetails.getUsername());
    System.out.println(principalDetails.getPassword());
    return "user";
  }

  @Secured("ROLE_ADMIN")
  @GetMapping("info")
  public @ResponseBody String info() {
    return "personal";
  }

  @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
  @GetMapping("data")
  public @ResponseBody String data() {
    return "data";
  }
}
