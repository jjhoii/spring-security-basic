package com.jhjeong.springsecuritybasic.config.oauth;

import com.jhjeong.springsecuritybasic.config.auth.PrincipalDetails;
import com.jhjeong.springsecuritybasic.config.oauth.provider.FacebookUserInfo;
import com.jhjeong.springsecuritybasic.config.oauth.provider.GoogleUserInfo;
import com.jhjeong.springsecuritybasic.config.oauth.provider.NaverUserInfo;
import com.jhjeong.springsecuritybasic.config.oauth.provider.OAuth2UserInfo;
import com.jhjeong.springsecuritybasic.domain.user.Role;
import com.jhjeong.springsecuritybasic.domain.user.User;
import com.jhjeong.springsecuritybasic.domain.user.UserRepository;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class PrincipalOAuth2UserService extends DefaultOAuth2UserService {

  private final UserRepository userRepository;
  private final BCryptPasswordEncoder bCryptPasswordEncoder;

  public PrincipalOAuth2UserService(
      UserRepository userRepository,
      @Lazy BCryptPasswordEncoder bCryptPasswordEncoder) {
    this.userRepository = userRepository;
    this.bCryptPasswordEncoder = bCryptPasswordEncoder;
  }

  /*
   * 구글로부터 받은 userRequest 데이터에 대한 후처리를 하는 메서드
   */
  @Override
  public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
    // super.loadUser 메서드는 유저 프로필을 받아옴
    OAuth2User oAuth2User = super.loadUser(userRequest);

    OAuth2UserInfo oAuth2UserInfo = null;
    if (userRequest.getClientRegistration().getRegistrationId().equals("google")) {
      oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
    } else if (userRequest.getClientRegistration().getRegistrationId().equals("facebook")) {
      oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
    } else if (userRequest.getClientRegistration().getRegistrationId().equals("naver")) {
      oAuth2UserInfo = new NaverUserInfo((Map)oAuth2User.getAttribute("response"));
    } else {
      // do something
    }

    String provider = oAuth2UserInfo.getProvider();
    String providerId = oAuth2UserInfo.getProviderId();
    String email = oAuth2UserInfo.getEmail();
    String username = provider + "_" + providerId;
    String password = bCryptPasswordEncoder.encode("default_password");
    Role role = Role.USER;

    User userEntity = userRepository.findByUsername(username);

    if (userEntity == null) {
      userEntity = User.builder()
          .username(username)
          .email(email)
          .password(password)
          .role(role)
          .provider(provider)
          .providerId(providerId)
          .build();
      userRepository.save(userEntity);
    }

    return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
  }
}
