# JWT

## JWT란?📕

RFC 7519 웹 표준으로 지정이 되어있고 JSON 객체를 사용해서 토큰 자체에 정보들을 저장하고 있는 Web Token

## JWT 장점

중앙의 인증서버, 데이터 스토어에 대한 의존성 없기 때문에 시스템 수평 확장에 유리

Base64 URL Safe Encoding 을 이용하여 URL, Cooke, Header 모두 사용 가능한 범용성을 갖고있음

## JWT 단점

Payload의 정보가 많아지면 네트워크 사용량(트래픽) 증가, 데이터 설계 고려 필요

토큰이 클라이언트에 저장되어 서버에서 클라이언트의 토큰을 조작할 수 없음



#### 출처

**inflearn 스프링 시큐리티 - Spring Boot 기반으로 개발하는 Spring Security**