# VPN_Service_With_Fido2.0

---

![image](https://user-images.githubusercontent.com/86182243/182912096-bfdb54e6-017a-4aa7-97d0-dc6cb078fc5f.png)

2021년도에 진행되었던 “2021 FIDO Alliance Developer Challenge”에서 아이디어 인터뷰 후, 본선 진출 20개 팀에 선발되어, 본선에서 제출했던 출품작입니다. 
인증 서버는 [W3C의 웹 인증 표준 권고안](https://www.w3.org/TR/2019/REC-webauthn-1-20190304/#intro)에 맞추어 개발되었습니다.


## 대회 프로세스—

7월 9일: 등록 마감

7월 16일: 초기 상영 및 상위 20개 팀 컷오프

8월 27일: FIDO2 API 구현

9월 10일: 최종 평가

9월 17일: 상위 3명의 수상자 발표

## 배경 및 목적—

1. COVID-19 팬대믹으로 인해 많은 기업들의 근무 형태가 재택근무로 변경되어 VPN의 사용률이 증가함.
2. 이에 따라, 공격자들도 이러한 점을 노려, 기업의 VPN 계정 탈취하여 다크웹 상에서 거래가 활발 해짐.
3.  FIDO2.0을 이용한 VPN을 사용하여 이러한 문제점들을 해결하기로함.

## 팀 구성—

[차현석](https://github.com/t3nderex)(순천향대학교 정보보호학과, SCH 사이버보안연구센터)

[박준형](https://github.com/CheLuEs)(순천향대학교 정보보호학과, SCH 사이버보안연구센터)

[김동언](https://github.com/7UN4)(순천향대학교 정보보호학과, SCH 사이버보안연구센터)

## 개발 프로세스—

| 작업 목록 |  담당자 |  사용 언어/소프트웨어 | 설명 |
| --- | --- | --- | --- |
| VPN Client |  박준형 | Python | VPN 서비스 클라이언트 |
| Web Server |  차현석, 김동언 | Apache | 웹 서버 |
| FIDO2.0 Server | 차현석, 김동언 | Python, Javascript | FIDO2.0 인증 처리 서버 |
| Web Client |  차현석, 김동언 | HTML(Flask-jinja2), CSS, Javascript | FIDO2.0 로그인 웹 페이지 |

## 동작 프로세스—

| 처리 주체 | 설명 |
| --- | --- |
| VPN Client | VPN 클라이언트를 실행시킨 후, 로그인 웹 페이지 생성 |
| FIDO2.0 Client | 회원 가입/로그인 시도 |
| FIDO2.0 Server | 인증 처리 |
| FIDO2.0 Server | 소켓 통신을 통해 인증 결과를 VPN Client로 전달  |
| VPN Client | 인증 결과가 참이라면 로그인 성공 |

## 구동

https://user-images.githubusercontent.com/86182243/182912166-229bba5a-f3b5-4c56-849c-06ee6d6a659d.mp4

