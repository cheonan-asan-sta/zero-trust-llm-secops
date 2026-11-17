# VPN 서버의 native journal·호출 근거 조사 — v127

2026-11-17 · 채희주 담당 · 무료 로컬 · 전체 목표 active

**기존 training 네 출처의 추가 native 파일39개를 조사했으나 탐지기에는 추가하지 않았다.**
공유 감사·VPN F1은 각각80%로 유지하며 기존 라벨·원래1,681,815행·목표를 바꾸지 않았다.
목표 전 push·새 CI·병합·유료 호출·AWS와8시간 soak는 계속 보류한다.

## 조사 이유와 범위

TLS 최초 접속 행에 뒤쪽 인증서·사람/기기 신원을 붙이면 당시 없던 근거를 쓰게 된다.
그래서 이미 확보한 같은 VPN 서버의 journal이 원래 OpenVPN 메시지를 더 정밀한 시각이나
프로세스 정보와 함께 남겼는지 확인했다. 존재하는 별도 native 복사본을 찾는 조사이며,
같은 사건의 복사본을 새 정상 학습 표본으로 늘리는 작업이 아니다.

원래 R/S/Shaw/Wheeler training 역할만 사용했다. Fox·Harrison·Wardbeck을 재학습하지 않았다.
각 원래 VPN 파일의 전체 SHA·행 수·UTC 준비 지문을 확인한 뒤 해당 호스트의
journal·audit·auth·syslog와 명시 VPN monitoring 경로만 고정해 읽었다.
설정·개인키·시뮬레이터·공격/라벨 규칙·정답 본문은 읽지 않았다.

각 파일은 최대32MiB, 출처당 선택 합계128MiB, journal 해제 출력64MiB로 제한했다.
원격 파일명을 경로로 풀지 않고 소유한 번호 파일로 보관했으며 모든 선택 member의
CRC·SHA를 검증했다. 기존 캐시는 이전에 게시 MD5·전체 SHA로 검증한 파일이다.
이번에는 **전체 ZIP을 다시 해시하지 않았고**, 원래 VPN member SHA·새 선택 파일 CRC/SHA와
읽기 전후 archive 크기/mtime를 확인했다. 새로운 전체 archive 검증으로 확대 주장하지 않는다.

## 실제 결과

| Training 출처 | 파일 수 | journal 기록 | text 행 | 원래 VPN 메시지와 exact match | OpenVPN 프로세스가 남긴 journal 기록 |
|---|---:|---:|---:|---:|---:|
| RussellMitchell |9|3,795|1,306|0|0|
| Santos |9|3,631|1,221|0|0|
| Shaw |11|4,119|1,772|0|0|
| Wheeler |10|4,202|1,569|0|0|
| 합계 |39|15,747|5,868|0|0|

선택한 원본 합계는67,932,203바이트다.21,615개 기록은 중복을 제거한 사건/사람/인증 세션 수가 아니다.
문자열이 아닌 journal MESSAGE4개도 삭제하지 않고 별도로 집계했다.
native journal 전체 물리 행·출처·지문을 보존했고, 새 분류 평가의 오류 행을 제외한 것은 아니다.

exact match는 원래 OpenVPN 행 전체 또는 앞의 고정 시각을 제거한 본문과 journal MESSAGE를 비교했다.
끝점·인증서 주체를 지워 서로 다른 행을 같게 만들지 않았다. 같은 초 후보도0이었다.
OpenVPN 프로세스 집계는 보고된 `_COMM/_EXE/_SYSTEMD_UNIT/SYSLOG_IDENTIFIER`의 명시 관측 범위다.
이것만으로 실행 binary나 사람을 인증했다는 뜻은 아니다.

네 출처에 각각3개씩 OpenVPN을 언급하는 **systemd의 서비스 시작 기록**은 있었다.
이는 PID1/root가 slice/서비스를 시작했다는 기록이며 OpenVPN 접속·인증서 검증 메시지가 아니다.
실제 호출 사람·새 연결의 PID/기기·권한·현재 인증서 신원을 만들지 않았다.
audit에서도 명시적으로 보고된 OpenVPN process 행은 이 조사 패턴에서0이었다.

system journal은 VPN 기간 안의 기록을 R1,217/S1,104/Shaw1,614/Wheeler1,422개 포함했다.
따라서 단순히 journal이 모두 오래됐기 때문이라고 해석하지 않는다.
이 범위에서 필요한 접속별 복사본을 찾지 못했다는 결과이며 모든 다른 source에서의 부재 증명은 아니다.
수신 시각과 원래 시각 중 늦은 값으로 비교하고, 알려지지 않은 시각/주체를 보완하지 않았다.

## 성능·검증의 경계

새 특징·모델·임계값·점수·운영 경로 변경0, 학습/예측/정답 재개봉0이다.
그 때문에 새 전체 탐지 재생·pytest·Docker 실행도0이다.
직전 [v126](extra-dedale-native-intake.md)의 관련 Windows/Linux120건과
최종 탐지 검증 v125의1,244건을 이번 조사에서 새로 실행한 것으로 쓰지 않는다.
조사 전후 app/scripts Python497파일이 동일함을 확인했다.

현재 원래 R/S/F의 공유 감사는TP4/FP0/FN2, VPN은TP84/FP42/FN0이다.
별도 Harrison VPN은TP28/FP36/FN0, Wheeler training은TP47/FP36/FN9다.
미채택한 v125 단계 통합 초안의 FP31을 최신 수치로 사용하지 않는다.

이번 추가 source 지문은 [v127 노출 대장](../infra/f1-lab/observed-source-exposure-v127.json)에 기록했다.
기존 ID·payload·pattern·training/비학습 역할은 보존했다. 새 독립 인수 사례는0이다.
원래6영역·5축과 source/label 검토 공백은 별도이며 [원래 독립 계획](extra-independent-evaluation-preparation.md)을 유지한다.

## 다음 판단

이미 시험한 protocol/issuer/고정 포트/연결 이력만 반복하거나 서비스 시작 기록으로
접속별 정상 지지를 늘리지 않는다. 이 조사 자료로는 기존 행에 부족한 사람·기기·권한 신호나
정밀한 접속 시각을 공급하지 못했다. 기존 event-level 목표는 계속 미완료다.

새 외부 자료는 [DEDALE 형식 조사](extra-dedale-native-intake.md)처럼 별도 모집단·라벨 의미·그룹을 먼저 검증한다.
그 자료가 과거 AIT 접속의 신원을 입증하거나 기존 FP/FN을 줄였다고 주장하지 않는다.
실제 개선에는 해당 접속 당시 이용할 수 있었던 추가 근거나, 현재 특징과 구별되는 유효한 인과적 특징의 검증이 필요하다.

[공유 JSON](infrastructure-results/extra-vpn-native-clock-v127-20261117.json)
