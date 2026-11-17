# Native DNS 요청·응답 근거 연결 검증 — v124

2026-11-17 · 채희주 담당 · 무료 로컬 · 전체 목표 active · 목표 전 push/새 CI/병합 보류

DNS 요청과 응답을 실제 parser 누계와 연결하는 별도 기능을 추가했다. 같은 1,681,815행과 별도 5개 자료를 유지한 9개 묶음 비교에서 **추가 TP/FP·기존 TP 손실·추론 오류는 모두 0**이었다. 공유 감사 F1 **80%**, VPN F1 **80%**로 v123과 같다. 이번 기능 검증을 탐지 수치 향상으로 보고하지 않는다. [v123의 실제 개선](extra-shared-native-dns-review.md)은 유지했다.

## 구현과 선정 근거

완전히 받아 발행자 MD5와 로컬 SHA-256을 확인한 기존 archive를 재사용했다. 같은 공유 서버의 원래 audit 바이트·UTC facts·Suricata 실행 로그·전체 EVE만 열었다. label·attacker/configuration·archive 프로그램은 열거나 실행하지 않았다. PCAP를 요구하지 않는 별도 typed profile이며 packet 번호나 frame SHA를 만들어 넣지 않는다. 원본은 AIT Log Data Set V2.1, Landauer et al., DOI 10.5281/zenodo.19483937, CC BY-NC-SA 4.0의 비상업 연구 자료다.

[Suricata 6.0.4 parser](https://github.com/OISF/suricata/blob/suricata-6.0.4/rust/src/dns/dns.rs)는 요청과 응답 각각에 새 transaction을 만든다. [parser counter 갱신](https://github.com/OISF/suricata/blob/suricata-6.0.4/src/app-layer-parser.c)과 [프로토콜 누계](https://github.com/OISF/suricata/blob/suricata-6.0.4/src/app-layer.c)를 확인했다. 요청만 세어서 `dns_udp` 누계에 대응시키면 나중 요청을 과거에 관측한 것으로 잘못 연결할 수 있다. R의 요청 전용 실험은 이 문제로 거부했다.

[DNS logger](https://github.com/OISF/suricata/blob/suricata-6.0.4/src/output-json-dns.c), [serializer](https://github.com/OISF/suricata/blob/suricata-6.0.4/rust/src/dns/log.rs), [transaction 출력 상태](https://github.com/OISF/suricata/blob/suricata-6.0.4/src/output-tx.c)를 대조했다. 여러 질문의 중복 query나 누락이 없도록 flow의 native query tx ID가 **요청+응답 전체 순서**와 맞아야 한다. v2 응답 한 event를 세며 v1·TCP·질문 중복/누락·counter/clock/uptime 역행·필수 counter 누락·손실·종료 개수 불일치는 거부한다. [flow 방향 header](https://github.com/OISF/suricata/blob/suricata-6.0.4/src/output-json.c)이므로 응답 event의 src_port를 실제 응답 packet 방향으로 해석하지 않는다.

| Source | 기존 역할 | 요청 | 응답 | DNS UDP 전체 누계 | stats 표본 |
|---|---|---:|---:|---:|---:|
| RussellMitchell | training |20,012|19,969|39,981|51,142|
| Fox | 관측한 비학습 비교 |18,031|18,031|36,062|62,737|

보고된 단일 worker·UTC·전체 ZIP/원문·EVE CRC/EOF·counter 순서와 마지막 decoder/kernel/종료 수를 확인했다. 처음 충분한 **transaction** 누계 시각만 사용하며 event 시각과 이 상한 모두 현재 audit보다 앞선 기존 5초 안에 있어야 한다. 늦은 동일 counter로 과거 관측을 갱신하지 않는다.

이는 고정 producer 계약 아래 native parser에서 처리했을 조건부 상한이다. 실제 앱의 과거 수신·binary 원격 증명·파일 flush·사람/기기·권한·해당 명령 인과·유출 성공은 증명하지 않는다. EVE 이름은 직렬화된 text 모양이며 원래 packet label 경계나 wire bytes를 확인한 것은 아니다. 복원할 수 없는 escape/비ASCII 등은 미지원으로 보존하고 없는 권한을 facts에서 소급 채우지 않았다.

## 미탐이 그대로인 이유

전체 예측 봉인·소유 컨테이너 제거 후 채점하고 Fox의 기존 미탐467/468행을 진단했다. 첫 성공 systemd 실행 흐름은 맞지만 앞선 5초에 counter로 검증된 DNS 질의가 없고 인코딩 형태 질의도 없었다. 가장 가까운 앞선 인코딩 질의는 audit보다 **9.045920초 전**, 첫 충분한 counter 상한은 **0.942297초 전**이었다. 늦은 표본을 새 활동으로 취급하거나 이 사례를 맞추려고 기존 5초 조건을 늘리지 않았다. 진단 뒤 모델·규칙·예측도 바꾸지 않았다.

R에서 고정한 v123 서비스 novelty 규칙을 공유했다. Fox의 비학습 역할과 원래 정답을 유지했고 새 head나 unit/IP/도메인/절대 시각 예외를 학습하지 않았다. 새 근거 형식의 지원 범위는 넓어졌지만 F1은 그대로다.

| R/S/F 종류 | TP | FP | FN | 정밀도 | 재현율 | F1 | 오탐률 | 미탐률 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 공유 감사 |4|0|2|100%|66.6667%|80%|0%|33.3333%|
| 웹 감사 |47|0|0|100%|100%|100%|0%|0%|
| 인증 |32|0|0|100%|100%|100%|0%|0%|
| VPN |84|42|0|66.6667%|100%|80%|0.2286%|0%|

v123과 모든 판정이 같다. 별도 Wilson/Wardbeck 공유 FN2씩, Harrison VPN FP36, Shaw VPN FP24, Wheeler training VPN FP36/FN9도 그대로다. DNS event와 기능 fixture는 원래 평가 분모에 더하지 않았다. 이 표는 원래 credential/device/privilege/lateral/exfiltration/remote 여섯 영역의 새 독립 인수를 대신하지 않는다.

## 검증과 남은 작업

Linux **1,190건·Ruff+RUF100 통과**, 실패/error/skip0이다. 새81건은 요청/응답 전체 순서·중복/누락 질문·flow 충돌·자료별 고정 ZIP 크기·동일 크기 변조·실패/미래 근거·역할 변경·원본/기존 TP/오류 보존을 확인한다. 초기 변조 fixture는 더 이른 단계에서 거부됐으며, 고정 R 크기를 가정하던 두 reader 경계와 import 순서를 수정했다. 중간 실패와 재검증 기록도 JSON에 남겼다.

예측에는 기능 시험과 같은 app/scripts 바이트를 사용했다. cached image에서 network none·UID10001·read-only·capability 제거·CPU2/2GiB로 실행하고 예전 프로젝트/설치 사본과 문서/테스트/정답 집계를 차단했다. 입력·원본 archive·코드 불변, 예측 봉인과 소유 컨테이너 제거 후 채점을 확인했다. 새 image build/pull은 없었다.

[노출 대장](../infra/f1-lab/observed-source-exposure-v124.json)은 source ID와 payload769/pattern601을 보존하고 이번 native member 지문을 추가해 알려진 source SHA를55→61로 늘렸다. 소비한 8개 testbed의 추가 modality이며 새 독립 source는 아니다.

공유 감사의 실제 선행 실행/주체 근거, VPN FP42→4 이하 개선과 TP84/FN0 보존, 별도 Wheeler FN9, 원래6영역·5축·정상/위협 지지와 source/label 심사는 남아 있다. 다음 후보는 선언한 training에서 개발하며 비학습 Fox에 맞춘 시각/이름 예외를 만들지 않는다. 라벨·분모·95%/5% 목표는 유지하며 전체 gate는 미달이다.

LLM의 새 품질 향상은 측정하지 않았다. provider/유료 호출·AWS·push·새 CI·병합·8시간 soak는 하지 않았다. [요청한 Docker 정리](extra-vpn-packet-data-review.md)는 v122에서 완료해 image10·관련 cache38, Docker 보고2.715GB를 정리했다. 현재 test image와 모든 volume을 보존했고 이번 소유 컨테이너도 제거했다.

[전체 JSON](infrastructure-results/extra-native-dns-transactions-v124-20261117.json) · [실제 JUnit](infrastructure-results/extra-native-dns-transactions-v124-20261117.xml) · [동결 계약](../infra/f1-lab/shared-dns-transaction-contract-v124.json) · [재현](native-dns-test-guide.md)
