# Native DNS 관측과 첫 서비스 실행 흐름으로 공유 감사 미탐 개선 — v123

2026-11-17 · 채희주 담당 · 무료 로컬 · 전체 목표 active · 목표 전 push/새 CI/병합 보류

원본은 [AIT Log Data Set V2.1](https://zenodo.org/records/19483937), Landauer et al., DOI 10.5281/zenodo.19483937, CC BY-NC-SA 4.0의 비상업 연구 자료다. 기존 training 역할과 발행자 라벨을 유지했다.

같은 1,681,815개 물리 행을 유지한 전체 비교에서 공유 감사 **TP 2→4·FN 4→2·FP 0 유지, F1 50%→80%**를 확인했다. 추가 오탐·기존 TP 손실·추론 오류는 모두 0이다. 새로 탐지한 두 행은 **RussellMitchell training의 같은 서비스 사건 시작/종료**이며 독립 공격 두 건이 아니다. 이 결과는 새로 검증한 native-capture 오프라인 검토 profile이다. 실제 프로젝트 앱이 과거 시각에 이 자료를 받았거나 운영 기본 탐지기에 배포했다는 뜻은 아니다.

## 새로 확보한 근거와 이용 가능한 시각

[v122에서 완전히 검증한 원본](extra-vpn-packet-data-review.md)에서 같은 공유 서버의 원래 감사 로그 바이트와 PCAP·Suricata EVE·프로그램 실행 로그·UTC metadata를 대조했다. PCAP 665,590개 물리 기록·DNS 질의 20,012개, EVE stats 51,142개를 확인했다. source SHA와 ZIP CRC를 보존했으며 원래 감사·정답 행을 바꾸지 않았다. label·attacker/configuration 파일이나 archive 안의 프로그램을 읽어 실행하지 않았다. facts는 timezone 확인에만 사용하고 당시 사람·기기·권한·명령을 채우지 않았다.

실제 프로그램 로그는 Suricata 6.0.4·ens3의 AF_PACKET 1개·packet processing worker 1개를 보고한다. 이 source의 마지막 kernel/decoder/종료 로그 카운터는 모두 PCAP 전체 665,590과 같고, stats의 필수 drop 카운터는 전부 0이었다. 누락된 값을 0으로 채우지 않았다. 여러 worker·부분/추가 PCAP·clock/counter 역행·손실·다른 원문/CRC/SHA·종료 개수 불일치는 이 profile에서 거부한다. VPN capture의 손실 통계와 혼동해 모든 source가 무손실이라고 가정하지 않는다.

[단일 worker 동작 설명](https://github.com/OISF/suricata/blob/suricata-6.0.4/src/runmode-af-packet.c)과 [packet logger](https://github.com/OISF/suricata/blob/suricata-6.0.4/src/log-pcap.c), [counter 수집](https://github.com/OISF/suricata/blob/suricata-6.0.4/src/counters.c)과 [stats 시각 생성](https://github.com/OISF/suricata/blob/suricata-6.0.4/src/output-json-stats.c)을 대조했다. 이 고정 producer의 단일 worker·완전한 순서 보존 capture 계약 아래, **처음으로 packet ordinal 이상을 보고한 decoder 누계**의 같은 호스트 wallclock을 원시 packet bytes가 native decoder에서 관측됐을 시각의 상한으로 사용한다. packet capture 시각만 현재 앱 수신 시각으로 바꾸지 않는다.

R의 packet 629,814는 audit 약 3.896초 전의 DNS 질의였고, 첫 충분한 decoder counter는 audit보다 158,354µs 앞선 wallclock을 보고했다. 카운터 표본은 갱신 지연이 있으므로 중간 kernel/decoder 값이 항상 같거나 kernel≥decoder라고 가정하지 않았다. 나중의 같은 카운터로 오래된 관측 시각을 새로 갱신하지도 않는다. 원래 packet 시각과 이 보수적 상한이 모두 기존 5초 창 안에 있어야 하며 현재와 같은/미래 시각은 제외한다.

이는 **검증한 publisher source의 native decoder 계약에 따른 관측 근거**다. 실제 binary가 upstream과 byte-identical하다는 원격 증명·로그 파일 flush/프로젝트 앱 도착 시각·사람/기기 신원·권한·해당 서비스 명령과 DNS의 정확한 인과·유출 성공을 증명하지 않는다. 관련 플래그는 false로 남긴다. 다른 source에 적용할 때 같은 producer와 완전성 계약을 새로 확인해야 한다.

## 적용한 검토 조건과 제외한 후보

처음의 넓은 후보는 root SERVICE_START/STOP와 근처 인코딩 DNS만 결합해 training에서 미탐 2행을 찾았지만 **정상 4행도 새로 경보**로 바꾸었다. 이 후보는 채택하지 않았다.

최종 후보는 해당 감사 source/epoch의 앞선 기록에 없던 **처음 관측한 unit 실행 흐름**을 추가로 요구한다. 실제 호스트에서 처음 만들어진 서비스라는 뜻은 아니다. unit은 source-local hash로 이전 start/stop을 연결하는 데만 쓰며 문자 이름·도메인·IP·절대 날짜를 공격 예외로 배우지 않는다. 앞서 관측한 일반 서비스가 우연히 같은 네트워크 활동 근처에서 실행된 경우는 새 unit으로 취급하지 않는다.

현재 행은 PID1/root systemd의 성공 서비스 사건이어야 한다. 시작 시의 관측 상태를 보존하고, 같은 첫 실행의 종료도 기존 5초 범위에서만 연결한다. 실패한 시작·다른 주체·원문 변경·순서/시각/serial 역행·다른 source·모호/누락된 지원은 추가 검토 근거로 쓰지 않는다. 나중 종료나 미래 DNS로 앞선 시작 판정을 채우지 않는다.

DNS 이름에서는 여러 긴 높은 entropy label과 비호스트명 base64 문자 같은 일반 모양만 사용한다. 이는 유효한 DNS label에서도 가능한 **관측 형태**이며 그 자체로 불법 질의나 악성 정답이 아니다. 이미 경보인 판정은 유지하고, 기존 `unchanged` 미경보에만 추가 검토 경보를 붙인다. 0.95는 검토 결정 표식이며 보정된 공격 확률이 아니다. 자동 차단·접근 허용·권한 변경은 하지 않았다.

## 같은 모집단의 실제 결과

| R/S/F 종류 | TP | FP | FN | 정밀도 | 재현율 | F1 | 오탐률 | 미탐률 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 공유 감사 | 4 | 0 | 2 | 100% | 66.6667% | 80% | 0% | 33.3333% |
| 웹 감사 | 47 | 0 | 0 | 100% | 100% | 100% | 0% | 0% |
| 인증 | 32 | 0 | 0 | 100% | 100% | 100% | 0% | 0% |
| VPN | 84 | 42 | 0 | 66.6667% | 100% | 80% | 0.2286% | 0% |

R 공유 감사 FN2→0, Santos의 기존 TP2 유지, Fox FN2 유지다. 보조 capture는 평가 대상 행 수에 더하지 않았다. 별도 Wilson/Wardbeck 감사·인증, Harrison/Shaw/Wheeler VPN은 판정 동일하며 원래 1,681,815행에 합산하지 않았다. Wilson/Shaw/Wheeler 등 기존 training과 Fox/Wardbeck/Harrison의 이미 관측한 비학습 보정 역할도 그대로다. R에만 이번 검증된 native 지원이 있으며 없는 다른 source의 자료를 소급 생성하지 않았다.

## 검증과 독립 인수 준비

Linux **1,109건·Ruff+RUF100 통과**, 실패/error/skip 0이다. 새 145건은 DNS/PCAP 경계·원본/UTC/프로그램/카운터·첫 source episode·실패 시작·정확한 µs/5초 경계·뒤늦은 기록·추가 정답 필드·불완전/변조 입력·누락/중복/다른 source·기존 오류/TP/전체 case ID 보존을 확인한다. 기능 fixture는 공격 탐지 F1에 더하지 않았다.

9개 자료 묶음의 예측은 network none·UID10001·read-only·capability 제거·CPU2/2GiB와 기존 image에서 실행했다. image 안의 예전 프로젝트/설치 사본·문서/테스트를 차단하고 새 정답/평가 집계를 제공하지 않았다. baseline 예측·필수 원문·검증된 관측 projection만 사용했다. 코드가 기능 시험과 byte-identical함을 확인하고 예측을 봉인·소유 컨테이너 제거 후 채점했다. 원본 archive·입력·코드 불변과 9개 전체의 추가 FP/TP 손실0을 확인했다.

[현재 노출 대장](../infra/f1-lab/observed-source-exposure-v123.json)도 갱신했다. v43 대장의 payload/pattern 항목을 보존하고 이미 소비한 8개 canonical testbed와 알려진 source SHA를 추가했다. Harrison/Wilson은 이미 접근/채점 또는 학습됐으므로 예전 예약을 미공개 최종 source로 재사용할 수 없다. 원래 ID와 이름만 바꾼 같은 source를 거부하는 4개 입력은 **메타데이터 제어군**이며 새 평가 사례가 아니다. 이 대장이 모든 의미상 유사 패턴을 완전히 열거한 것도 아니다. 원래 6영역·5개 분리 축·정상/위협 지지·독립 source/label 심사와 최종 후보 동결은 아직 미완료다. 예전 준비 프로토콜의 바이트를 바꾸지 않았다.

현재 공유 감사의 Fox 미탐2, VPN FP42·별도 Wheeler training FN9, 원래 6영역의 새 독립 인수는 남아 있다. 정밀도·재현율·F1≥95% 및 FPR/FNR≤5% 전체 목표는 미달이다. 실제 LLM 품질 향상은 측정하지 않았고 유료 호출·AWS·push·새 CI·병합·장기 soak도 수행하지 않았다. 과거 시간 의존 fixture 오류의 근본 원인이 해결됐다고 보고하지 않는다.

[전체 혼동행렬·지문·조건 JSON](infrastructure-results/extra-native-dns-v123-20261117.json) · [실제 JUnit](infrastructure-results/extra-native-dns-v123-20261117.xml) · [재현](native-dns-test-guide.md)
