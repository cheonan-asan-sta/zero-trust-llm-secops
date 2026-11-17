# VPN 초기 프레임 진단 연결과 캡처 품질 확인 — v121

2026-11-17 · 채희주 담당 · 무료 로컬 · 실제 원본 수집 진행 중인 시점의 기록 · 전체 목표 active

[진단 연결기](../scripts/link_vpn_initial_frames.py)는 검증된 PCAP 관측과 원래 VPN 행의 endpoint/SID를 대조하고, 중복·누락·기록된 시각 관계를 구분한다. 새 시험 35건을 포함한 **Linux 964건·Ruff+RUF100 통과**다. 원본 전체 수집·실제 intake/연결 실행·시각 이용 가능성 입증·모델 적합·탐지 성능 재평가는 아직 미완료다.

이 연결기는 **예측기 입력으로 승인하지 않는 진단 도구**다. unique match는 공격 탐지 성공이나 실제 사람/기기 인증을 의미하지 않는다. 현재 확정 탐지 수치는 [v117](extra-apparmor-status-review.md)의 공유 감사 TP 2/FP 0/FN 4·F1 50%, VPN TP 84/FP 42/FN 0·F1 80%를 유지한다. 원래 1,681,815행·정답·목표를 바꾸지 않았고 기존 탐지 코드 바이트도 그대로다.

## 진단 연결의 구현 범위

[관측 인덱스](../scripts/f1_lab/vpn_initial_frame_link.py)는 [v120 검증 intake](extra-packet-member-verification.md)가 완료한 PCAP/관측 파일의 SHA·CRC 확인 상태와 같은 원래 VPN source를 요구한다. 물리 packet ordinal·정수 capture 시각·6개 허용 헤더 특징·고정 필드만 수용한다. 임의 label/expected_alert 필드, 잘못된 domain/자료형, 중복된 물리 source/ordinal, 경로 이탈, 불완전/다른 source의 intake를 거부한다.

현재 행이 정해진 IPv4 TLS initial 형식이어야 하고 prefix와 본문의 endpoint가 같아야 한다. SID는 해당 행에서 직접 읽는다. 구체적인 IP/포트/SID는 source-local 연결 hash에만 쓰며 특징 값으로 학습하지 않는다. name/인증서/나중 handshake 성공으로 앞선 initial을 채우지 않는다.

사전 고정한 진단 창은 해당 초의 1초 전부터 그 초가 끝나기 전까지다. 이 창은 **기록된 시각의 호환성을 조사하는 범위이며 실제 이용 가능 시각의 증명이 아니다.** 후보 0개·복수·고유 ID 일치를 구분하고, 고유 일치에는 capture가 로그 초의 하한 이전인지 같은 초 안인지 표시한다. 더 나중의 후보가 앞선 고유 후보를 취소하지 않으며 모호한 동시 후보를 임의로 하나 고르지 않는다. 인덱스 조회 참조만 정렬하고 원래 packet/log 물리 ordinal을 유지한다.

모든 원래 VPN 행의 case ID·ordinal·원문 행 SHA를 출력하며 파싱 오류/시각 역행도 남긴다. 오류 행을 정상으로 바꾸거나 제거하지 않는다. 입력 intake/관측/원문/UTC manifest·준비 지문을 끝에서 다시 확인하며 변화가 있으면 최종 결과를 게시하지 않는다. 이전 963건 snapshot 뒤 입력 지문 기록/manifest 재검증 회귀를 보강한 최종 코드로 964건을 확인했다. 이전 성공 실행도 private runtime에 보존했다.

각 행과 report의 `admitted_to_predictor=false`, `temporal_availability_proven=false`를 유지한다. `matched=true`는 endpoint/SID와 기록된 범위의 일치이며 공격 판정이 아니다. 새 가중치·점수·권한/차단 동작을 추가하지 않았다.

## 실제로 추가 확인한 source 품질

이미 확보한 RussellMitchell **training** no-pcaps archive의 게시 MD5 확인 기록·로컬 SHA와 ZIP member CRC를 보존했다. 추가로 같은 VPN 서버의 journal 2개와 syslog 4개, 디코딩/물리 기록 **4,159행**을 조사했지만 TLS initial 메시지나 OpenVPN 버전 메시지는 0이었다. 이 자료로 해당 initial 행의 초 단위 시각을 native 중복 메시지의 µs 시각으로 보강할 수 없었다. 조사한 6개 파일 범위의 결과이며 모든 외부 자료에도 근거가 없다는 뜻은 아니다.

journal decoder는 정상 종료했고 원문/decoded SHA를 기록했다. 한 실행에는 WSL host 설정 경고(구체 원인 미확정)가 stderr에 있었고, journal JSON은 정상 출력됐다. 전역 WSL 설정을 변경하지 않았다. 디코딩한 기록에서 찾지 못했다는 범위를 유지한다.

같은 archive의 VPN Suricata stats.log도 CRC/전체 SHA를 확인하며 **3,206,910행·Date header 51,143개**를 읽었다. `capture.kernel_packets` 표본 51,139개는 관측 최대 3,233,007, `capture.kernel_drops` 표본 40,591개는 관측 최소 2,859·최대 22,396이었다. [Suricata 공식 통계 설명](https://docs.suricata.io/en/suricata-6.0.20/performance/statistics.html)은 capture mode에 따른 kernel counter의 의미를 구분하며 drop을 설명한다. 이 문서의 버전이 실제 대상 엔진 버전을 검증한 것은 아니다.

이 값은 **전체 파일에서 발견한 표본 통계**다. 특정 오탐/미탐 행의 패킷이 유실됐다고 판정하거나 정확한 대상 기간의 손실률을 계산한 것이 아니다. 없는 counter를 0으로 채우지 않았고 이 수치를 탐지 오탐률/F1로 바꾸지 않았다. 다만 전체 캡처가 손실 없이 완전하다고 가정할 수는 없다. 같은 SID 후보가 하나뿐이어도 처음 패킷이나 재전송의 정확한 현재 시점을 입증한 것으로 보고하지 않는다.

## 실제 검증과 다음 단계

Windows 새 35건, Linux 전체 관련 964건·실패/skip 0이다. source/ID/형식·시각/중복/원문 보존·참조 불변·외부 pin/manifest 변화·label 필드 유입·불완전 intake·모호한 연결·시각 불명 상태에서의 예측기 승인 금지를 검사했다. network none 시험 컨테이너를 제거했다. 기능 시험을 1,681,815행의 새 성능 재평가로 대체하지 않는다.

전체 7.1GB source 수집이 완료되면 full checksum을 검증하고 실제 PCAP intake·진단 연결을 실행한다. 그 뒤 무엇이 실제로 구분 가능한지와 현재/이전 이용 가능성을 따로 확인해야 한다. 기록된 초가 같다는 이유나 캡처 완전성 가정으로 `admitted_to_predictor`를 켜지 않는다. 근거가 검증된 특징에 한해서만 training 역할·최소 정상 지지 5·공격 veto·단계별 지지를 유지하며 적합하고, 정답 차단 전체 재생·봉인 후 비교한다. 목표 도달은 실제 증거가 있을 때만 주장한다.

공유 감사 FN 4·VPN FP 42·별도 Wheeler training FN 9와 원래 6영역의 새 독립 인수는 남아 있다. 실제 LLM 품질 향상·유료 호출·AWS·push·새 CI·병합·장기 soak는 하지 않았다. 과거 시간 의존 fixture 오류의 원인이 해결됐다고 보고하지 않는다.

## 요청한 Docker 정리

사용자가 이번 작업 후 이 프로젝트의 불필요한 Docker 리소스 정리를 요청했다. 현재는 삭제 없이 프로젝트 실행 기록과 실제 tag/ID·container 참조를 대조해 **이전 일회성 프로젝트 이미지 tag 12개**를 확인했다. 실제 삭제는 현재 원본/패킷 검증 단계가 끝난 후 최신 사용 여부를 다시 확인하며 수행한다.

현재 재사용 시험 image SHA와 역할별 최신 baseline 6종, DB/백업을 포함한 volume 14개, 관련 없는 container를 보존한다. 이름만 비슷하거나 소유권이 확인되지 않은 공유 cache를 전역 prune하지 않는다. 이 문서 시점에는 삭제를 수행하지 않았으며, 정리 결과는 실행 뒤 별도 증거로 남긴다.

[코드·시험 지문·source 품질·정리 대기 JSON](infrastructure-results/extra-wire-link-v121-20261117.json) · [실제 JUnit](infrastructure-results/extra-wire-link-v121-20261117.xml) · [실행/재현](packet-source-test-guide.md) · [현재 목표 진행표](goal-performance-progress.md)
