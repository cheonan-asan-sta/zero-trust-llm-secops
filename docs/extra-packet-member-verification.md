# 패킷 member 검증과 공유 감사 근거 공백 확인 — v120

2026-11-16 · 채희주 담당 · 무료 로컬 · 원본 수집 진행 중인 시점의 개발 기록 · 전체 목표 active

공개 원본의 전체 SHA/게시 MD5, 동일 VPN 원문, 선택 PCAP의 CRC/전체 SHA를 검증하는 [intake CLI](../scripts/prepare_vpn_packet_members.py)를 구현했다. 새 시험 21건과 기존 회귀를 묶은 **Linux 929건·Ruff+RUF100 통과**다. 이는 구현/기능 검증이며, 실제 대용량 원본 수집·intake·로그 연결·모델 적합·탐지 성능 재평가는 아직 완료하지 않았다.

파일 크기 확인 뒤 source가 증가하는 경우에도 읽기 상한에서 거부하도록 보완했고 해당 경계 회귀를 추가한 최종 고정 코드로 929건을 확인했다. 보완 전 928건 통과 기록도 private runtime에 보존했다.

원본 수집은 [v119 수집기](extra-packet-source-acquisition.md)의 같은 실행을 계속 사용한다. 완료 전 chunk를 PCAP 원본으로 쓰거나 성공으로 바꾸지 않았다. 확정 수치는 [v117](extra-apparmor-status-review.md)의 **공유 감사 TP 2/FP 0/FN 4·F1 50%, VPN TP 84/FP 42/FN 0·F1 80%**다. 원래 1,681,815행·정답·목표를 유지하며 원래 탐지 코드 바이트도 그대로다. 새 기능 fixture 통과율을 F1에 합산하지 않는다.

## 새 검증기의 실제 동작

입력 acquisition receipt의 외부 SHA·완료/학습/비상업 연구 범위·고정 asset·전체 수신 크기·게시 checksum 확인 상태를 검증한다. 이어 archive 전체 SHA와 고정 게시 MD5를 직접 다시 계산한다. 검증된 receipt만 믿고 실제 archive 확인을 생략하지 않는다.

고정 archive에 한정한 ZIP64 중앙 목록의 크기·수·위치·단일 disk 경계를 확인하고 중복/위험 member 이름을 거부한다. **기존 일반 ZIP reader의 2GiB 제한은 바꾸지 않았다.** 필요한 두 PCAP와 VPN 원문만 열며 labels·설정·archive 코드 본문은 열거나 실행하지 않는다. 원래 평가에서 사용한 VPN 원문 SHA와 archive의 VPN 로그 전체 바이트가 같아야 한다.

두 PCAP는 각 2GiB 이내의 일반·비암호화·지원 압축 member여야 한다. 충분한 여유 공간을 확인한 뒤 고정 출력 이름으로 제한 복사하고 EOF에서 CRC와 전체 SHA를 확인한다. 그 다음 [v119 초기 프레임 관측기](../scripts/f1_lab/pcap_initial.py)로 source SHA·물리 ordinal·근사 capture 시각·프레임 지문을 보존한다. 마지막으로 archive/원문/receipt가 바뀌지 않았는지 다시 확인해야 root report가 completed=true가 된다. 두 번째 member가 실패해 첫 결과가 있어도 전체 완료로 표시하지 않는다.

이 기능은 초기 프레임의 source 검증/준비다. 실제 사람·기기 권한·프레임의 암호학적 인증을 검증하거나 접근 권한을 발급하는 기능이 아니다. 원래 로그 행과의 endpoint/SID/시각 연결과 모델 적합·기존 오류/위험 경보 보존은 다음 단계다. 나중의 인증서나 ClientHello를 앞선 initial 행에 소급하는 조건을 추가하지 않았다.

## 공유 감사 미탐 4건의 journal 공백

원본과 예측/정답 지문을 유지하고 이미 관측한 R/S/F의 잔여 오분류를 확인했다. R과 Fox의 SERVICE_START/STOP 각각 2행이 남아 있고 Santos는 기존 2행 탐지를 유지한다. 사건 전 60초~사건 시각까지 journal 수신 기준으로 이용 가능한 행은 **4개 미탐 모두 0**이었다. 이 범위를 넘는 모든 역사나 모든 다른 자료에도 근거가 없다는 뜻은 아니다.

| 자료 | 남은 audit 행 | 사건 전 60초 journal 행 | 사건 뒤 journal 수신 지연 |
|---|---|---:|---|
| R·training | 667/668 시작·종료 | 각각 0 | +4,130µs / +22,978µs |
| Fox·기존 비학습 보정 | 467/468 시작·종료 | 각각 0 | +5,441µs / +9,007µs |

사건 뒤 도착한 두 journal 행은 추가 실행 명령이 아니었다. 원래 audit 시각·serial·type/body를 대조해 같은 원래 시작/종료 행의 echo임을 확인했다. 실제 `_CMDLINE`이나 별도 실행 주체의 새 근거로 쓰지 않았다. Fox는 이미 관측한 보정 자료의 오류 분석이며 이번에도 학습하거나 새 독립 평가라고 부르지 않았다.

이 결과는 현재 연결기의 구문 조건을 완화하거나 사건 뒤 journal을 앞당겨도 실제 부족한 실행/사람 근거가 새로 생기지 않는다는 점을 보여 준다. 부모 PID·현재 호출 신원·기기 권한을 추측해 채우지 않았다. 새 source 관측을 확보하거나 독립적인 실행/네트워크 근거를 검증해야 한다.

## 검증 범위와 다음 단계

새 Windows 시험 21건과 Linux 전체 관련 929건이 통과했다. 새 시험은 원래 로그 바이트 일치·labels 본문 미열기·archive/receipt/raw 외부 pin·scope/크기/기실행 거부·member 누락·디스크 경계·불량 CRC·중간 실패 때 완료 금지·ZIP/ZIP64 목록 경계를 검사한다. network none 시험 컨테이너를 제거했고 유료/클라우드 호출은 없다. 실제 원본 전체 checksum을 이미 통과했다는 증거로 대체하지 않는다.

원본 수집이 검증 완료되면 이 intake를 실제 자료에서 실행하고, 동일 source·endpoint·SID·실제 이용 가능 시각으로 초기 frame 연결을 확인한다. packet capture 시각은 근사 값이고 헤더는 위조 가능하다. 현재 초기 packet 자체에서 나온 관측과 나중 handshake 신원을 구분한 후에만 training 역할로 적합·정답 차단 전체 재생·봉인 후 채점으로 넘어간다. 성공 가능성을 미리 확정하지 않는다.

공유 감사 FN 4·VPN FP 42·별도 Wheeler training FN 9, 원래 6개 보안 영역의 새 독립 인수와 미뤄 둔 장기 soak는 남아 있다. 과거 service_registry_window 시간 의존 오류는 이번 929건에서 재현되지 않았지만 원인이 해결됐다는 뜻은 아니다. 실제 LLM 품질 개선/재평가·유료 API·AWS·push·새 CI·병합은 하지 않았다.

[혼동행렬 유지·지문·기능 시험·journal 공백 JSON](infrastructure-results/extra-packet-members-v120-20261116.json) · [실제 JUnit](infrastructure-results/extra-packet-members-v120-20261116.xml) · [실행/재현](packet-source-test-guide.md) · [현재 목표 진행표](goal-performance-progress.md)
