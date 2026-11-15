# 실행 근거 수집기의 사전 승인 키 공급자 이중화

## 해결하는 문제와 신뢰 경계

수집기 하나가 사용하는 키 공급 프로세스·Unix 소켓이 사라지면 수집이 중단된다. 이 작업은 **서로 다른 runtime 서명키를 이미 승인받은 두 공급자**에 직접 연결한다. 단일 중계기·공유 개인키를 새로 만들지 않는다. 같은 tenant/server/source/unit과 공개 신뢰 registry SHA, 두 key ID·소켓·peer UID를 묶은 profile SHA를 관리자가 사전 고정한다. failover는 권한 발급·신규 키 등록·pin 자동 갱신이 아니다.

공급자 부재·연결 거절·아무 바이트도 없는 시간 초과, 사전 등록된 주 키의 비활성/기간 만료만 대기 공급자 선택을 허용한다. 잘못된 키·다른 역할/범위·안전하지 않은 경로·잘린/초과 응답·UID·서명 불일치는 **대기 공급자가 살아 있어도 전체 요청을 거부**한다. endpoint당 최대0.5초, 후보2개, 응답32바이트와 EOF를 검사한다. private parent0700/socket0600·inode·SO_PEERCRED UID를 확인하며 운영자/커널/system manager는 신뢰한다.

## 동일 UID의 다른 서비스에 키를 주지 않는 방법

키 없는 health worker와 수집기가 같은 UID를 쓰는 템플릿이 있으므로 UID 확인만으로는 부족하다. 새 `serve_collector_credential`의 운영 모드는 `--allowed-service-unit`을 필수로 받는다. kernel SO_PEERCRED의 PID, systemd의 정확한 Id·MainPID·현재 상태·InvocationID, `/proc/PID/cgroup`의 정확한 v2 경로, 검사 전후 프로세스 시작 tick을 대조한 뒤에만 key supplier를 호출한다. 동일 UID의 다른 unit도 거부한다. 명시적인 `--local-uid-only-fixture`는 단위 시험용이며 운영 인수로 사용하지 않는다.

WSL은 v1 controller 행과 `0::경로`를 함께 반환한다. 첫 실제 시도는 전체 파일을 한 줄로 가정해 정상 수집기도 거부했다. 실제 소유 시험 unit의 manager/kernel 값을 대조한 뒤, v2 행을 정확히 찾고 존재하는 name=systemd 행도 일치하도록 수정했다. 다른 unit·PID 재사용·중복 행·잘못된 경로는 계속 거부한다. [Linux cgroup v2 문서](https://origin.kernel.org/doc/html/v6.8/admin-guide/cgroup-v2.html), [systemctl 공개 속성 문서](https://www.freedesktop.org/software/systemd/man/latest/systemctl)를 참고한다.

개별 공급자는 새 Python 프로세스로 시작하며 할당된 runtime 키 하나만 anonymous stdin pipe로 전달한다. 부모가 가진 다른 fixture 키가 fork 뒤 메모리에 남는 구조를 사용하지 않는다. 개인키 파일·argv·환경·로그를 만들지 않으며 dumpable0, capability0, NoNewPrivileges를 검사한다. 이는 보관소·HSM·장기 운영용 키 provisioning/escrow·원격 attestation 구현이 아니다. 공급자 CLI는 최대100연결·600초의 제한된 어댑터이며 운영 재시작·키 주입 수명 관리는 별도 인수가 필요하다.

## 연결 지점

| 구성 | 구현 및 동작 |
|---|---|
| 선택 | `scripts/f1_lab/collector_provider_ha.py`: 고정 profile·현재 registry·개별 키를 확인하고 수집 전후 pin 유지 |
| 수집 CLI | `scripts.collect_shared_execution --provider-profile ... --provider-profile-sha256 ...`; 기존 stdin/LoadCredential 모드는 기본 동작 유지, HA와 동시 선택 불가 |
| peer 인증 | `credential_peer_service.py`, `serve_collector_credential.py`, `CredentialSocket`의 선택형 peer validator |
| 신선도 | `CollectorMonitor`에 명시적인 대체 key ID 하나만 허용; 원래 primary 범위의 단일 ledger로 key 전환 전후 관측 순서 유지 |
| health CLI | `scripts.service_capture_status --alternate-key-id ...`; 이 인수를 생략하면 기존 단일 key 검사 유지 |
| 운영 템플릿 | `secops-execution-collector-ha@`·`secops-capture-health-ha@` service/timer와 선택형 metrics drop-in. 자동 설치/enable 없음 |

수집기는 SYS_PTRACE/DAC_READ_SEARCH 두 capability만, health는 capability0으로 동작한다. `ReadOnlyPaths`는 mount 보호이며 health의 공개 증거 읽기를 뜻한다. 같은 UID의 쓰기·키 접근을 전부 차단하는 독립 보안 경계라고 주장하지 않는다. 새 키 공급자에서는 추가 unit/PID 인증으로 **키 수령**을 제한한다. 서명키를 가진 승인된 수집기 자체의 침해나 root/커널 침해는 이 경로가 해결하지 않는다. 하나의 대상에는 수집 writer 하나를 배치한다.

## 실제 로컬 인수와 한계

초기 focus115개, 전달 경로120개, 강화된 초기122개는 별도 예비 결과다. 첫 native 실패는 안전한 거부 보고서에서 `credential_peer_cgroup`으로 확인했다. 정확한 hybrid 파싱 수정 후 고정 소스 `b65526cc758d397fae22fe06bda06ab17bf531a221a36ff9df93f5359df2baa9`의 집중134개와 실제 systemd10조건이 통과했다. 예비 시험과 최종 표본을 합산하지 않는다.

실제 조건은 별도 공급자 두 개의 capability0/NNP, 같은 UID의 다른 unit 키 수령 거부, 주 키 정상 수집, 주 프로세스/소켓 유실 후 다른 사전 승인 키 수집, 양쪽 중단 시 latest 불변·실제30초 초과 후 stale, 주 공급자 복구 후 새 근거, 이전 대기 근거 replay 거부, 잘못된 주 키에서 standby 우회 거부, 정확한 원래 키 복구, 명시적 관리자 폐기/pin 갱신 후 대기 키만 허용이다. target 서비스 재시작·grant/인가 재발급·자동 신뢰 변경은0이며, 소유 unit·프로세스·상태·소스는 정리했다.

위 결과는 프로세스/소켓 장애와 수집 상태 기능 인수다. 물리 호스트 이중화·실제 사람 SSO·호스트 전체 audit·배포 완료·원래 여섯 영역 독립 F1 목표 달성이 아니다. 신규 source를 기존1,681,815행 관측 개발 결과나 v87 같은 생성 계열 평가에 섞지 않는다. AWS/유료 API0, 사용자 유예한8/12시간 soak는 계속 유예한다. 통합 전체 시험·기존 결정 비교·PR/CI는 완료 후 아래에 별도로 기록한다.


## 최신 통합 인수 — 2026-11-16

고정 소스 `f714ea643220dc1629553fad4cdbc8f8651f3f5cb13a706458a1709c2d2dae18`에서 집중240개·전체6,122개·실제systemd10조건을 통과했다. 신규52개이며 실패/skip0이다. 집중은 전체의 부분집합이다. 같은 UID의 다른unit·다른MainPID·활성 상태/실행회차 불일치·PID 재사용·manager실패·hybrid경로 모호성을 포함한다. 예비115/120/122/134/146 결과를 최종 수에 합산하지 않는다. 부모 PR84는17개 검사 성공 후 aitest `29c5f1a`에 병합됐다.

실제 두 공급자의 UID1·capability0·NNP를 관측했고, 주 프로세스/소켓 유실 뒤 다른 사전 승인 키로 수집했다. 양쪽 중단에서는 latest 바이트 불변과 실제30초 경과 stale, 복구 뒤 새 근거와 과거 대기 근거 replay 거부를 확인했다. 잘못된 주 키는 살아 있는 standby로 우회하지 않았다. 단일 monitor ledger가 key 전환 전후 순서를 보존했다. target 재시작·인가 재발급·자동 pin 갱신은0이며, 명시적 관리자 폐기/pin 변경 시험은 구분했다.

공급자 메모리를 덤프해 다른 키의 부재를 관측한 것은 아니다. 새 Python exec와 단일 할당 key pipe의 코드 계약, 실제cap0/NNP 관측을 구분한다. 기존 수집기의SYS_PTRACE/DAC_READ_SEARCH 권한을 가진 센서와root/커널은 신뢰 경계다. 운영 계정/ACL·감독되는 장기 키 공급 수명·물리 이중화 인수는 남는다.

기존1,681,815행 판정 SHA는 동일하고 새FP·기존TP손실·정답 재열람0이다. 공유 감사F1 0%·웹 감사80.70%·인증95.08% 및 미달 재현율을 유지한다. 소유 unit/공급자/상태/소스/컨테이너 정리 완료, AWS/유료 API0·장기soak유예다. [코드·실제 흐름·실패와 최종 실행 근거](infrastructure-results/extra-collector-provider-ha-v91-20261116.json).
