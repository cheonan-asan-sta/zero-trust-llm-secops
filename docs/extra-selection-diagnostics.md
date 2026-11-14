# 선택 부하 검증의 안전한 오류 진단과 재현 인수 — v77

2026-11-14 · 기준 aitest `d9188cf006d88db20a7cec121b671377e1410f7d` · [v76](extra-capture-load.md)의 후속 인프라 작업이다.
기준 CI16개 성공은 실패한 selection/test의 일회 재실행 후 결과다. 최초34조건 뒤 runtime_command_failed_1 실패와 원인 미확인은 보존한다.
이번에는 오류 진단을 보강하고 실제 로컬 mTLS 프로필에서 정상·의도적 장애를 확인했다. 과거 실패의 정확한 원인을 소급해 찾았다고 주장하지 않는다.

## 결과

| 구분 | 확인한 결과 |
|---|---|
| 집중 진단 시험 | 100개 통과, 실패/skip0 |
| 로컬 전체 pytest | 5,491통과·0skip, Ruff+RUF100 통과 |
| 실제 정상 프로필 | 기존37조건 통과, 동시성1/4/8·3반복·27wave |
| 정상 부하 요청 | 576요청,153허용·423거부. gateway 장애3회 전달0, 새 grant 복구3건은 별도 |
| 실제 프록시 중단 | 16개 오류 행 보존, 오류 분류 io, 전달0·자동 재시도0 |
| 실제 작업자 중단 | 비정상 종료·command 단계/command_exit 기록, 공개 상태에서 operator 정지 확인 |
| 기존 판정 | 1,681,815행 동일, 새 FP0·TP 손실0·정답 재열람0 |
| 비용·정리 | API/AWS0, 소유 시험 container/volume/network와 단위 시험 container 정리 |

집중100개는 전체 시험의 부분집합이므로 합산하지 않는다. 정상37조건과 의도적 장애2조건은 목적과 결과 파일이 다르다.
정상 보고서 verification.json은 기존37조건/27wave를 유지한다. 의도적 실패 보고서는 completed=false·passed=false를 유지하며 diagnostics-acceptance.json이 그 실패의 올바른 관측을 판정한다.
첫 정적 실행은 잘못된 타입 인수에 ValueError를 쓴 TRY004에서 멈췄다. TypeError로 바로잡고 최종 고정 소스에서 집중/전체/실제 Docker를 검증했다. 초기 정적 실패는 기능 시험 실패로 집계하지 않는다.
보강 전 후보의 집중95/전체5,486통과는 개발 기록이다. 최종 boolean/terminal guard를 추가하기 위해 그 후보의 proxy를 명시적으로 중단하고 부분 native 실행을 종료했다. 이 중단을 자연 오류나 과거 CI 원인의 재현으로 계산하지 않는다. 최종 인수는 새 소스 지문·새 경로에서 수행했다.

## 이전에 무엇이 부족했는가

기존 command 래퍼는 비정상 종료 시 raw stdout/stderr를 공개하지 않고 runtime_command_failed_N만 남겼다. 이 비밀 보호는 유지하되, 부하 작업이 끝나기 전에 실패하면 요청 단계와 부분 응답을 잃는 문제를 보완했다.
실패는 counter_before → command/probe → counter_after → response_validation → replay_validation → health 순서로 저장한다. recovery/prepare 단계도 표시한다.
자원 전달 카운터를 읽지 못하면 delivered를0으로 만들지 않는다. 실패한 probe 뒤 카운터 조회도 실패하면 두 문제를 구분하고 먼저 관측한 probe 실패를 유지한다.
이미 있던 [bounded C01 진단](../scripts/monitoring_diagnostics.py)을 정리 전에 재사용한다. 소유 프로젝트의 실행/정지·재시작·OOM/종료 코드와 허용된 Prometheus 집계만 수집한다.

## 프로토콜과 비밀 보호

[infra_probe_diagnostics](../scripts/infra_probe_diagnostics.py)의 Pydantic strict envelope와 기존 중복 키/비유한 수 거부 decoder를 사용한다.
kind·동시성은 호출자가 요청한 값과 같아야 한다. 알 수 없는 필드, 틀린 타입/범위·행 순서·허위 완료·추가 헤더/본문은 게시하지 않는다.
완료 플래그는 strict boolean이므로 문자열 true/false를 자동 변환하지 않는다. 최상위 실패 envelope도 정해진 schema·실제 false·안전한 Failure만 허용하며 성공으로 바꾸거나 추가 stderr 필드를 받아들이지 않는다.
성공 응답은 HTTP상태·본문SHA256·확인한 TLS버전·지연과0~15 요청 순번을 남긴다. 원본 body나 grant/session 값은 남기지 않는다.
실패 응답은 상태·본문SHA·TLS버전이 null이며, 실패 단계·고정 오류 분류·요청 순번·관측 지연을 남긴다. null은 평문 연결이나403 응답을 의미하지 않는다.
오류 분류는 timeout/connection/tls_certificate/tls/http_protocol/io/invalid_data/runtime_control/internal 등 고정 값이다. 예외 str/repr·동적 클래스명·URL·헤더를 직렬화하지 않는다.
mint 단계에서는 성공한 발급 수와 안전한 HTTP상태만 보존한다. 부분 mint 실패 뒤 리소스 wave를 시작하지 않는다.
worker는 실패 metadata를 JSON으로 출력하고 exit1을 유지한다. 부모는 비정상 종료, probe 미완료, 프로토콜 거부를 모두 실패로 처리한다. 실제 전달 수가 맞아도 비정상 종료를 성공으로 바꾸지 않는다.
개별 행을 얻지 못한 최상위 실패도 작업자 단계와 고정 오류 분류를 보존한다. 행을 복원할 수 없는 경우 성공/거부 수를 지어내지 않는다.
후속 replay는 첫 wave의 전송 실패 뒤 실행하지 않는다. 개별 실패는 자동 재시도하지 않는다. 부분 성공이 있어도 기존 허용/거부·콘텐츠·TLS·재사용·health 검증을 완화하지 않는다.

범위는 입력1,024바이트, 게시 가능 report32KiB, wave16행, 동시성1/4/8이다. 원문 stdout은 RAM에서 포착하고 검증된 envelope만 게시하며 stderr는 버린다. 프로세스 stdout 전체 메모리 사용의 OS 하드 한도를 구현한 것은 아니다.
operator 호출120초와 기존 C01 진단20초 상한, 기존 mTLS·grant·정책/신선도 만료를 유지했다. TLS 검증 해제·권한 확대·인가 결과/탐지 변경을 하지 않았다.
Docker CLI timeout을 원격 exec 작업 전체의 취소 보장으로 해석하지 않는다. 실패 시 카운터는 그 시점의 관측 차이이며 이후 무활동을 증명하지 않는다. 인수 도구는 실패 후에도 소유 fixture를 정리한다.
비정형/초과/잘못된 출력은 고정 invalid_report로만 기록한다. 공개하지 않는 원문이 필요한 세부 원인은 별도의 비밀 보호 조사 절차가 필요할 수 있다.

## 실제 인수·재현

```text
python -m scripts.test_infra_selection_runtime --directory runtime/c02/새-정상-시험
python -m scripts.test_selection_diagnostics_runtime --directory runtime/c02/새-진단-인수
python -m pytest tests/test_infra_probe_diagnostics.py tests/test_infra_selection.py tests/test_monitoring_diagnostics.py -q
```

출력은 runtime/c02 아래 새 경로만 허용한다. 두 번째 도구는 기존 정상37조건 뒤 생성한 proxy/operator만 중단·복원한다. 프록시 중단은 실제 전송 오류, 작업자 중단은 고정 Docker exec의 exit 오류를 검증한다.
역사적 CI와 같은 실제 정상 시나리오를 새 이미지에서 실행했지만, 의도적 중단의 원인이 그 역사적 실패의 원인이라는 뜻은 아니다. 이번 원인 확정 값은 false다.
정상 보고서와 의도적 실패 기록·인수 결과를 구분하고 CLI 완료만으로 정상 부하 전체가 성공했다고 판단하지 않는다.

실제 시험은 기존 원본 Dockerfile로 앱 이미지를 만들고 source/release lock·이미지 안의 현재 파일 SHA를 검사했다. 공개 관측 도구 아카이브는 기존 캐시를 SHA검증해 재사용했다. 빌드/공개 이미지 확인의 네트워크와 실제 시험의 내부 Docker 네트워크를 구분한다.
로컬 source_commit은 분기 기준 커밋이고 source_dirty=true인 개발 트리다. 실제 시험 소스는 archive/file SHA로 고정하고 이미지 바이트와 대조했다. 이후 PR/병합 CI의 정확한 커밋과 결과는 최종 PR 기록·결과 문서를 따른다.
유료 LLM/AWS를 호출하지 않았고 API 키 파일을 읽지 않았다. 생성한 mTLS/자격 키는 기존 관리 흐름대로 RAM→전용 UID10001 볼륨에 전달하고 시험 자원과 함께 정리했다.
단위 시험은 캐시 이미지·network none·비root·read-only root·cap drop이다. 실제 mTLS14서비스는 internal network·비root·cap drop·읽기 전용 rootfs·게시 포트/host bind 없음 조건을 유지했다.

## 기존 결과와 남은 범위

| 항목 | F1 이전→이후 | FP 이전→이후 | FN 이전→이후 |
|---|---:|---:|---:|
| 공유 서버 감사 | 0%→0% | 24→24 | 6→6 |
| 웹 서버 감사 | 70.77%→70.77% | 37→37 | 1→1 |
| 인증 | 95.08%→95.08% | 0→0 | 3→3 |

고정 개발 판정 비교이며 새 독립 성능 평가가 아니다. 모델·규칙·정답·PDP/PEP를 수정하지 않았다. 진단은 접속 권한이나 자동 차단을 부여하지 않는다.
과거 CI의 정확한 원인은 미확인이다. 향후 자연 실패가 관측되면 이 안전한 단계/부분 응답/상태 자료로 조사한다. 반복 부하의 조건을 바꿔 과거 원인을 만들어 설명하지 않는다.
8~12시간 장기 시험, 실제 systemd 작업자 CPU/메모리 재측정·자원 한도 집행, 운영 SLO/RTO/RPO, 운영 키/외부 pin 보관·백업 일정/경보·원격 보관과 최종 인수 정리는 남아 있다.
이번 Docker 관측 자원 샘플을 이전 WSL systemd 작업자의 미측정 회계값 대신 사용하지 않는다. kernel 실행 이력·조직 SSO/앱 연결·새 독립 평가도 별도다.

- [공개 결과·소스/판정 지문](infrastructure-results/extra-selection-diagnostics-v77-20261114.json)
- [probe 구현](../scripts/infra_load_probe.py), [호출자 단계/실패 보존](../scripts/test_infra_selection_runtime.py), [실제 장애 인수](../scripts/test_selection_diagnostics_runtime.py), [진단 단위 시험](../tests/test_infra_probe_diagnostics.py)
- [Python subprocess](https://docs.python.org/3.12/library/subprocess.html#subprocess.run), [HTTP 예외](https://docs.python.org/3.12/library/http.client.html#http.client.RemoteDisconnected), [Pydantic extra 설정](https://docs.pydantic.dev/latest/api/config/#pydantic.config.ConfigDict.extra): 반환 코드/오류 종류/추가 필드 거부의 선정 근거다.

채희주 요청에 따른 Codex 보조 구현·실행·측정이며 팀원 독립 검토나 운영 승인으로 기록하지 않는다.
