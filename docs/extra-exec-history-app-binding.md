# 실행 당시 이력과 호출 신원 및 앱 정책 연결

2026-11-15 · v82 · 로컬 구현·묶음 검증 완료 · GitHub 미업로드·미병합

기존 실행 중 프로세스 수집에 더해, 관리자가 고정한 일회 작업의 첫 성공 exec를 커널 ptrace 정지 시점에 관측하는 선택형 경로를 추가했다. 요청에 결속한 로컬 OIDC 신원과 앱의 현재 세션·일회용 접근권한을 모두 확인한 뒤 실행한다. 짧게 실행되고 끝나는 프로세스도 종료 전에 지문을 확보한다. 기본 앱 API나 탐지 임계값을 변경하지 않는다.

채희주의 인프라 실행·측정 범위를 Codex가 보조 구현·실행했다. 팀원의 독립 검토나 실제 운영 승인을 완료한 기록이 아니다.

## 처리 순서

1. 기존 `ServiceCallerBroker`가 고정 tenant/server/unit·실행 파일/명령 SHA·nonce·만료를 가진 요청을 발급한다. 인증원은 운영자 pin으로 고정하며 사용자 입력 키 URL을 조회하지 않는다.
2. `AppExecutionGate`는 요청 결속 ID token의 person과 앱 인증 `Principal`의 tenant·subject를 일치시킨다. 앱 responder 역할, 정확한 자원·행위와 관리자 고정 명령을 요구한다. ID token을 API bearer token으로 쓰지 않는다.
3. 기존 `ZeroTrustOperations.access`가 현재 세션의 소유자·정책·신호 출처·회수·만료·기존 사용을 확인하고 접근권한을 한 번 소비한다. 서버 전용 `execution_request_sha256`를 기존 해시 체인 access 이력에 추가해 브로커 영수증과 연결한다. 일반 API 입력에는 이 필드를 추가하지 않았다.
4. 시작 직전 세션 버전·허용 상태·정책 SHA와 신호 출처를 다시 검사한다. 앱 정책과 독립 서비스 정책 레지스트리 SHA가 달라지면 시작하지 않는다. 기본은 `verified_source` 세션만 받는다. fixture의 서명 신호도 실제 EDR 기기 검증을 뜻하지 않는다.
5. `HistoryUnitLauncher`는 관리자에게 이미 설치된 비활성 allowlist unit만 시작한다. HTTP 요청으로 argv·키·파일 경로·unit 생성 명령을 받지 않는다. 고정 argv와 요청의 임시 입력은 0700 관리자 디렉터리의 0600 단일 파일에만 놓인다.
6. worker는 systemd MainPID가 자신인지 확인한다. 하위 프로세스를 별도 nobody UID·빈 추가 그룹·NoNewPrivileges·권한 capability 0으로 낮추고, 성공한 `PTRACE_EVENT_EXEC` 정지에서 실제 `/proc`를 읽는다. boot·invocation·PID·시작 tick·UID와 파일/명령 SHA를 결속하고 별도 runtime 키로 서명한다. 명령 원문은 capture에 쓰지 않는다.
7. 프로세스가 종료된 뒤에도 서명된 event/proof를 읽고 기존 별도 정책 proof와 검증한다. 브로커 영수증의 요청 SHA와 앱 access 이력을 대조한다. 실행 실패·증거 누락은 uncertain이며 앱 접근권한을 환급하거나 자동 재시작하지 않는다.

## 범위와 한계

- 이번 수집은 관리자가 지정한 **관리 경로의 첫 exec**에 한정한다. 호스트 전체 auditd/EDR, 모든 자식의 명령 이력·네트워크 목적지나 비관리 실행의 수집이 아니다. ELF 실행 파일과 정확한 cmdline 지문이 맞아야 한다. 스크립트의 인터프리터·후속 exec가 달라지면 원래 명령으로 승인하지 않는다.
- 로컬 WSL은 CONFIG_AUDIT/AUDITSYSCALL이 있지만 읽기 전용 AUDIT_GET가 EPERM이었다. 호스트 audit 설정·전역 규칙을 바꾸지 않았다. 실제 시스템 전체 감사 수집을 완료했다고 쓰지 않는다.
- tracer는 자식의 다른 UID를 관측하기 위한 root/CAP_SYS_PTRACE 등 제한된 권한을 요구한다. 대상 자식은 비root이지만 tracer 자체를 비root 수집기로 표현하지 않는다. static unit·브로커·커널·운영자 저장소는 신뢰 경계다.
- 실제 systemd255.4에서 명시적 `User=root`와 NoNewPrivileges 조합의 tracer는 CAP_SETUID가 없어 자식 UID 전환에 실패했다. 같은 제한을 유지하고 시스템 서비스의 기본 UID0을 사용한 후 실제 실행에 성공했다. CAP_KILL도 소유한 다른 UID 자식 정리에 필요했다. 대상 자식은 UID65534·NoNewPrivileges1·CapEff0을 계속 요구한다. [관련 upstream 보고](https://github.com/systemd/systemd/issues/44778)는 다른 버전의 유사 증상이며 현장 재현 결과와 구분한다.
- `ptrace_exec`와 `ptrace_exec_lab`를 별도로 검증한다. lab 근거로 systemd 권한을 충족할 수 없다. 초기 exec 정지는 실행 당시 관측이며 원격 attestation이나 사람의 현장 존재를 증명하지 않는다.
- 권한 확인과 OS 실행은 분산 트랜잭션이 아니다. 시작 직전 재검사를 제공하지만 이미 실행한 작업의 즉시 중단이나 소급 취소를 보장하지 않는다. 고위험 명령의 기존 2인 승인 계약을 대체하지 않으며 임의 관리 명령을 새로 허용하는 API도 없다.
- 접근 허용은 관측 결과가 아니라 실행 **이전**의 앱 정책을 따른다. allow 근거로 기존 경보를 지우지 않는다. 과거 공개 로그에 없는 신원·실행 정보를 사후 채우지 않는다.
- 조직 SSO·실제 기기 신호·운영 설치·다중 호스트 합의·원격 rollback 방지·독립 성능 평가와 8시간 연속 시험은 별도다. 장기 시험은 유예를 유지한다.

## 구현과 재현

| 파일 | 역할 |
|---|---|
| [실행 당시 관측](../scripts/f1_lab/exec_history.py) | 소유 자식의 초기 exec 정지·현재 프로세스 지문·실행 회차 결속 |
| [앱 정책 어댑터](../scripts/f1_lab/app_execution_gate.py) | 신원 일치·앱 일회용 grant 소비·실행 직전 재검사 |
| [고정 unit 어댑터](../scripts/f1_lab/exec_history_launcher.py) | 제한 입력·출력 파일과 기존 unit 시작 |
| [worker](../scripts/collect_exec_history.py) | LoadCredential 키 공급과 근거 출력 |
| [선택형 설치 템플릿](../infra/systemd/secops-exec-history@.service) | 고정 경로·제한 권한·비활성 기본값. 실제 운영 설치·enable은 하지 않음 |
| [로컬 인수 실행기](../scripts/run_exec_history_controls.py) | 로컬 신원·서명 앱 신호 fixture와 실제 systemd/ptrace 연결 |

```text
python -m scripts.run_exec_history_controls --directory <존재하지 않는 결과 디렉터리>
```

실제 systemd가 PID1인 로컬 Linux/WSL root 인수용이다. 실행기는 UUID 소유 unit과 /run 디렉터리만 만들고 정리한다. 정적 설정의 임시 argv 파일과 테스트키도 정리 대상이다. 실제 계정 인증·운영 배포나 장기 시험으로 보고하지 않는다.

신뢰하는 서버 코드의 연결 예시는 다음과 같다. `principal`은 기존 앱 인증 결과이며 클라이언트가 자칭하는 subject/role 객체가 아니다. target·launcher·sign_current_policy는 운영자 설정이다. 기본 어댑터는 내부 READ만 받으므로 고위험 승인 API의 대체 경로로 사용하지 않는다.

```python
gate = AppExecutionGate(
    broker, operations, AppExecutionTarget(target, "zt-demo-documents", "READ"),
    request, principal, protected_access, id_token,
)
receipt, event, proofs = gate.dispatch(history_launcher, sign_current_policy)
```

## 검증과 기존 지표 비교

| 검증 | 최종 결과 |
|---|---|
| 코드 검사 | 전체 Ruff와 RUF100 통과 |
| 집중 Linux | 308개 통과, 전체의 부분집합 |
| 전체 Linux | 5,672개 통과, 실패·skip0 |
| 실제 systemd·ptrace | 11조건 통과. 짧은 프로세스 종료 후 근거 유지·일회용 grant·신원 결속·재사용/회수 거부 |
| 기존 판정 대조 | 1,681,815건 전후 결정 SHA 동일, 새 FP0·기존 TP 손실0·라벨 재열람0 |
| 환경·정리 | network none 비root Docker 회귀와 별도 WSL root native 구분. 소유 컨테이너·unit·개인키/임시 argv 상태·스냅샷 정리 |
| 비용 | AWS·유료 API0, 운영 배포0, 8시간 시험 미실행·유예 |

모두 같은 최종 소스 archive `d44d36e0d8267cbda6f32c1023b63551965e356caefd358902385a442e16ec36`를 사용했다. 보고서 문구와 결과 JSON만 검증 후 갱신하며 코드·설정 지문은 [공개 결과](infrastructure-results/extra-exec-history-app-binding-v82-20261115.json)에 고정했다.

| 개발 기준선 | F1 이전→이후 | FP 이전→이후 | FN 이전→이후 |
|---|---:|---:|---:|
| 공유 서버 감사 | 0%→0% | 24→24 | 6→6 |
| 웹 서버 감사 | 70.77%→70.77% | 37→37 | 1→1 |
| 인증 | 95.08%→95.08% | 0→0 | 3→3 |

위 지표는 유지된 개발 기준선이며 새 독립 채점이 아니다. 새 관리 경로의 기능 인수를 과거 공유 서버 6건의 탐지 개선이나 실제 사람·기기 인증 완료로 바꾸지 않는다.

최초 native 기동 실패를 발견해 최초 전체 회귀를 중단했고, 집중 302개 통과와 중단 exit137을 보존했다. 이후 UID 전환 실패를 단계/errno와 CapEff로 좁혔으며 소유 PID 정리·재사용 방지와 CAP_KILL을 보강했다. 명시적 User=root 설정을 제거한 대조에서 native11조건이 통과했고, 최종 소스에서 집중/전체/native/판정 비교를 다시 묶었다. 중간 실패를 성공으로 덮어쓰지 않으며 반복 집중 수를 합산하지 않는다.


다음은 새 관리 경로의 근거를 기존 보관·백업 흐름에 연결하는 작업과, 운영 전용 계정·허용 명령·키 공급 및 실제 조직 SSO의 인수다. 기본 fixture UID65534와 로컬 서명 신호를 그대로 운영 환경의 신뢰 근거로 사용하지 않는다. 호스트 전체 감사 수집과 새 독립 성능 평가는 별도로 남는다.

## 선정 근거

[Linux ptrace 문서](https://man7.org/linux/man-pages/man2/ptrace.2.html)의 TRACEEXEC 정지와 EXITKILL을 사용한다. 대상의 사용자 코드가 진행되기 전 관측할 수 있어 주기 snapshot의 짧은 프로세스 누락을 줄이는 관리 경로로 선택했다. OS 전체 감사 수집의 대안 완료라는 의미는 아니다. 기존 [신원 결속](extra-systemd-caller-identity.md)·[서명 및 별도 정책 검증](extra-shared-execution-evidence.md)·앱 access 원장을 재사용하며 별도 토큰 발급 체계를 만들지 않았다.
