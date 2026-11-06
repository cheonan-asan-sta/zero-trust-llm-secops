# CA 공유 DB 암호화 백업과 격리 복원 검증

2026-11-07 · 채희주 인프라 구성·실행·측정, Codex 도구 보조.

기존 선택 실행 경로의 DB 통신 키 교체·프로세스 복구에 CA 공유 PostgreSQL의 백업 검증을
연결한다. 백업 파일이 생성됐다는 확인에서, **암호문을 인증하고 별도 PostgreSQL에 실제로
복원한 뒤 토큰 소비·폐기·발급 기록과 DB 식별자가 일치하는지 확인**하는 절차로 확장한다.
운영 DB에 과거 덤프를 덮어쓰는 명령은 제공하지 않는다.

## 실행 경계

| 항목 | 구현 |
|---|---|
| 선택 프로필 | 기존 18서비스·10내부망에 백업 암호문/키 볼륨 2개 추가, 총39볼륨. 기존37볼륨 프로필 유지 |
| 관리 충돌 | CA/DB 교체·시작·종료·purge와 같은 호스트 OS 잠금. 백업 중 일반 시작/종료·교체 거부 |
| 작성자 정지 | 원래 leaf pause 기록 → pause 확인 → 고정 ID의 양 CA 정지 → `secops_ca` DB 세션0 확인 |
| 백업 형식 | `pg_dump -Fc --no-owner --no-privileges`, 전체 `stepca` DB의 custom archive |
| 보관 | 기존 AES-256-GCM 형식 재사용. 프로젝트·고정 프로필 지문·백업 ID·시각·보안 테이블 지문을 AAD로 인증 |
| 키 분리 | 별도 UID10001 Linux 키 볼륨. 온라인 서비스·복원용 PostgreSQL에는 연결하지 않음 |
| 복원 장소 | 고정 PostgreSQL 이미지, network none, 포트 없음, 비root, 읽기 전용 rootfs, capability 제거, tmpfs만 사용 |
| 복원 제약 | CPU1·메모리256MiB·PID64, 컨테이너 swap 비허용, Docker 로그 저장 비활성화. 운영 볼륨/호스트 bind/socket 없음 |
| 실행 SQL | `pg_restore --exit-on-error --single-transaction --no-owner --no-privileges`, 새 격리 DB에만 입력 |
| 일치 검사 | `used_ott`, `revoked_x509_certs`, `x509_certs`, `x509_certs_data`, `runtime_guard.anchor`의 행수·정렬된 행 SHA-256 |
| 발급 재개 | 복원 검증과 live DB 지문 보존 확인 후 같은 CA 재시작 → 새 mTLS DB 접속 확인 → 원래 leaf pause 복원 |

덤프·복호화 데이터는 파이프와 신뢰 호스트 RAM을 거친다. Windows 작업 폴더·명령행 인자·공개
보고서에 평문 덤프나 키를 저장하지 않는다. 호스트 관리자·Docker 관리자·프로세스 메모리 접근은
기존 신뢰 경계에 포함된다. 백업 키도 같은 Docker 호스트에 있으므로 두 볼륨의 분리는 물리적
재해 복구나 원격 키 보관을 의미하지 않는다.

## 중단과 재개

`quiescing → stopped → sealed → verified → resuming → complete`를 공개 journal에 기록한다.
백업 게시 후 다음 journal 저장 전에 실행기가 사라져도 같은 ID·AAD의 암호문을 먼저 확인한다.
인증된 기존 파일이 있으면 덤프를 새로 만들거나 덮어쓰지 않는다. 암호문 지문이 기록된 뒤에는
그 지문도 일치해야 한다. 복원 도중 중단된 격리 컨테이너는 이름·프로젝트/백업 label·이미지·명령·
망·mount·권한·자원 제한을 모두 확인한 뒤 제거하고 새 tmpfs DB에서 검증을 다시 수행한다.

검증 전 실패하면 양 CA의 발급을 계속 중지한다. 원래 pause 상태를 무조건 false로 바꾸지 않는다.
백업 완료는 과거 snapshot의 복원 검증이며, 이후 발생한 폐기나 토큰 소비를 포함한다는 뜻은 아니다.
`status`는 읽기 전용 journal 조회로, 현재 서비스 health나 백업 최신성을 인증하지 않는다.
상위 `phase/epoch/recovery_required`는 기존 DB 통신 교체 상태다. 백업은 별도 `backup.phase`를
확인하며 `absent/complete` 이외이면 `resume`이 필요한 상태다. `isolated_restore_verified`가 true여도
`resuming`이면 CA/leaf 복귀가 아직 끝나지 않았을 수 있다.

백업 한 개의 압축 덤프는32MiB, 보호 테이블은 각각10만 행, 저장소는16개 archive로 제한한다.
자동 삭제·보관기간 관리·키 갱신·스케줄러 등록은 이번 범위에 없다. 새 백업은 발급을 멈추기 전에
키 접근과 잔여 슬롯을 검사하므로 보관 한도에 도달한 요청은 기존 발급 상태를 유지하며 거부한다.
진행 중 파일/키 오류로 중단되면 원인을 해결하고 같은 작업을 재개해야 한다. 임의로 journal을 지워 발급을
재개하지 않는다. `--purge`는 로컬 시험 환경과 그 백업을 모두 폐기하는 명시적 작업이다.

## 로컬 사용

기존 descriptor를 새 프로필로 자동 변환하지 않는다. 새로운 시험 directory에서 시작한다.

```powershell
.venv/Scripts/python.exe -m scripts.database_backup_runtime up --directory runtime/c02/my-db-backup
.venv/Scripts/python.exe -m scripts.database_backup_runtime backup --directory runtime/c02/my-db-backup
.venv/Scripts/python.exe -m scripts.database_backup_runtime status --directory runtime/c02/my-db-backup
# 중단된 동일 백업만 재개; 완료된 작업이면 새 백업을 만들지 않음
.venv/Scripts/python.exe -m scripts.database_backup_runtime resume --directory runtime/c02/my-db-backup
# 기존 자동 교체 실행기는 이 프로필을 인식한다. 실행 중에는 관리 잠금을 계속 보유한다.
.venv/Scripts/python.exe -m scripts.database_transport_runtime once --directory runtime/c02/my-db-backup
# 시험 종료. 백업/키를 포함한 해당 프로젝트 볼륨도 삭제한다.
.venv/Scripts/python.exe -m scripts.database_backup_runtime down --purge --directory runtime/c02/my-db-backup
```

## 검증과 근거

최초 소스의 Linux2458개 통과 후 재시작 프로필/보관 한도 보완으로 입력 지문이 달라져 후속
단계를 차단했다. 다음 고정 소스 묶음은 Linux2462개·관측75개를 통과했지만 통합 인수는58개 뒤
발급 재개 직전 오프라인 설정 검사에서 중단됐다. 두 실행과 정리0을 원자료에 보존한다.

중단 journal은 `resuming/verified=true`로, 격리 PostgreSQL 복원과5테이블 대조를 마친 상태였다.
당시 폐기된 collector의 만료 시각은 진단 수집보다5.34초 이전이고 활성 신원에는 최소125초가
남아 있었다. 하위 helper의 원래 오류는 일반 검증 실패로만 기록돼 원인 전체를 단정하지 않는다.
다만 기존 검사에서 폐기 client의 만료만으로 전체 오프라인 인수가 거부되는 경계를 별도로 재현했다.

보완은 명시적 disabled client·`status=disabled`·진행 중 후보 없음·기록된 모든 peer pin 제거를
확인한 보관 기록에 한정한다. 서명·키 일치·권한·현재 지문 검사는 그대로이며 미래 인증서와
활성 인증서의 만료는 거부한다. TLS/인가/재발급에 만료 예외를 추가하지 않는다. 긴 인수에서는
멈춰 둔 활성38신원만 정상 mTLS 갱신 후 백업을 검사하고, 폐기된 수집기는 다시 발급하지 않는다.

추가로 암복호화 도우미도 `--log-driver none`과 memory=memory-swap을 사용해 복호화 출력의
Docker 로그 저장과 컨테이너 swap을 차단한다. 호스트 RAM/관리자 신뢰 경계는 유지한다.
최종 집중 검사는287개(이번 변경의 신규59개)가 통과했다. 이후 실제 백업 집중 인수와 도우미 로그
검증, 정확한 PR head/병합 CI를 구분해 기록한다. 기존 전체 묶음을 최종 소스의 전체 통과로 바꾸지 않는다.

격리 PostgreSQL 사전 확인은 합성5테이블·5,249바이트 custom dump의 지문 일치/11.09초였다.
운영 RTO나 실제 전체 백업 소요시간이 아니다.

```powershell
.venv/Scripts/python.exe -m scripts.test_infra_preflight_batch
```

전체 Linux 회귀 → 관측75개 → 기존 CA/DB 교체54개와 백업·만료 경계13개를 합친67개 인수를 순차 실행한다.
새 인수는 암호문 게시 직후 실제 자식 프로세스 강제 종료, 같은 archive 재사용, 변조 거부와 발급
중지 유지, 실제 격리 복원, 원본 DB/객체/pause 보존, 두 백업의 독립 검증, 재시작과 정리를 포함한다.
CI는 기존 여섯 실행 경로를 유지하고 백업 프로필을 별도 작업으로 검증한다.

## 완료로 확대하지 않는 항목

- PostgreSQL role/ACL·전역 객체까지 포함한 cluster 복구: 이번 덤프는 단일 DB이고 owner/ACL 재현을 생략한다.
- 임의 모든 DB 객체의 의미 검증: 덤프 전체를 복원하지만 별도 동등성 대조는 위5개 보안 테이블에 한정한다.
- CA root/JWK/leaf 키·앱 DB·감사 저장소를 포함한 전체 서비스 재해 복구 또는 DB 물리 이중화.
- 백업 이후의 최신 폐기 기록과 대조하는 독립 witness, 운영 DB live restore, 롤백 방지 외부 checkpoint.
- 정기 자동 백업·보관기간/용량 관리·키 escrow/교체·호스트 전원 손실·Docker 데몬 종료 인수.
- 김택희의 앱 저장 의미 검토/독립 재현, 탐지 정밀도·재현율·F1 개선 또는 운영 SLA 달성.

이전 PR42의 CA 검사 중단1회는 원인 미확정으로 [기존 기록](database-transport-process-recovery.md)에
남아 있다. 이번 백업 기능으로 그 원인을 해결했다고 표현하지 않는다.

설계 근거: PostgreSQL17 [pg_dump](https://www.postgresql.org/docs/17/app-pgdump.html)는 일관된 단일 DB
snapshot과 custom archive를 제공한다. [pg_restore](https://www.postgresql.org/docs/17/app-pgrestore.html)의
오류 즉시 종료/단일 transaction을 사용한다. 덤프 복원은 원본에서 정의한 SQL 코드를 실행할 수 있으므로
비밀·운영 데이터·망에서 분리된 서버에 복원한다.

## 최종 로컬 확인

보완 소스의 **집중287개(신규59), 백업·만료 경계13/13, 실제 암복호화 도우미2작업**이 통과했다.
최종13개 인수에는 실제 프로세스 강제 종료1회, 동일 archive 재개, 암호문 변조 거부, 격리 PostgreSQL
복원3회, 정상 재시작 후 새 백업과 과거 백업 검증이 포함된다. 만료 대조는 검사 프로세스의 시각만
제어했으며, 실제 TLS·인증서 TTL·운영 시각을 변경하지 않았다. 단위 검사는 실제 만료된 인증서를 사용한다.

13개 집중 인수의 기동·정리 포함 관측 시간은672.49초다. 운영 RTO가 아니다. 모든 소유 컨테이너/볼륨/망0, 기존 kind/Engine·ZIP2개 보존을 확인했다.

[공개 원자료](infrastructure-results/database-backup-verification-20261107.json)에 최초 Linux2458,
다음 Linux2462/관측75/통합58 중단, 이후 바뀐6파일과 최종 소스 지문·집중 결과를 구분했다.
두 이전 Linux image의 실제 파일 바이트도 다시 대조했다. 최종 소스 전체 회귀와67개 통합 인수는
정확한 PR head 및 병합 후 CI에서 별도로 확인하고 PR 본문에 기록한다. 이전2462를 최종 전체
회귀로 바꾸거나 미실행 검사를 합산하지 않는다.
