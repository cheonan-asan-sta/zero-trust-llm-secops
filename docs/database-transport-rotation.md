# DB 통신 root·서버·client 키 자동 교체와 중단 재개

2026-11-07 · 채희주 인프라 구성·실행·측정, Codex 도구 보조.

[PR40 사전 점검](infrastructure-preflight-batch.md) 다음 단계다. 기존 업무용 CA/JWK 교체·
CA 두 노드·공유 PostgreSQL·Linux 보관함·서명 계획·로컬 묶음 검증을 재사용한다.
업무용 root와 DB 전송 root는 독립적으로 관리하고, 앱·탐지·정책·평가 데이터는 유지한다.

## 기존에서 달라진 동작

| 경계 | PR40 | 이번 선택형 프로필 |
|---|---|---|
| DB 전송 인증서 | 고정2일 fixture·만료/권한 사전 점검 | root30일·서버/client7일,24시간 주기 또는 만료 여유1일에 전체 키 교체 |
| root 개인키 | 초기 RAM 이후 폐기 | 별도 암호화 보관함, 온라인 서비스에는 미마운트 |
| 동적 신뢰 | 최초 파일 지문 고정 | 최초 승인 root에서 검증한 서명 계획·세대·이전 계획 hash로 이행 |
| 적용 경계 | 수동 새 프로필 | leaf 발급 제어기 일시 정지·양 CA/DB 정지 확인 후 게시·같은 객체 재시작 |
| 중간 종료 | 자동 교체 없음 | 이미 승인한 후보를 보존하고 같은 컨테이너 ID·볼륨에서 단계 재개 |
| 검증 | 관측75·기존 CA/DB38 | 기존38에 타이머·중단/재개·구 신원 거부·DB 상태 보존 등10개 추가 |

새 프로필은18서비스·10내부망·37볼륨이다. 추가한 볼륨은 `database-transport-vault` 하나다.
기존36볼륨 프로필과 기존 descriptor를 자동 승격하거나 사용자 키/데이터를 이관하지 않는다.

## 실행

```powershell
.venv/Scripts/python.exe -m scripts.database_transport_runtime up --directory runtime/c02/my-db-rotation
.venv/Scripts/python.exe -m scripts.database_transport_runtime run --directory runtime/c02/my-db-rotation
.venv/Scripts/python.exe -m scripts.database_transport_runtime status --directory runtime/c02/my-db-rotation
.venv/Scripts/python.exe -m scripts.database_transport_runtime preflight --directory runtime/c02/my-db-rotation
```

`run`은 신뢰된 로컬 호스트에서 계속 실행하는 foreground 조정기다. root·서버1개·client2개와
각 개인키를 한 묶음으로 자동 교체한다. 자체 호스트 service 설치/OS 자동 시작 설정은 포함하지 않는다.
`tick`은 한 단계, `once`는 현재 필요한 DB/업무 CA 작업이 idle이 될 때까지 실행한다.
기한 전 idle에서는 무거운 Docker helper를 실행하지 않는다. 예시 주기/유효기간은 운영 조직이
승인한 수명 정책이 아니다. 실패하면 후보를 새로 만들거나 rollback하지 않고 중단하며,
같은 프로필에서 `tick/once/run`으로 다시 실행해야 한다. 만료를 넘긴 현재 신원은 자동 부활시키지 않는다.

## 신뢰와 게시 순서

1. 현재 release·설정·서명 이력·볼륨 소유권과 고정한 leaf/CA/DB 객체를 대조한다.
2. 기존 공통 lease를 잡고 업무 CA 교체가 idle인지 확인한다. leaf 제어기의 원래 pause 값을 보존한다.
3. leaf 발급이 정지한 뒤 network=none 작업이 독립 전송 root·세 leaf/개인키를 만들고 암호화한다.
   이전 root가 새 root와 모든 파일 hash·고정 policy·epoch·이전 계획 hash를 서명한다.
4. 양 CA와 DB를 실제 정지한 것을 확인하고 승인한 파일만 각 Linux 볼륨에 게시한다.
   파일 단위 임시 기록·fsync·rename을 재사용한다. 여러 볼륨 전체의 원자적 변경을 주장하지 않는다.
5. 동일 DB → 동일 CA 두 노드를 순서대로 시작한다. DB anchor·등록/nonce/폐기 테이블,
   양 CA의 실제 health와 새 인증서로 생성한 DB TLS/인증 연결을 검증한다.
6. 성공한 후보만 완료하고 이전 암호화 묶음을 정리한 뒤 원래 leaf pause 값으로 복귀한다.

교체 중 DB/양 CA의 새 발급은 잠시 중단된다. 업무 데이터 plane을 함께 정지하지는 않지만,
기존 접근의 계속 성공은 각 인증서/토큰의 정상 유효기간과 해당 서비스 상태에 달려 있다.
무중단 교체·DB 복제·물리 호스트 HA·운영 RTO/RPO 보장이 아니다.

진행 기록은 `database-transport-journal.json`이다. 진행 중 일반 `up/down`은 거부하고
고정 객체의 작업으로 먼저 재개한다. 부분 게시에서는 파일마다 이전/승인 후보 hash만 인정하며,
새 프로필/컨테이너 ID·다른 key·정책 확장·변조된 서명·누락 이력은 거부한다.
모든 게시 파일이 완전한 새 쌍이 된 뒤 실제 연결을 검사하며, 실패한 live 검증으로 완료하거나
제어기를 풀지 않는다. 객체 자체 삭제/DB 유실은 자동 재승인하지 않는다.

보관함에는 암호화된 현재/승인 후보와 로컬 password가 존재한다. 이는 소프트웨어 격리 경계다.
호스트 관리자·RAM·password까지 신뢰하며 HSM·악성 root 방어·외부 anti-rollback을 제공하지 않는다.
온라인 CA/DB/leaf에는 보관함과 Docker socket이 없다. 공개 검증은 vault 없이 세 TLS 볼륨만 RO로
마운트한다. 비밀 작업은 network=none·UID10001·RO rootfs·capability 제거·자원/시간 제한을 사용한다.
완료 후 파일 unlink는 RAM·백업까지 복구 불가능한 소거라는 뜻이 아니다.

DB의 `verify-full`·client `cert` 인증·제한 role과 기존 공개 사전 점검을 유지한다. 근거는
[PostgreSQL17 서버 TLS](https://www.postgresql.org/docs/17/ssl-tcp.html),
[서버 이름 검증](https://www.postgresql.org/docs/17/libpq-ssl.html),
[인증서 로그인](https://www.postgresql.org/docs/17/auth-cert.html)이다.
기동 후 검사는 실제 새 연결이며 기존 pooled connection만으로 성공 처리하지 않는다.
전체 관리 저장소를 동시에 과거로 되돌리는 공격은 별도이며 이력64세대/4MiB를 넘으면 거부한다.

## 묶음 검증

```powershell
.venv/Scripts/python.exe -m scripts.test_infra_preflight_batch
```

한 번의 고정 소스 실행에서 전체 Linux Ruff/pytest → 관측75 → 기존 CA/HA38을 포함한 새48개
인수를 수행한다. CI에는 새 인수를 별도 병렬 job으로 추가하고 기존 앱 전체 복구24·관측75·CA30·
leaf22·CA/HA38·Lambda를 유지한다. 소스/엔진 변경·잘못된 image payload·부분 성공·정리 누락은
통과로 집계하지 않으며 자동 재시도는 없다.

실제 시험은 원래 정상 DB client가 인증되는 양성 대조를 먼저 수행한다. 교체 후에는 서버 신뢰를
현재 root로 고정하고 아직 유효한 구 client만 제시해 거부를 확인한다. 구 서버 신뢰의 불일치가
client 폐기를 가리지 않게 한다. 시험용 구 키는 Linux 볼륨에서만 다루고 종료 시 정리한다.
nonce/폐기 행의 정렬된 내용 지문, workload CA epoch3·leaf 지문·회수 신원 보존도 대조한다.

최종 수치는 [공개 원자료](infrastructure-results/database-transport-rotation-20261107.json)와
해당 PR의 정확한 head/병합 후 CI로 기록한다. 예정48개를 완료 전에 통과로 기록하지 않는다.
AWS·유료 모델 호출 없이 로컬/기존 공개 저장소 CI를 사용하고 kind·사용자 ZIP은 보존한다.

DB/물리 호스트 HA·전체 백업 복원 통합·장기 signed checkpoint·침해된 root 신뢰 복구·native 즉시
폐기/기존 TLS 세션 종료·실제 JSONL writer/path 연결·김택희의 독립 인수는 후속이다.
이번 결과를 탐지95% 달성이나3주차 전체 완료로 표현하지 않는다.

## 최종 로컬 결과와 소스 구분

첫 고정 소스 묶음은 Linux2383통과/기존 경고2·관측75/75 후 새 인수46개에서 중단됐다. 두 전송 세대와 정상 재시작까지 통과했고 서명 변조도 거부했지만 InvalidSignature가 공통 LifecycleError로 변환되지 않아 검사기가 최종 거부/복구 검사를 마치지 못했다. 소유 자원0이며48개 통과로 바꾸어 기록하지 않는다.

이후 서명 예외를 고정 오류로 통일하고, prepare/install/commit helper에 같은 프로젝트 고정 이름을 부여해 살아 있는 이전 helper가 다음 쓰기 작업을 차단하도록 했다. 검증 helper는 vault/고정 쓰기 이름이 없다. Docker의 실제 이름 충돌125·해제 후 성공0·정리0과 최종 인자 회귀를 확인했다. 시험용 강제 실행은 정상 host refresh의5분 대기만 생략하며 운영 policy/period/margin은 유지한다.

전체 로컬 회귀·관측을 다시 반복하지 않고 변경 경계의 집중229개/Windows POSIX1 제외·신규47개와 고정 Ruff0.17.3, 최종 소스의 실제 인수48/48을 별도로 확인했다. 기존38개를 포함한48개 모두 최종 image/source/release 지문을 대조했고 소유 컨테이너/볼륨/망0·두 ZIP/기존 kind·앱/동료 코드 보존을 확인했다. 초기/최종 소스와 공개 anchor를 원자료에 구분한다. 최종 소스의 전체 Linux2387과 모든10개 job 증거는 해당 PR의 정확한 head/병합 후 CI를 따른다. AWS/유료 모델 호출0.
