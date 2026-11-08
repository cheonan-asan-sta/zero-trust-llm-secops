# CA DB 복원 체크포인트와 과거 보안 상태 거부 검증

2026-11-08 · 채희주 인프라 구성·실행·측정. 로컬 Docker 인수17개와 최종 Linux2520개 통과.
정확한 PR head와 병합 후 CI 증거는 해당 PR 본문에 별도로 기록한다.

기존 암호화 백업·격리 복원에 **마지막 명시적 정지 체크포인트와의 보안 상태 대조**를 추가했다.
이후 인증서를 폐기하고 새 체크포인트를 기록하면 과거 백업은 암호문이 유효해도 SQL 복원 전에
거부한다. 최신 백업은 별도 PostgreSQL에서 실제 복원해 검증한다. 운영 DB에 덮어쓰는 명령은 없다.

## 구성과 처리 순서

| 항목 | 구현 |
|---|---|
| 선택 프로필 |18서비스·10내부망·41볼륨. 기존39볼륨 백업 프로필에 체크포인트/키 볼륨2개 추가 |
| 키와 저장소 |백업과 다른 AES-256-GCM 키. 온라인 서비스는 체크포인트/키 볼륨을 연결하지 않음 |
| 작성자 정지 |기존 관리 잠금 → leaf pause 확인 → 고정 CA2개 정지 → CA DB 세션0 → 보안5테이블 지문 |
| 체크포인트 |프로젝트·목적·순번·이전 지문·백업 manifest를 인증해 원자적으로 게시 |
| 호스트 기준 |신뢰하는 descriptor의 순번/지문과 대조. 삭제·변조·다른 프로젝트·되돌린 볼륨 기록 거부 |
| 중단 재개 |게시 직후 호스트 저장 전에 중단되면 정확히 같은 다음 기록만 채택. 재시작 시 순번 유지 |
| 과거 백업 평가 |백업 암호문 인증 → 마지막 체크포인트의 보안 상태와 일치 확인 → 격리 SQL 복원 |
| 일치 대상 |used_ott·revoked_x509_certs·x509_certs·x509_certs_data·runtime_guard.anchor의 행수/정렬 행 SHA-256 |
| 복원 경계 |network none·비root·읽기 전용 rootfs·capability 제거·tmpfs만 연결. 운영 볼륨/호스트 bind/socket 없음 |
| 도우미 |체크포인트 도우미 메모리/총 swap128MiB·CPU1·PID32·로그 저장 비활성화. 키 읽기 전용 |

체크포인트는 백업이 완성되기 전에 게시될 수 있다. 이후 덤프/복원이 실패해도 과거 기준으로
되돌리지 않고 같은 작업을 명시적으로 재개한다. 체크포인트가 게시됐다는 사실만으로 백업 생성이나
발급 서비스 복귀가 끝났다고 판단하지 않는다. journal의 backup.phase와 최종 평가 결과를 확인한다.

## 로컬 실행

새 directory에서 시험한다. 기존 프로필의 descriptor를 자동 변환하거나 데이터를 재기준화하지 않는다.

```powershell
.venv/Scripts/python.exe -m scripts.database_recovery_runtime up --directory runtime/c02/my-recovery
.venv/Scripts/python.exe -m scripts.database_recovery_runtime backup --directory runtime/c02/my-recovery
# 시간 초과·중단 뒤에는 같은 journal을 사용해 명시적으로 재개
.venv/Scripts/python.exe -m scripts.database_recovery_runtime resume --directory runtime/c02/my-recovery
# manifest.json에는 해당 백업 journal의 manifest 객체만 저장한다.
.venv/Scripts/python.exe -m scripts.database_recovery_runtime assess --directory runtime/c02/my-recovery --manifest manifest.json
.venv/Scripts/python.exe -m scripts.database_recovery_runtime down --purge --directory runtime/c02/my-recovery
```

운영 backup/resume CLI의300초 실행 예산은 유지한다. 초과하면 같은 기록으로 재개해야 한다.
기존 백업 시험 드라이버의 재개/중단 마커 예산도300/240초다. 추가 도우미 검증이 있는 새 프로필의
**시험 드라이버만 각각600초**를 사용하며 실제 마커 경계에서 프로세스를 강제 종료하는 검증은 유지한다.
마커 전 중단 시 자식 종료 여부·종료 코드·경과 시간·예산·허용된 공개 스택을 남긴다.

## 최신성과 신뢰 경계

최신의 기준은 **마지막 명시적 정지 체크포인트 시점**이다. 그 이후 모든 폐기·토큰 소비를 자동으로
수집하는 실시간 원장이나 원격 witness는 아니다. 다음 캡처 전 변경은 포함되지 않는다.
평가 결과의 checkpoint_compatible=true는 운영 복원·접속 허가를 뜻하지 않으며,
live_restore_authorized=false를 함께 반환한다. 시작 명령에 최신 체크포인트와의 온라인 DB
동등성 강제를 추가한 것도 아니다. 이 평가는 선택한 백업을 격리 복원하는 경로에 적용된다.

호스트 관리자와 descriptor는 신뢰한다. 키·anchor·체크포인트를 함께 되돌리는 관리자 공격,
호스트 전체 소실, 독립 원격 보관·외부 단조 카운터는 이번 범위에 없다. 정상 발급 증가만 있어도
보안 지문이 다르면 거부하는 보수적 검사다. 최신 기록을 병합하는 운영 복원·CA root/JWK/leaf 키와
앱 DB를 포함한 전체 PKI/서비스 복구·물리 HA·김택희의 독립 인수는 후속이다.

## 검증 결과

최종 인수17개는 기존 백업/만료 경계13개에 체크포인트4개를 더한다. 실제 폐기 API200과
폐기 테이블 행수 **61→62**를 확인하고, 활성38신원을 정상 mTLS로 갱신한 뒤 새 백업을 생성했다.
폐기된 collector의 지문은 유지했으며 다시 발급하지 않았다. 과거 암호문은 여전히 인증되지만
체크포인트 불일치로 거부됐고, 거부 중 SQL 복원 함수가 호출되지 않은 것도 확인했다.
최신 백업 복원과 재시작 후 anchor/복원 검증, 모든 소유 컨테이너·볼륨·네트워크0을 확인했다.

인수의 기동·강제 종료·복원·재시작·정리 포함 관측 시간은1766.547초다. 운영 RTO/RPO가 아니다.
그 뒤 공통 pytest 시각 fixture3개만 정리했다. 실행 프로그램·정의의 release 지문이 같음을 대조해
긴 인수를 재사용하고, 최종 테스트 소스의 Linux 전체2520개·고정 Ruff0.17.3을 다시 검증했다.
로컬 Git head는 당시 f78f22e이고 tracked 작업과 기존 ZIP 때문에 dirty였다. 파일/이미지 지문을
고정했으며, clean PR head와 병합 커밋 검증은 CI 원자료와 구분한다.

[최종 원자료와 소스 지문](infrastructure-results/database-recovery-checkpoint-20261108.json),
[오전7시까지의 초안 기록](infrastructure-results/database-recovery-checkpoint-draft-20261108.json)을 보존한다.
CI는 기존 앱mTLS 복구를 포함한8개 경로를 유지하고 체크포인트 경로를 더해9개 runtime·총13개 job이다.

## 초기 실행과 보완 기록

| 실행 | 결과와 보완 |
|---|---|
| 초안 집중 검사 |103통과. 처음99통과/1실패와 장시간 도구 지연은 초안 원자료에 보존 |
| 첫 Docker 인수 |14개 뒤 폐기 응답 확인에서 중단. 기존 컨트롤러와 같은 passive=true 요청으로 맞추고 상태/DB 행수를 기록. 원 응답 코드는 미기록 |
| 첫 전체 묶음 |Linux2518/1실패(체크포인트 시각 범위가 먼저 거부), 최초 발급 인수0/미발급3. 후자는 원인 미확정으로 유지 |
| 다음 묶음 |Linux2517/2시각 실패. 새 인수14개 후300초 드라이버 예산 중단. journal은 resuming/verified=true였고 자원0 |
| 다음 묶음 |Linux2518/1공유 이벤트 ID 검토 목록 실패. 중단 마커 이전 인수4개 뒤 중단, 원래 자식 exit/timeout 분류는 미기록 |
| 새 인수 완료 |17/17·정리0. 같은 묶음 Linux2519/1fixture 준비 오류가 남아 공통 시각 fixture로 정리 |
| 최종 확인 |관련137개 집중 통과 후, 실제 프로그램 지문 동일함을 확인하고 최종 Linux2520개 통과 |

시각 제어는 무결성·저장 실패 시험의 checkpoint 시간에만 적용한다. 만료/미래 시각 시험은 인증된
timestamp를 기준에서 각각 이동시켜 계속 거부되는지 확인한다. 실제 운영 시각·TLS TTL·인가를
완화하지 않았다. 검토 상태 시험은 고유 이벤트 ID로 격리했고, 같은 이벤트의 더 오래된 분석이
나중에 저장돼도 최신 analyzed_at 기록을 선택하는 기존 동작은 재시작까지 별도 검증했다.
app/·탐지 기준·벤치마크 데이터는 변경하지 않았다.

새벽의 긴 실행 지연 구간은 Windows 절전/복귀 기록과 일치했다. 개별 시간 오류의 실제 age 값은
기록되지 않아 모든 실패의 원인으로 단정하지 않는다. 장시간 실행에는 작업 수명 동안만
[Windows 스레드 전원 요청](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setthreadexecutionstate)을
사용하고 종료 시 해제한다. AWS·외부 유료 LLM API는 호출하지 않았다.
