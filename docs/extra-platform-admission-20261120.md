# 로컬 검증 목표: 플랫폼 보장과 비동기 취소 시험

2026-11-20 · `extra` · 제품/동기화 구현 `ff44064`, Windows 시험 표시 범위 정정 `4b4c50c`, VPN 시험 TLS 오류 전달 보강 `217d090`. 사용자의 “목표달성까지 계속” 요청에 따라 [직전 전체 검증](extra-full-regression-20261119.md)의 Windows 실패와 간헐 대기 실패를 후속 처리하고 지원 범위의 로컬 검증을 마쳤다. 유료 API·AWS·Docker 자원 생성·업로드·CI·병합·실제8시간 soak는 하지 않았다. 탐지 지표 목표나 Windows 운영 인수를 대신하는 목표가 아니다.

최종 Windows 전체는 **8,025통과·591제외·실패/오류0**이다. Linux 전체는 **8,610통과·5제외·실패/오류0**이며 이후 바뀐 테스트2개 파일의 보관40건·VPN25건도 Linux에서 통과했다. 기존 Windows 통과7,996건이 모두 유지됐고, 기존 실패70건은 Windows17통과·Linux 전용53건으로 분류됐다. 해당70건은 Linux 전체에서 모두 통과했다. [원본·소스 지문·항목별 대조 manifest](infrastructure-results/extra-platform-admission-20261120.json)를 함께 보존한다.

## 실제로 바꾼 보안 경계

| 경로 | 변경과 유지한 계약 |
|---|---|
| `exec_history.collect_owned_exec` | 공통 입력·timeout을 먼저 검사하고 Linux·`SIGCHLD`·`fork` 능력을 확인. 없는 syscall의 AttributeError나 실제 fork 전에 거부. uid·실행 pin·현재 권한·자식 소유권 검사는 유지 |
| `capture_backup.private_file/private_directory` | POSIX 소유권·no-follow 보장이 없는 환경에서는 파일 접근 전에 명시적으로 거부. UID/mode 검사를 가짜 값으로 대체하지 않음 |
| 수집기의 `read_private(..., durable=True)` | POSIX durability를 제공하지 않는 환경에서 거부. fsync 오류 무시나 일반 읽기로의 우회 없음. 직전 링크·파일 신원 검증도 유지 |
| mTLS 복구 `restore/sync_directory` | POSIX directory fsync가 없으면 복구 상태 접근·승인 전에 거부. 실제 Linux의 directory fsync·중단 복구 검사는 유지 |

새 플랫폼 거부 시험은 없는 syscall/소유권/directory durability가 신뢰로 바뀌지 않음을 검사한다. 비밀·승인 토큰을 만들거나 실제 기업 신원을 인증하는 시험이 아니다.

## Linux 전용 시험과 mock 단위 시험을 구분

기존 Windows 실패70건에는 POSIX 파일 mode·UID·directory fsync·wait status 같은 보장이 필요한 시험이 포함돼 있었다. 이 기능을 Windows에서 안전하게 제공하도록 ACL·native handle·FlushFileBuffers 등을 구현한 것은 아니다. Windows의 chmod를 POSIX 보장으로 인정하거나 저장 동기화를 생략하지 않는다.

- POSIX sealed-outbox 보관39건, fork/wait cleanup4건, durable input retirement5건은 Linux에서 유지한다.
- owner-only feed1건, FIFO/공개 mode2건, container 복구1건, 실제 보호된 status 파일의 metrics1건도 POSIX 환경에서 검증한다.
- Windows에서 제외하는53건은 각각 필요한 primitive와 이유를 시험에 명시한다. Linux에서 해당 사례를 그대로 실행해야 한다. 이 제외를 Windows 기능 성공으로 계산하지 않는다.
- kernel peer 시험은 kernel/manager 응답을 전부 제공하는 mock 단위 시험이다. 시험에만 socket 상수를 제공하고 실제 `SO_PEERCRED` 검사는 바꾸지 않는다. Linux의 실제 Unix peer 시험은 유지한다.
- 잘못된 profile schema/limit7건은 입력 파싱 단위 시험으로 reader를 명시적으로 주입한다. production의 보호 파일 reader와 POSIX 실제 파일 시험은 유지한다. unsigned 상태 metrics는 여전히 권한을 부여하지 않는다.

새 검증에서 Linux 전용 보호를 Windows에서 삭제해 통과한 것으로 표현하지 않는다. 원래 실패했던 node의 최종 상태와 Linux 실행 여부는 최종 manifest에서 일대일 대조한다.

중간 대조에서 sealed-outbox 모듈 단위 제외가 기존에 Windows에서 통과했던 `store_link` 거절1건까지 제외하는 문제를 찾았다. `4b4c50c`에서 각 시험과 parameter의 실제 필요 primitive에만 표시하도록 범위를 좁혔고, Windows에서 해당 모듈1통과·39제외를 확인했다. 제품 코드와 시험 함수 본문은 변경하지 않았다. 진행 중이던 `ff44064` 전체 결과와 이 표시 정정 후 부분 검증은 별도로 기록한다. 둘을 합산해 최신 commit의 단일 전체 재실행으로 표시하지 않는다.

## 비동기 취소의 간헐 실패

기존 시험은 SDK의 첫 응답 파싱·retry 준비가 끝난 뒤 다음 검증 worker가 **2초 안에** 시작해야 한다고 가정했다. 동일한 기존 시험에 로컬 mock 응답 지연2.2초만 넣으면 같은 `entered.wait(2)`에서 실패하는 것을 재현했다. 유료 provider나 모델 판정을 사용한 재현이 아니다. 원래 전체 실행 당시의 정확한 지연 원인을 확정했다는 뜻은 아니며, 고정2초 가정 자체의 문제를 재현한 것이다.

시험은 이제 검증 worker가 `call_soon_threadsafe`로 asyncio Event에 진입 사실을 알리게 한다.10초는 미진입/실패 시 종료하는 watchdog이며 운영 timeout을 바꾼 값이 아니다. worker는 release를 기다리는 동안 끝나면 안 되고, 이때 이벤트 루프에서 취소를 처리할 수 있어야 한다. 두 번 취소한 뒤에도 I/O worker가 끝나기 전 요청이 완료되지 않아야 하며, release 후 CancelledError·추가 SDK 호출0을 그대로 확인한다. 검증 callback이 이벤트 루프를 막는 구현은 이 조건을 통과하지 못한다.

2.2초 로컬 응답 지연 사례를 새 정상 시험에 추가해, 느린 준비가 있어도 동일한 취소·호출 한도 검사가 유지되는지 검증한다. 실제 SDK 파서·local MockTransport를 사용한다. 모델·프롬프트·점수·정답·평가 예측은 수정하지 않았다.

## 검증 진행 상태

| 실행 | 상태 |
|---|---|
| 최초 Windows 영향 범위 | 195통과·58제외·2실패. 신규 fixture가 RecoveryError를 ValueError로 잘못 기대한2건 |
| 최초 Linux 영향 범위 | 300통과·1제외·같은 fixture2실패 |
| fixture 수정 후 Windows guard/SDK | 16통과·실패0 |
| fixture 수정 후 Linux guard/SDK | 15통과·1제외·실패0. 제외는 실제 non-POSIX 거부 시험 |
| 기존 대기 가정 재현 | 의도한1실패 확인. 제품 검증의 최종 실패로 합산하지 않음 |
| `ff44064` Windows 전체 | 8,022통과·592제외·1실패. 약38분57초. 후술한 Windows TLS reset 오류 전달 차이를 발견 |
| `ff44064` Linux 전체 | 8,610통과·5제외·실패0. 같은 커밋 archive를 새 Linux native 경로에서 검증, 약19분23초 |
| `4b4c50c` Windows 보관 범위 확인 | 1통과·39제외·실패0. 원래 통과하던 store_link 거절을 계속 실행 |
| `4b4c50c` Linux 보관 범위 확인 | 40통과·실패0. 원래 모든 POSIX 사례를 유지 |
| `217d090` 실제 VPN mTLS 영향 범위 | Windows25통과·Linux25통과·실패0. OS별 실행 횟수를 합산하지 않음 |
| `217d090` Windows 최종 전체 | 8,025통과·591제외·실패/오류0. 약25분56초. 표시 범위 정정과 TLS 시험 전달 보강을 포함 |

초기 fixture의 예상 예외만 기존 `RecoveryError`에 맞췄다. 복구의 거부 동작이나 오류 class를 시험에 맞춰 완화하지 않았다. 원본은 모두 보존한다. OS별 반복 실행을 새 독립 데이터 수로 합산하지 않는다. 마지막 전체 실행이 종료되고 원본 대조가 통과한 뒤 완료로 기록했다.

Windows591제외는 기존538건과 이번에 실제 POSIX 계약을 명시한53건이다. 기존 통과 사례가 최종 제외 목록에 새로 들어간 것은0건이다. collection 단계의 skip marker 감사와 최종 XML의 실제 결과를 각각 대조했다. 중간 모듈 단위 제외에 포함됐던 store_link1건도 최종 전체에서 통과했음을 확인했다. 전체 Ruff는 진단0건이다.

Linux5제외는 JSONL 전용 view 조건2건, 패치 컨테이너 전용 runtime/provenance·offline pip2건, 실제 non-POSIX 거부 시험1건이다. 컨테이너를 생성하거나 이미지 인수를 수행한 것은 아니다. Windows 최종 전체에 들어간 새 VPN reset 주입1건은 Linux 전체 이후 추가했으므로, Linux에서는 영향 범위25건에 포함해 통과를 확인했다. 서로 다른 기준 commit/전체와 부분 실행을 합산해 하나의 전체 수치로 바꾸지 않는다.

### 마지막 Windows TLS 실패와 처리

`ff44064` 전체 실행의 나머지1실패는 인증서 없는 VPN 접속의 음성 시험이었다. 서버가 TLS에서 거부했지만 Windows 클라이언트에 `SSLError` 대신 TCP `ConnectionResetError`가 전달되어, 시험 연결 도우미가 서버의 실제 거절 예외를 가져오지 못했다. production VPN TLS 검증이나 인증서 필수 설정을 바꾸지 않았다.

`217d090`의 시험 도우미는 클라이언트 오류를 기억하고 서버 Future 결과를 확인한다. 서버가 실제 TLS/수집 검증에서 거부하면 그 예외를 전달하고, 서버가 성공했는데 클라이언트만 끊겼으면 해당 클라이언트 오류를 다시 던진다. 임의 reset을 인증서 거부의 성공 근거로 묵인하지 않는다. 음성 시험은 서버의 `PEER_DID_NOT_RETURN_A_CERTIFICATE` 사유와 관측 생성0까지 확인하도록 강화했다.

또 실제 유효 mTLS 응답을 받은 후 클라이언트 reset을 주입하는 사례를 추가했다. 서버의 관측 생성 성공이 클라이언트 연결 실패를 숨기지 못해야 한다. 실제 loopback TLS를 사용하는 VPN·등록 위험25건을 양 OS에서 실행해 통과했다. `ff44064` 이후 바뀐 것은 테스트 표시와 도우미·검증 사례뿐이며 제품 코드는 그대로다. Linux 전체와 이후 영향 검증을 최신 commit의 단일 전체 실행으로 합산하지 않는다.

## 남는 운영 범위

이 목표가 끝나도 실제 Windows 보안 수집기 운영, 기업 SSO·외부 client 전환, 별도 권한·호스트의 독립 witness/WORM, 실제8시간 soak와 새 독립 탐지 평가는 남는다. 기존 합성 개발360건의 정밀도96.45%·재현율90.56%·F1 93.41%·보수 오탐률3.33%는 그대로다. 로컬 회귀의 통과율을 F1 목표 달성으로 바꾸지 않는다.

## 재현

프로젝트의 기존 테스트 환경에서 실행한다. provider는 local mock, TLS는 loopback fixture이며 클라우드 배포나 유료 평가 명령이 아니다.

```powershell
python -m ruff check .
python -m pytest -q --junitxml=runtime/platform-full.xml
python -m pytest tests/test_native_platform_admission.py tests/test_async_evidence_io.py tests/test_vpn_gateway_collector.py tests/test_vpn_enrollment_risk.py -q
```

Linux 전체는 Windows 공유 경로의 I/O 지연을 피하기 위해 해당 기준 commit의 `git archive`를 새 Linux native 임시 경로에 풀고 기존 Linux 가상환경으로 실행했다. archive SHA256·환경/OpenSSL 버전·전체 기준 commit과 후속 시험 기준을 manifest에 명시한다. 실제 `.env.local`·미추적 비밀 파일은 복사하지 않았다.
