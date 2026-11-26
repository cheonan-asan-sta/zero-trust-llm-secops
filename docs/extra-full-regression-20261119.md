# extra 전체 회귀 검증과 남은 인수 항목

> 최신 후속: [플랫폼 거부 경계·비동기 취소·VPN TLS 시험 검증](extra-platform-admission-20261120.md)을 완료했다. 최종 Windows8,025통과/591제외·실패0, Linux 전체8,610통과/5제외와 이후 영향 검증을 구분해 보존했다. 아래70실패/부분 검증 기록은 당시 시점이며 실제 Windows 운영 인수·탐지 F1 달성은 별도다.

2026-11-19 · 사용자의 후속 진행 요청으로, [직전 개발 범위](extra-active-development-goal-20261119.md)에서 남겨둔 전체 Python 회귀 검증을 수행했다. 테스트 기준은 `58d698a85002891707ed096248baab44736317fc`다. GitHub 업로드·CI·병합·유료 API·AWS·Docker 자원 생성은 하지 않았다. 실제8시간 soak는 이번 실행에 포함하지 않았다.

## 실행 범위와 현재 상태

| 실행 | 현재 상태 |
|---|---|
| Windows 전체 `python -m pytest -q` | 7,996통과·70실패·538제외·오류0. 약38분24초 |
| Linux native 전체 `python -m pytest -q` | 8,600통과·4제외·실패0. 약17분12초 |
| 전체 `ruff check .` | 통과. JSON 진단0건 |
| 실제 UI 브라우저 | 이번에 재실행하지 않음. 직전 기능 검증의 원본·소스 지문 유지 |

전체 Python 회귀는 공개 API·인증·검토 버전/CAS·신원 철회·감사 원본 보존·검색·페이지·검증자·기존 실행/복원 기능을 저장소 시험 전체로 확인한다. 분류 성능의 새 평가, 실제 LLM 호출, 실제 기업 SSO·다중 호스트 장애 인수와는 다른 검증이다.

Linux의 첫 공유 폴더 실행은 파일 I/O 지연 때문에 중단했다. 그 실행을 통과나 전체 완료로 계산하지 않는다. Windows worktree의 `.git` 경로는 Windows 절대 경로이므로 Linux Git에서 직접 열지 못했다. Windows Git으로 같은 HEAD를 archive하고 Linux 전용 임시 경로로 풀어 재실행했다. native 경로·기준 커밋·archive SHA256은 `runtime/extra-full-regression-native-source-20261119.json`에 보존한다. `.env.local`·작업 트리의 비밀 파일은 복사하지 않았다.

OS별로 같은 사례를 반복한 횟수를 독립 평가 데이터 수로 합산하지 않는다. Linux 전용 syscall·peer credential·POSIX 권한 시험의 Windows 실패/제외가 있으면 지원 범위와 실제 기능 실패를 나눠 기록한다. 실패를 숨기기 위해 보안 검사·평가 정답을 완화하거나 제외를 임의로 추가하지 않는다.

Linux 제외4건은 JSONL 전용 view 변경2건을 SQLite의 별도 시험에서 다루는 것과, 패치된 Linux 컨테이너 안에서만 실행하는 runtime/provenance·offline pip2건이다. 호스트 전체 통과를 컨테이너 이미지 검증 완료로 표시하지 않는다.

## Windows 실패 분류와 후속 수정

전체 실행은 Windows도 **실패 상태 그대로** 기록한다. 실패한70개 node는 같은 기준 커밋의 Linux 전체 실행에서 모두 통과했다. 이것만으로 원인을 전부 OS로 단정하지 않고 실제 예외를 확인했다. 두 환경의 Python·FastAPI·Starlette·Pydantic 버전도 달라 환경 원본을 함께 보존한다.

| Windows 실패 영역 | 건수 | 확인한 내용 |
|---|---:|---|
| managed 실행 보관 | 39 | Windows에 없는 `os.geteuid` 사용 |
| 실행 이력 경계 | 11 | Linux를 흉내 낸 fixture에서 없는 `SIGCHLD`·`fork`를 참조 |
| 실행 복구 상태 | 8 | 보호된 bridge 파일 shape 검사부터 거부되어 상태/본문 오류 기대와 불일치 |
| 실행 보관·회전 | 5 | 읽기 전용 descriptor의 `fsync`가 Windows에서 `EBADF` |
| 연속 feed 검사 | 3 | symlink가 통과하는 실제 문제1건 수정. FIFO API 부재·POSIX chmod 기대2건은 남음 |
| mTLS 문맥 복구 | 1 | `O_DIRECTORY` 미제공 |
| feed 소유 권한 | 1 | Windows chmod만으로 POSIX owner-only 계약을 재현할 수 없음 |
| kernel peer 인증 | 1 | `SO_PEERCRED` 미제공. 인증 우회로 처리하지 않음 |
| LLM SDK 비동기 취소 | 1 | 두 번째 검증 진입을 기다리는2초 대기 실패. 같은 파일8건 단독 재실행 통과, 원인 확정 안 됨 |

`scripts/behavior_execution_collector.py`의 `read_private`는 기존에 `getattr(os, "O_NOFOLLOW", 0)`만 사용했다. 이 flag가 없는 환경에서 링크가 원본처럼 읽히는 문제를 실제 Windows 실패에서 확인했다. 이제 `lstat`으로 symlink를 명시적으로 거부하고, 열기 전·열린 descriptor·열기 후 경로의 device/inode를 비교해 파일 교체도 거부한다. Windows binary flag도 명시해 입력 바이트를 보존한다. Linux의 `O_NOFOLLOW`·열린 객체 권한 검사·기존 `fsync`는 유지한다.

이 보강이 Windows ACL 검증이나 durable directory sync를 구현한 것은 아니다. Windows에서 POSIX 검사를 흉내 내거나 `fsync` 오류를 무시해 녹색으로 만들지 않았다. 해당 native 수집기·보관·복구 기능을 Windows 운영용으로 인수했다고 주장하지 않는다. 별도 Linux 환경에서 실행해야 하며, Windows 운영 지원에는 ACL·native file identity·동기화/복구 계약을 별도로 구현·인수해야 한다.

수정 뒤에는 새 파일 신원3건, 기존 symlink 거절, SDK 비동기8건을 Windows에서 확인하고, Linux에서는 collector·continuous·retention·managed retention 영향 범위를 묶어 실행한다. 초기 Windows 혼합 재검증의 FIFO/권한2실패도 원본에 남긴다. 기준 커밋 전체 결과와 수정 후 부분 검증을 합쳐 최신 전체 재실행 통과로 표시하지 않는다. 단독 재실행 통과를 전체 실행의 간헐 실패가 해결됐다는 뜻으로 표현하지 않는다.

수정 구현은 `b87c0a0`이며 후속 검증은 **Windows12통과·Linux113통과·제외0**이다. SDK 비동기 파일의 첫 단독 재확인8건도 통과했다. 초기 혼합 확인4통과·2실패를 포함해 모든 실행의 원본과 각 소스 기준은 [manifest](infrastructure-results/extra-full-regression-20261119.json)에 기록했다. 전체 Ruff는 기준/후속 모두 진단0건이다.

## 비용과 재현

두 실행에 실제 API 키 대신 로컬 시험용 값, AWS 메타데이터 비활성화를 적용했다. provider·AWS·Docker 연동은 기존 시험의 local stub/mock 경로로 검증한다. cloud 배포나 유료 모델 평가 명령은 실행하지 않았다.

```powershell
python -m ruff check .
python -m pytest -q --junitxml=runtime/extra-full-regression-windows-20261119.xml
```

Linux에서는 같은 커밋을 Linux 로컬 파일시스템으로 옮긴 후 기존 Linux 가상환경으로 `python -m pytest -q --junitxml=runtime/extra-full-regression-linux-native-20261119.xml`을 실행한다. 테스트 중 사용하는 서버·CLI 프로세스는 각 fixture가 소유하고 정리한다. 기존 운영 서버나 컨테이너를 기동하지 않는다.

## 탐지 수치와 남은 작업

모델·프롬프트·정답·평가 예측은 바꾸지 않았다. 기존 합성 개발360건은 정밀도96.45%·재현율90.56%·F1 93.41%·보수 오탐률3.33%다. 이번 회귀의 통과율을 탐지 F1이나 독립 성능 목표 달성으로 표현하지 않는다.

실제8시간 soak, 외부 client 전체 목록과 필수 검토 정책의 실제 배포, 기업 신원 인증원, 별도 권한·호스트의 독립 감사 보관 인수는 남아 있다. 로컬 witness는 명시적 일회성 CLI이며 자동 수집 scheduler·앱의 online 필수 gate를 적용한 상태가 아니다.

이번에 기준 커밋의 전체 Python 검증과 실패 원인 정리, 링크/파일 교체 거절 보강과 영향 범위 재검증까지 마쳤다. Windows 전체70실패를 모두 해결한 것은 아니다. Windows ACL·POSIX syscall·durability 차이와 비동기 시험의 간헐 대기 실패는 위 분류대로 남긴다. 안전한 기본 서버 인수는 Linux 결과를 기준으로 하며, Windows를 동일한 운영 보안 환경으로 간주하지 않는다. 전체38분·17분은 이번 환경의 관측 소요 시간이며 일반적인 OS 성능 비교나 처리량 benchmark가 아니다.
