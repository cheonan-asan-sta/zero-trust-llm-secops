# 웹 기록부 암호화 백업·복원과 외부 checkpoint v47

2026-11-13 · `extra`에서 [v46 기록부](extra-web-evidence-ledger.md)의 일관된 백업·복원과
**별도 지문으로 고정한 checkpoint 검사**를 추가했다.
복원본에서 기존 위험이 유지됐고, 최신 checkpoint보다 오래된 백업과 전체 로컬 이력 되돌림을 거부했다.
기능 예제10개·신규30개 포함 **Windows/Linux 관련387개씩 통과**했다.
[공개 실행 근거](infrastructure-results/extra-web-backup-v47-20261113.json)에 지문과 결과가 있다.

이번 검증은 작성한 로컬 기능 조건이다. 실제 서버 관측/새 독립 자료/F1 측정은0이고,
이전 웹 FN30·FP19는 보존 기록이다. 앱·기존 모델/라벨·승인/복구/PEP 경로는 수정하지 않았다.

## 구현한 백업과 복원

핵심 코드는 [web_ledger_backup.py](../scripts/f1_lab/web_ledger_backup.py),
실행 예제는 [run_web_backup_controls.py](../scripts/run_web_backup_controls.py)다.
`WebLedgerBackup`은 기존 기록부와 별도32바이트 복구 키, key ID, 운영자가 설정한
정확한 유지보수 주체 목록을 받는다. API key/OIDC 인증·admin 역할·목록 일치를 모두 요구한다.
일반 tenant admin이나 analyst라는 이유만으로 전체 기록부를 백업할 수 없다.
이는 신뢰할 수 있는 서버 호출자의 `Principal`을 사용하는 라이브러리이며 새 운영 API는 아니다.

| 단계 | 실제 동작 | 완료 조건 |
|---|---|---|
| checkpoint | 잠금 상태에서 store ID·설정·순번·해시·시각을 새 파일에 기록 | 기존 파일 덮어쓰기 거부, 이전 checkpoint를 지정하면 지문과 역사 연속성 대조 |
| 백업 | 기록부 잠금과 SQLite backup API로 DB 스냅샷 생성. 대응 witness·HMAC 키를 함께 묶음 | 현재 head가 지정 checkpoint와 같아야 함. 다르면 새 checkpoint 필요 |
| 암호화 | DB·witness·HMAC 키 묶음 전체를 AES-256-GCM으로 암호화 | key ID·스냅샷 metadata를 AAD로 결속. 복구 키는 묶음에 저장하지 않음 |
| 백업 게시 | `payload.aesgcm`을 쓴 뒤 `manifest.json`을 마지막에 게시 | 정확한2파일 목록과 외부 manifest SHA를 검증해야 사용 가능 |
| 복원 | 새 비공개 출력 폴더에 복호화하고 DB·witness·해시 연결·checkpoint 대조 | 검증 뒤 `state`와 `restore.json` 게시. 기존 경로는 덮어쓰지 않음 |
| 복원본 열기 | receipt 지문을 확인하고 `CheckpointedWebLedger` 반환 | 자동 서비스 활성화 없음. 이후 읽기/쓰기에도 checkpoint 재검사 |

checkpoint와 manifest의 기대 SHA는 백업 묶음 밖의 신뢰할 수 있는 경로에서 받아야 한다.
검사할 파일을 읽어 즉석에서 계산한 SHA를 다시 “기대 SHA”로 쓰는 것은 외부 신뢰 고정이 아니다.
초기 checkpoint 생성은 운영자의 bootstrap 작업이며, 이후에는 알려진 이전 지문과 최신 지점을 이어 관리해야 한다.

백업은 암호문과 공개 manifest 두 파일만 포함한다. 원래 로컬 witness 비밀키도 암호문 안에 넣는다.
복원본에는 운영에 필요한 witness 키가 다시 비공개 파일로 생기며 복구 키 자체는 쓰지 않는다.
경로는 고정된 구성요소만 사용하고, checkpoint를 묶음/복원 폴더 또는 source witness 안에 두지 못하게 한다.
실패한 출력은 불완전 상태로 남기고 덮어쓰거나 자동 활성화하지 않는다.

## checkpoint가 추가로 막는 것

v46에서는 DB와 witness를 함께 과거로 돌리면 서로 일치하는 오래된 이력이 될 수 있었다.
신규 `CheckpointedWebLedger`는 읽기/쓰기마다 별도 checkpoint 파일의 지문과 최소 역사 prefix,
store ID·설정·시각을 확인한다. 이미 고정한 순번보다 짧거나 같은 위치의 해시가 다르면 거부한다.
정상적인 새 기록은 같은 prefix 뒤에 추가할 수 있다.

실제 테스트에서는 원래 클래스가 빈 과거 DB/witness/key 조합을 열었지만,
새 checkpoint를 적용한 클래스는 같은 조합을 되돌림으로 거부했다.
checkpoint가 시작 후 바뀌거나 사라지는 경우도 매 접근에서 다시 확인하며 캐시된 정상 상태로 계속 쓰지 않는다.

이 보호는 **알려진 최신 checkpoint와 기대 지문을 보호한다는 조건**에 달려 있다.
checkpoint 파일·설정의 기대 SHA까지 함께 되돌리는 공격과, 마지막 checkpoint 이후의 미고정 이벤트 손실은
이 경계만으로 탐지할 수 없다. 주기적 새 고정과 활성 구성의 최신 지문 적용이 필요하다.
기존 일반 `WebEvidenceLedger`를 그대로 사용하는 경로에는 이 추가 보호가 자동 적용되지 않는다.

## 확인한 결과

| 항목 | 결과 |
|---|---|
| 암호화 백업 → 새 경로 복원 | 기존 adverse·경보·검토 유지 |
| 정상 증거를 추가한 복원본 | 기존 위험 유지, 이력2→4개 |
| 최신 checkpoint4와 예전 백업2 | 복원 거부 |
| 예전 DB·witness 전체 복사본에 최신 pin 적용 | 접근 거부 |
| 잘못된 키/다른 key ID·payload/metadata 변조·기대 SHA 불일치 | 복원 거부 |
| 진행 중 검증이 있는 스냅샷 | pending 유지. 기한 후 불확실한 검토로 복구 |
| 비허용 유지보수 주체·경로 겹침·기존 목적지·시계 역행 | 거부 |
| 원본 저장소 경로가 없는 복원 템플릿 | 백업과 별도 키/지문으로 새 복원본 검증 가능 |

통합 예제10개 모두 기대 결과를 냈고, 두 checkpoint의 순번은2와4다.
복구 결과는 자동 활성화하지 않고 기존 위험이 보존되는지만 확인했다.
예제는 v45의 고정 테스트 시계를 사용하며 실제 서버 관측이나 공격 표본이 아니다.

신규 테스트30개 중 **실제 프로세스 강제 종료5경우**를 추가했다.
백업 payload 후/게시 후, 복원 state 생성 전/게시 전/게시 후에 종료해
완료 marker 없는 산출물이 열리지 않는지 확인했다. 기존 v46의8경계도 관련 묶음에 포함됐다.
최종 Windows387·network none Linux Docker387개가 각각 통과했고 실패/skip0, Ruff도 통과했다.
Linux748소스 전후 동일·exit0·OOM false·해당 소유 컨테이너 제거를 확인했다.
전체 앱 회귀·실제 물리 전원/디스크 장애·실제 IdP/PDP/센서 인수는 이번 범위가 아니다.

## 복구 키와 운영 인수의 남은 범위

실행 예제의 복구 키는 테스트 메모리에만 생성했다. 따라서 **생성된 예제 묶음은 운영 백업이 아니다.**
같은 실행 안에서 복원까지 검증한 기능 산출물이며, 프로세스 종료 뒤 예제 묶음을 재복호화할 키를 제공하지 않는다.
실제 사용에는 별도 보호한 복구 키·key ID와 manifest/checkpoint 기대 지문의 관리가 필요하다.
강제 종료 단위 테스트는 하위 프로세스에 키를 전달하기 위한 비공개 임시 키 파일을 사용했으며 공개/Git에 넣지 않았다.

이번 external-checkpoints 디렉터리는 같은 컴퓨터 안의 논리적 분리다.
물리적으로 독립된 보관소·원격 WORM·KMS·호스트 HA를 배포하거나 검증한 결과가 아니다.
백업/복원 목적지의 POSIX 권한을 제한했고 Windows의 실제 ACL/키 보관 인수는 추가로 필요하다.
운영 복원 시 기존 writer를 차단하고 새 writer로 전환하는 펜싱·절체도 아직 연결하지 않았다.
원본 signed proof의 별도 보관·사건 검토/종결 권한 흐름은 계속 남는다.

## 재현과 다음 단계

실제 예제는 `runtime/f1/web-backup-controls-v47-20261113`,
관련 시험은 `runtime/f1/web-backup-tests-v47-20261113`에 있다.
[고정 실행 프로토콜](../infra/f1-lab/web-backup-controls-protocol.json)의 SHA는
`4f437e053bb24c9264d4e11a0ded1b01c81e3cc98ea35ded26acff2bfb9ff6d8`다.

```powershell
.venv\Scripts\python.exe -m scripts.run_web_backup_controls --plan infra/f1-lab/web-backup-controls-protocol.json --expected-plan-sha256 4f437e053bb24c9264d4e11a0ded1b01c81e3cc98ea35ded26acff2bfb9ff6d8 --output runtime/f1/web-backup-controls-new
```

고정한 v46 receipt와 새 출력 폴더가 필요하다. 새 키·nonce·store ID로 지문은 실행마다 달라질 수 있다.
암호문·로컬 witness 키·복원 데이터는 runtime에만 두고 공유 JSON에는 공개 상태와 지문만 남겼다.
다음은 실제 수집기 요청 상관, 복구 키/checkpoint의 보호된 운영 보관, writer 절체와 사건 검토 흐름의 인수다.
실제 수집/새 F1 평가는0이고 유료 API/AWS·다운로드·GitHub push·병합도0이다.
