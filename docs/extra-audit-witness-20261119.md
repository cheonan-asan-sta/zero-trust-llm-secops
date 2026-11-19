# 별도 로컬 감사 검증자와 서명 영수증

2026-11-19 · `extra`. 앱과 별도 프로세스로 실행하는 검증자를 구현했다. 감사 SQLite 전체 chain과 최소 head를 직접 읽어 검증하고, 감사 DB 밖의 전용 디렉터리에서 Ed25519 서명 영수증을 보관한다. 실제 독립 호스트·계정·WORM 보관이나 기업 인수 완료는 아니다. 앱에 필수 online witness 정책을 켜거나 운영 설정을 변경하지 않았다.

## 기존 체크포인트에서 발전한 점

기존 체크포인트는 운영자가 선택한 JSON의 SHA256과 감사 DB를 비교했다. 이번 검증자는 자체 서명키와 연속 영수증 journal을 사용한다. 제출자가 만들어 준 head를 그대로 서명하지 않고, 설정된 감사 DB를 열어 모든 감사 이력과 이전 영수증 head의 실제 prefix를 확인한다. DB가 같은 길이의 다른 이력으로 바뀌어도 거부한다.

각 영수증은 stream ID, source 경로의 digest, 공개키 digest, 영수증 번호, 이전 영수증 digest, 관측 시각, 감사 head(seq·digest)를 서명한다. 이벤트 본문·사용자·자격 증명·개인키를 영수증에 넣지 않는다. source 경로도 평문 대신 digest로 남긴다. 영수증 digest는 JSON의 canonical 표현 기준이며, 파일 바이트의 SHA pin인 기존 checkpoint와 다르다.

서명키 없이 공개키와 명시적인 영수증 digest만으로 후보 DB를 검증할 수 있다. 복원 후보 경로가 바뀌면 `source_locator_matches=false`로 알리되 선택한 stream의 최소 감사 이력은 검증한다. source를 바꿔 새 영수증을 발급하려는 `observe`는 locator 불일치로 거부한다.

| 명령 | 기능과 보호 |
|---|---|
| `init` | 새 전용 디렉터리만 생성. 기존 상태·개인키를 덮어쓰거나 자동 재생성하지 않음 |
| `observe` | 마지막 영수증 digest를 정확히 지정. journal 전체 서명·연속성 확인 후 감사 DB chain/prefix 확인, 새 서명과 SQLite commit |
| `status` | 개인키 없이 journal 확인. 지정 최소 영수증이 이력에 있어야 하며 최신 서명 영수증을 반환. 저장/자동 재서명 없음 |
| `inspect` | 내보낸 서명 영수증·공개키·stream·두 pin을 확인하고 후보 DB가 해당 head를 포함하는지 검사. 복원 활성화 없음 |

첫 관측만 초기값인 64자리 `0`을 사용한다. 이후에는 반드시 직전에 보관한 `receipt_sha256`을 전달한다. 매번 초기값으로 재설정하거나 `status`가 반환한 값을 무조건 새 신뢰 기준으로 삼으면 후퇴 보호의 의미가 약해진다. 최신 영수증 pin을 witness journal과 함께 되돌릴 수 없는 위치에 별도로 보관해야 한다. 불일치·응답 유실 때는 자동 재시도하지 않고, 기존 pin을 최소 기준으로 `status`와 이력을 확인한 후 운영자가 다음 요청을 결정한다.

동일한 예상 영수증으로 동시에 여러 요청이 들어오면 `BEGIN IMMEDIATE`로 하나만 발급하고 나머지는 현재 기준 불일치로 거부한다. 시간은 참고용이며 외부 시각 인증이나 최신성 증명이 아니다. `inspect`는 선택한 최소 head 이후의 최신 기록 존재를 보장하지 않아 `latest_live_state_verified=false`를 반환한다.

## 재현 방법

비밀은 명령행 인자로 전달하지 않는다. `public-key-sha256`과 영수증 digest는 공개 검증 기준이며 인증 토큰이 아니다. 다음은 기존 감사 DB와 새 로컬 state 경로를 명시하는 예시다. 실제 운영 DB를 자동 선택하지 않는다.

```powershell
python -m scripts.audit_witness init --state-dir <새-검증자-디렉터리> --database <기존-audit.sqlite3> --stream-id local-audit
python -m scripts.audit_witness observe --state-dir <검증자-디렉터리> --database <같은-audit.sqlite3> --public-key-sha256 <init의-public_key_sha256> --expected-receipt <첫-관측은-64자리-0>
python -m scripts.audit_witness status --state-dir <검증자-디렉터리> --public-key-sha256 <고정한-공개키-pin> --minimum-receipt <별도-보관한-이전-영수증-digest>
python -m scripts.audit_witness inspect --database <후보-audit.sqlite3> --receipt-file <선택한-서명-영수증.json> --expected-receipt <영수증-digest> --public-key-file <공개키-복사본> --public-key-sha256 <공개키-pin> --stream-id local-audit
```

`observe/status`의 출력은 `receipt`와 `receipt_sha256`을 포함하는 wrapper다. `inspect --receipt-file`에는 wrapper 전체가 아닌 **`receipt` 값 자체**를 JSON으로 내보낸다. 개인키는 `private.key` 32바이트, 공개키는 `public.key` 32바이트다. 실제 개인키를 출력·Git 추가·복사한 사례는 없다. 시험 키는 임시 디렉터리에서만 생성했다.

기존 암호화 백업·복원 API는 그대로다. 시험에서는 옛 암호화 백업을 정상 복원한 뒤 최신 서명 영수증으로 검사해 거부되는지 확인한다. 옛 영수증을 의도적으로 선택하면 그 과거 최소 기준만 검증하므로, 저장소에서 현재 필요한 pin을 보호하는 운영 절차가 필수다. 검증자가 백업을 자동 활성화하거나 접근 grant를 발급하지 않는다.

## 로컬 검증 범위

원본과 소스 지문은 [기능 검증 manifest](infrastructure-results/extra-audit-witness-20261119.json)에 보존한다. Windows·Linux에서 동일한 신규 사례와 기존 checkpoint/progression을 묶어 검증한다. 서로 다른 OS 실행 횟수를 독립 평가 사례 수로 합산하지 않는다.

최종 Windows65통과·2제외, Linux67통과·제외0. 제외는 POSIX 소유권/권한 관련 사례다. 실제 별도 signer CLI 프로세스는 두 OS에서 모두 확인했다. 초기12건과 중간 묶음 원본도 보존했다. Ruff·format 검증을 통과했다. 이것은 해당 기능 묶음의 결과이며 전체 저장소 회귀 완료를 의미하지 않는다.

- 실제 별도 Python 프로세스의 init·서명·검증·잘못된 이전 기준 거절, 개인키 없는 status/inspect.
- 정상적으로 chain 검증되는 옛 감사 DB와 옛 witness journal 복원, 같은 길이의 다른 감사 이력 거절.
- 영수증 본문·서명·stream·번호·이전 digest 변조, 공개키 pin/영수증 pin 불일치 거절.
- journal 잘림·중복 JSON·metadata 변조, signer 교체·기존 디렉터리 재초기화 거절.
- 같은 기준 동시 발급 중 하나만 성공, 저장소 최대4096 영수증 도달 시 이력 삭제 없이 거부.
- 감사 원본 불변, source와 witness 위치 분리, POSIX 소유권·0600/0700·심볼릭 링크 거절.

```powershell
python -m pytest tests/test_audit_witness.py tests/test_audit_checkpoint.py tests/test_audit_checkpoint_progression.py -q
```

## 남은 운영 제약

Windows에서는 POSIX mode가 ACL 격리를 증명하지 않는다. 이번 프로세스 분리는 같은 사용자·같은 호스트이며, 호스트 관리자나 동일 권한 주체가 개인키·journal·외부 pin을 모두 제어하면 검증자를 우회할 수 있다. 실제 독립 보관은 별도 권한 주체·호스트·네트워크 인증·pin 보관·복구/키 교체 절차와 장애 인수가 필요하다. 초기화 실패 시 남은 디렉터리를 자동 복구·교체하지 않으며 운영자가 원인을 검토한다.

이 구현은 명시적 일회성 CLI다. 상시 scheduler, 앱 요청의 필수 witness gate, 원격 승인 프로토콜, 키 교체·보존 정책·기업 배포는 구현 완료로 표시하지 않는다. 로컬 journal에는 최대4096 영수증/128MiB 제한이 있고 초과 시 거부하며, 오래된 영수증을 자동 정리하지 않는다. 운영에 적용하려면 기간별 보관·새 signer/pin 인계 계획을 별도로 검토해야 한다.

모델·프롬프트·정답·예측 변경은 없다. 기존 합성 개발360건의 정밀도96.45%·재현율90.56%·F1 93.41%·오탐률3.33%와 별개인 감사 기능 시험이다. 유료 API·AWS·Docker·push·CI·병합·실제8시간 soak·최종 전체 회귀 결과 정리는 수행하지 않았다.
