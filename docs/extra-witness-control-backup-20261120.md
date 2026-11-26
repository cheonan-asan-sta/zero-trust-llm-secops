# 수집기 확인 기록의 암호화 백업과 최소 기준 보존

2026-11-20 · `extra` · 구현 `c05c87a`. [08:00까지의 지속 목표](extra-until-0800-20261120.md)는 진행 중이다. 기존 `audit_entries`용 백업 형식을 다른 SQLite DB에 억지로 적용하지 않고, observer 확인 기록 전용 형식과 검증을 추가했다. 서비스 설정/실제 배포/개인키 백업은 변경하지 않았다.

## 보존하는 내용과 암호화

백업은 프로필·공개키·`observer.sqlite3`의 일관된 SQLite snapshot만 포함한다. 프로필에 고정된 원본/witness 위치, 서명 영수증 체인, 원래 pending 작업 ID/이전 기준/시작 시각을 그대로 보존한다. 수집기의 실제 lease를 잡은 동안 snapshot을 복사하고, 복사본과 발행 직전 원본을 다시 검증한다. 다른 수집기가 실행 중이면 백업을 거부한다. 서명키·원본 감사 이벤트·살아 있는 프로세스/PID/잠금은 복사하지 않는다.

32바이트 복구키와 무작위96비트 nonce로 AES-256-GCM 암호화한다. 형식/schema·프로필/영수증 pin·snapshot 식별자·생성 시각·파일 목록/길이/digest는 AAD로 묶는다. 이 header의 제한된 메타데이터는 평문이며 프로필/공개키/확인 DB 본문은 암호문이다. 외부에 고정한 package SHA256과 key SHA256도 별도로 요구한다. 키를 자동 생성하거나 프로그램이 백업 옆에 함께 저장하지 않는다.

DB는16MiB, 프로필64KiB, 공개키32바이트로 제한하고 크기를 초과하면 거부한다. 열린 파일 descriptor의 타입/소유자/모드/단일 link/크기/변경 여부를 검사해 FIFO·symlink·hardlink 및 읽기 중 변경을 거부한다. SQLite는 online backup과 정확한 schema·서명 체인·최소 기준·quick_check로 검증한다. private 임시 staging에는 검증용 평문 snapshot이 잠시 존재한다. 정상 종료 시 정리하지만 강제 종료 시 남은 staging의 별도 안전 정리가 필요하며, 메모리 전용 처리나 보안 삭제를 주장하지 않는다.

## 복원과 중단 경계

복원은 외부 package/profile/최소 영수증 pin을 요구한다. AEAD·파일 목록·길이·digest·복사된 프로필과 영수증 서명/순서를 검증한 뒤 새 디렉터리만 만든다. 외부 최소 기준보다 과거인 백업은 디렉터리 생성 전 거부한다. 더 오래된 기준으로 명시적 검토를 허용해도, 실제 witness가 이미 전진했다면 상태는 witness_advanced이며 자동으로 최신 head를 채택하지 않는다.

복원 중에는 `restore.pending`을 먼저 저장해 일반 수집기 실행/상태 검증을 차단한다. 모든 파일 검증과 완료 receipt 저장 후에만 marker를 제거한다. lease DB는 고정된 profile row로 새로 만든다. 복원은 검토 후보를 만드는 작업이며 설정 변경·서비스 시작·신원/접근 허가는 하지 않는다. 원본 위치도 자동 변경하지 않는다. 새 호스트로 옮기는 운영 절차는 별도 인수가 필요하다.

현재 중단 복원은 **기존 디렉터리를 덮어쓰지 않고 다른 새 후보로 다시 복원**한다. marker를 삭제해 성공으로 만드는 복구가 아니다. 원래 관측 pending이 들어 있는 백업은 복원 후 명시적으로 cycle을 실행하면 같은 작업 ID로만 이어진다. 서명이 이미 저장됐던 작업이면 같은 서명/시각을 돌려받으며 새 영수증을 중복 발행하지 않는다.

```bash
python -m scripts.audit_witness_observer_backup backup --directory <control> --profile-sha256 <외부-profile-pin> --minimum-receipt <외부-최소-pin> --destination <새-암호화-package> --key-file <분리한-32바이트-key> --key-sha256 <key-pin>
python -m scripts.audit_witness_observer_backup restore --package <package> --backup-sha256 <외부-package-pin> --profile-sha256 <외부-profile-pin> --minimum-receipt <외부-최소-pin> --destination <새-검토-디렉터리> --key-file <분리한-key> --key-sha256 <key-pin>
```

Linux는 소유자/0700·0600 및 디렉터리 fsync 계약을 검사한다. Windows는 로컬 암호화/상태 기능 시험이며 실제 보안 ACL/호스트 운영 인수로 표시하지 않는다. 백업/복원 key 값은 명령 인자가 아니라 분리한 파일에서 고정한 digest로 읽는다. 오류 응답은 상세 경로/키를 출력하지 않는다.

## 무료 로컬 검증

Linux 관련 묶음은 **123통과·제외0**. Windows는 **109통과·10제외** 묶음 뒤, 추가한 서명 이력 변조4건을 별도로 실행해 **4통과**했다. 두 Windows 실행의 고유 사례는113통과·10제외이며 새 단일 전체 실행으로 표시하지 않는다. 제외10건은 POSIX 권한/파일/상태 게시 경로다. 새 백업30건과 실제 프로세스 손실4건을 포함하며 전체 프로젝트 회귀/독립 탐지 평가 수치와 합산하지 않는다.

| 검증 | 확인 결과 |
|---|---|
| 정상 snapshot/복원·실제 CLI | 원본 감사/원본 확인 기록/witness journal 보존, 개인키 없음·자동 활성화 없음 |
| 서명 전/서명 저장 후 pending 백업 | 원래 ID·시각 보존, 복원 뒤 서명 중복0 |
| 외부 최소 기준보다 과거·타 writer | 거부 또는 검토 상태 불일치, 자동 pin 갱신0 |
| 패키지/키/프로필 pin 오류·추가/잘린 bytes | 후보 생성 전 거부 |
| 유효 AEAD로 다시 만든 악성 header/SQLite | 임의 파일/알고리즘/필드, 서명 변조·anchor 삭제·view·다른 pending 기준 거부 |
| 활성 lease·동시 복원·기존 대상·경로 중첩 | 단일 새 대상만 성공, 기존 파일 덮어쓰기0 |
| 실제 프로세스 종료81/82/83/84 | marker 직후/파일 완료/receipt 완료에서 부분 후보 실행 거부, 완료 후에만 일반 검증 허용 |
| 부분 복원 후 새 후보 복원 | 원본 변경 없이 새 후보 검증 통과 |

프로세스 종료 시험은 별도 테스트 소유 wrapper로 수행했으며 제품 CLI에 crash switch를 추가하지 않았다. 코드/원본 지문은 [manifest](infrastructure-results/extra-witness-control-backup-20261120.json)를 따른다. 기존 탐지 F1 93.41%·재현율90.56%는 그대로이고 목표 미달이다. 새 모델 호출/유료/API/AWS/Docker/push/CI/병합/실제8h soak0. 다음은 복원 완료 receipt의 별도 검증·경보 연결과 중단 후보의 명시적 재개 보강이다.
