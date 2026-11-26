# 감사 자료 검증 이관과 암호화 백업·복원

> 후속: [실제 native 실행→공동 감사 저장→백업·복원 HTTP 인수](extra-native-audit-recovery-20261119.md)를35조건으로 확인했다. 아래의 이관/복원 함수는 여전히 자동 활성화를 하지 않는다.

2026-11-19 · extra · 오전08:00 목표를 이어가는 후속 묶음. 유료 API/AWS/push/CI/병합/실사용 설정 전환은 하지 않았다.

## 기존 자료를 보존하는 이관

`python -m scripts.audit_storage scan --source <audit.jsonl>`은 원래 JSONL과 worker별 파일을 읽고 파일별 SHA-256, 행 수, 해시된 행/legacy 행 수와 목록 전체의 `inventory_sha256`을 출력한다. 원본 manifest가 있으면 등록된 파일과 checkpoint prefix도 읽기 전용으로 검증한다.

`migrate`는 이 목록 해시를 명시적으로 받아 일치할 때만 새 SQLite DB를 만든다. 원래 analysis와 검토 이력을 시간 순서대로 보존하고 동일 행 재전송만 중복 제거한다. 원래 분석이 빠진 검토, 서로 다른 불변 내용의 동일 ID, 불법 검토 전이는 거부한다. 없는 원래 상태를 만들어 넣지 않는다. 해시 없는 legacy 자료는 기본 거부하며 `--allow-legacy`로 선택한 경우 별도 개수를 남긴다. 이를 서명/해시 검증된 원본으로 재분류하지 않는다.

원본을 다시 읽어 이관 중 변경 여부를 검사하고, 전용 임시 디렉터리에서 만든 DB를 검증한 후 배타적인 동일 파일시스템 link로 새 경로에만 게시한다. 기존 파일이나 다른 writer가 먼저 만든 출력물을 덮어쓰지 않는다. 파일 전체의 전역 cutover lock은 아니므로 실제 전환 시에는 source writer를 멈추거나 확정한 기준 시점 이후의 기록을 별도로 이관해야 한다. 승인한 source 목록은 그 시점의 입력 증거이며 게시 순간까지의 모든 append를 포함한다는 뜻이 아니다.

```sh
python -m scripts.audit_storage scan --source <원본/audit.jsonl>
python -m scripts.audit_storage migrate --source <원본/audit.jsonl> --destination <새/감사.sqlite3> --inventory-sha256 <scan에서_확인한_해시>
```

## 온라인 암호화 백업

`backup`은 읽기 전용 source 연결에서 SQLite 온라인 backup API로 일관된 snapshot을 만든다. 외부 writer가 기록 중이어도 snapshot의 체인과 durable head를 다시 검증한 뒤 백업한다. source를 초기화하거나 고치지 않는다. copy 단계에는 30초 제한과 512MiB DB 크기 제한이 있다.

snapshot은 AES-256-GCM으로 64KiB씩 암호화한다. manifest의 DB 해시·크기·snapshot ID·생성 시각·체인 sequence/head·nonce 전체를 추가 인증 데이터로 묶는다. 키는 32바이트 private 파일에서 읽고 별도로 제공한 SHA-256 핀, 일반 파일/link, POSIX 권한을 검사한다. 키 자체는 백업 패키지나 출력 receipt에 넣지 않는다. Windows NTFS ACL 보호는 운영자 설정 영역이다.

```sh
python -m scripts.audit_storage backup --database <감사.sqlite3> --destination <새/감사.enc> --key-file <비공개/backup-key.bin> --key-sha256 <키파일_SHA256>
```

출력 receipt의 `backup_sha256`과 `head.seq/digest`를 신뢰된 별도 위치에 보관한다. 대칭 키를 새로 자동 발급하거나 변경하지 않는다. 기존 프로젝트의 CA/JWK/참조 암호화 키를 자동 재사용하지도 않는다.

## 새 경로로만 복원

`restore`는 별도로 제공한 패키지 SHA-256, AES-GCM tag, 원래 DB SHA-256, SQLite 스키마·전체 체인·durable head를 확인한다. 복호화한 파일을 정상 DB로 초기화/수리해서 통과시키지 않는다. 기존 audit 스키마가 정확히 있어야 한다. 검증에 성공한 후보만 새 경로로 게시한다.

```sh
python -m scripts.audit_storage restore --package <감사.enc> --destination <새/복원.sqlite3> --backup-sha256 <receipt의_패키지_SHA256> --key-file <비공개/backup-key.bin> --key-sha256 <키파일_SHA256> --minimum-seq <현재_신뢰된_체인_seq> --minimum-head <해당_seq의_digest>
```

`minimum-seq`와 `minimum-head`는 함께 제공한다. 이 checkpoint보다 오래되거나 해당 시점의 이력이 다른 정상 암호화 백업도 거부한다. 옵션을 생략하면 선택한 패키지의 정확한 내용만 검증하며 최신 시점까지 복구됐다는 증거는 아니다. receipt 자체나 로컬 DB와 함께 오래된 버전으로 되돌린 checkpoint는 외부 신뢰 앵커가 아니다.

복호화 snapshot은 전용 private 임시 디렉터리에 잠시 존재하며 성공/실패 시 정리한다. 보안 삭제/메모리 zeroization 보장은 아니다. 패키지 손상·다른 키/핀·truncation·추가 바이트·새 출력 경로 경쟁 때 살아 있는 DB를 건드리지 않는다. 모든 receipt의 `automatic_activation_allowed`는 false다. 환경 설정이나 사용 중인 DB 경로를 자동으로 바꾸지 않는다.

## 검증과 의미

최신 Windows/Linux 집중 시험은 각각42건 통과이며 새 이관·백업22건과 기존 SQLite writer20건의 같은 시험이다. 이전 단계의 Linux 확대177건과 Windows40건 결과는 별도 보존하며 중복 합산하지 않는다. [검증 요약과 소스 지문](infrastructure-results/extra-audit-transfer-backup-20261119.json).

시험에는 원본 바이트 보존·검토 이력 보존, 원래 상태가 없는 검토 거부, source pin/원본 변경/출력 경쟁, CLI scan→이관→백업→복원, 다른 키/핀/tag/추가·부족 바이트, 오래된 백업 checkpoint, 읽기 전용 opener의 missing/foreign DB 비생성, 동시 append 중 온라인 백업, 64KiB를 넘는 암호화 스트림 복원을 포함한다.

초기 Windows 시험에서 읽기 전용 fd의 fsync 실패와 SQLite backup 목적지 연결 미해제 때문에 정리 실패를 발견했다. 전용 stage를 쓰기 가능한 fd로 동기화하고 목적지 SQLite 연결을 명시적으로 닫아 수정했다. 실패를 통과로 집계하지 않고 수정 후 결과를 남겼다.

SQLite writer의 초기 검토 저장 경계도 보완했다. 새 분석 없이 검토 snapshot만 쓰는 요청은 commit 전에 거부하며, 이미 그런 상태로 손상된 DB는 무결성 오류로 취급한다.

## 이어갈 작업

- 실제 native 실행→SQLite HTTP 분석→백업/복원까지 묶은 운영 인수
- 취소/부하/중단과 복원 승인·checkpoint 보관 절차의 추가 검증
- 대규모 자료 검증 비용·페이지 조회·보관/압축 정리
- 다중 DB의 동일 시점 복원, 실제 호스트 재부팅/전원 단절, 원격 WORM/악의적인 관리자 rollback 방어는 이번 범위가 아니다.

백업한 것은 감사 기록이다. 현재 세션·권한·인증서를 함께 복구하거나 과거의 ALLOW를 재승인하지 않는다. 실제 모델 품질/F1 평가와 8시간 연속 시험은 새로 수행하지 않았다.
