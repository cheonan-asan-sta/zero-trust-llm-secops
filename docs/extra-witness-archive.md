# 이전 감사 서명 세대의 불변 보관과 복구

용량을 모두 쓰고 마지막 영수증까지 확인한 세대는 `audit_witness_archive`로 내보낼 수 있다. 파일에는 스트림 식별자, 원본 위치의 해시, 공개키와 4,096개 서명 영수증이 들어간다. 내보낼 때 서명 저널과 확인 DB의 마지막 영수증이 같은지 확인한다. 원본 경로를 참조하지 않는 검증기는 전체 서명, 순서, 이전 영수증 해시와 마지막 감사 위치를 대조한다.

감사 원본 이벤트, 서명 개인키, 운영용 확인 DB는 별도로 관리된다. 감사 이벤트까지 복구하려면 해당 감사 위치를 포함한 기존 암호화 SQLite 백업과 복구키가 필요하다. 복구 출력은 검토용 SQLite 파일이다.

## 내보내기와 보관

1. 이전 세대의 확인이 끝났는지 검토한다. 운영자가 보관한 기존 프로필과 마지막 영수증 해시로 내보낸다.

   ```text
   python -m scripts.audit_witness_archive export --control OLD_CONTROL --profile-sha256 OLD_PROFILE --terminal-sha256 OLD_TERMINAL --destination generation.json
   ```

2. 결과의 파일 SHA-256, 공개키 지문과 마지막 영수증 해시를 원본 호스트와 별도의 운영자 기록에 저장한다. 가능하면 기존 감사 SQLite의 암호화 백업도 별도로 보관한다. 감사 백업 SHA-256과 복구키 지문은 백업 파일과 분리하고 키는 별도 비밀 저장소에 둔다.
3. 원본 호스트와 관리 권한이 분리된 계정의 기존 S3 Object Lock 버킷을 사용한다. 운영 정책에서 승인한 UTC 보존 기한을 `YYYY-MM-DDTHH:MM:SSZ` 형식으로 지정한다. 파일 해시로 정한 객체 키에 조건부 저장한다. 별도 관리 계정과 복구 계정의 권한 설정은 배포 전에 검토한다. [S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)

   ```text
   python -m scripts.audit_witness_archive upload-worm --archive generation.json --archive-sha256 ARCHIVE_PIN --public-key-sha256 KEY_PIN --terminal-sha256 OLD_TERMINAL --bucket ARCHIVE_BUCKET --bucket-owner ARCHIVE_ACCOUNT --region REGION --retain-until RETAIN_UNTIL_UTC
   ```

4. 업로드는 `If-None-Match: *`와 SHA-256 체크섬을 사용한다. 반환된 동일 버전을 다시 읽어 `COMPLIANCE`, 보존 기한, 해시와 서명 전체를 확인한 뒤 버전 ID를 출력한다. 객체 키, 버킷·소유 계정·리전, 버전 ID와 보존 기한을 2단계의 운영자 기록에 추가한다. 원본 호스트를 폐기하기 전 별도 복구 계정으로 해당 버전을 실제로 읽을 수 있는지 확인한다. [조건부 업로드](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html) · [객체 버전 조회와 보존 정보](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html)

업로드 역할에 대상 접두사로 한정한 `s3:PutObject`와 `s3:PutObjectRetention`을 부여한다. 업로드 후 읽기 검증과 복구에는 `s3:GetObjectVersion`과 `s3:GetObjectRetention`이 필요하다. 복구 역할은 읽기 권한만 갖도록 분리한다. 버킷 정책으로 조건부 쓰기와 허용 보존 기간을 제한하고 삭제 권한은 보관·복구 역할과 분리한다. 업로드 응답이 유실되거나 중복 요청이 거부되면 저장소 관리자가 동일 객체 키의 버전 ID를 운영 기록과 대조한다. 아래 정확한 버전 읽기로 보관을 확인한다. [S3 API별 권한](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-policy-actions.html) · [Object Lock 보존 정책](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-managing.html)

## 원본 호스트 없이 복구

별도 복구 환경에서 운영자 기록에 고정한 버전을 받아 새 파일에 저장한다. 조회된 버전·잠금 모드·보존 기한·서명 중 하나라도 검증에 실패하면 복구 파일을 게시하지 않는다. 보존 기한이 지난 버전은 여전히 조회 가능한 경우 무결성을 검증할 수 있고, 출력에 활성 보존 여부가 표시된다.

```text
python -m scripts.audit_witness_archive fetch-worm --archive-sha256 ARCHIVE_PIN --public-key-sha256 KEY_PIN --terminal-sha256 OLD_TERMINAL --bucket ARCHIVE_BUCKET --bucket-owner ARCHIVE_ACCOUNT --region REGION --version-id VERSION --retain-until RETAIN_UNTIL_UTC --destination recovered.json
```

이미 안전하게 전달한 파일은 네트워크와 개인키 없이 확인할 수 있다. 파일명이나 원래 저장 경로에 의존하지 않는다.

```text
python -m scripts.audit_witness_archive inspect --archive recovered.json --archive-sha256 ARCHIVE_PIN --public-key-sha256 KEY_PIN --terminal-sha256 OLD_TERMINAL
```

원본 이벤트까지 필요하면 별도로 보관한 암호화 백업을 복호화한다. 백업 해시와 키 지문을 대조하고, 백업이 이전 세대의 마지막 서명에 기록된 감사 위치를 포함할 때만 새 복구 파일을 게시한다. 복구 환경의 출력 디렉터리는 접근을 제한한다.

```text
python -m scripts.audit_witness_archive restore-audit --archive recovered.json --archive-sha256 ARCHIVE_PIN --public-key-sha256 KEY_PIN --terminal-sha256 OLD_TERMINAL --backup audit.aes --backup-sha256 BACKUP_PIN --key-file RECOVERY_KEY_FILE --key-sha256 RECOVERY_KEY_PIN --destination recovered.sqlite3
```

## 시험 범위

로컬에서 실제 한도인 4,096개 유효 서명 fixture를 내보냈다. 원본 경로를 치운 뒤 별도 CLI 프로세스에서 전체 이력을 검증하고, 암호화 백업을 새 SQLite로 복구했다. 중간 서명 손상, 누락, 잘못된 키·마지막 영수증 해시도 검사했다. 원격 API는 로컬 SDK 스텁으로 검증했다. 실제 별도 계정과 버킷의 권한·보존 정책 및 네트워크 경로 검증은 운영 인수 항목이다.

감사·세대 전환·백업을 포함한 회귀 묶음은 Windows 59개 통과·5개 제외, Linux 64개 통과였다. 이후 오래된 암호화 백업의 거부를 추가하고 보관·복구 테스트 11개를 양쪽에서 각각 통과했다. 중복 쓰기·다른 객체 버전·잘못된 잠금 모드·짧은 보존 기한·손상된 객체 거부도 확인했다. AWS 요청과 리소스 생성은 0회였다.
