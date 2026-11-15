# GuardDuty EventBridge 경보의 로컬 입력

로컬 전달자가 서명한 EventBridge JSON을 수집기의 `append-guardduty`로 넣는다. 수집기는 매핑된 관측을 기존 SQLite spool에 보존하고 서명해 `POST /zero-trust/signals/inbox`로 보낸다. 별도 worker가 같은 테넌트의 지정 사용자와 자원에 해당하는 세션을 회수한다. 같은 사용자라도 다른 자원에 대한 세션은 독립적으로 판단한다.

[AWS EventBridge 경보 형식](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings_eventbridge.html) 중 직접 계정의 활성 `AccessKey` finding을 지원한다. 로컬 적용 기준은 심각도 7~10이다. 봉투와 상세의 계정·리전, finding ARN, 생성·갱신·전달 시각, `resource.accessKeyDetails.principalId`를 대조한다. 계정·리전과 주체가 명시된 매핑에 있어야 한다. 기록되는 관측에는 로컬 주체·자원과 상세 내용의 SHA-256을 담는다. AWS 원문·키 ID·IP는 Inbox와 정책 저널에 전달하지 않는다.

## 준비와 실행

기존 [수집기 설정](continuous-signal-collector.md)에 따라 앱과 worker에 같은 정책 DB 및 공개 출처 등록 파일을 지정한다. 새 수집기는 아래처럼 초기화한다.

```sh
python -m scripts.continuous_signal_collector init \
  --directory runtime/guardduty-collector --tenant local \
  --source-id local-guardduty --kind guardduty \
  --subject demo-user --resource zt-demo-documents
```

생성된 `sources.json`의 공개 출처 항목을 앱·worker의 등록 파일에 추가한다. 이 출처의 `observation_kinds`는 `["guardduty"]`이며 `guardduty_resource_ids`로 자원 범위를 제한한다. 수집기의 개인키는 수집기 디렉터리에 보관한다.

로컬 전달자의 별도 Ed25519 공개키를 `runtime/guardduty-collector/guardduty-map.json`에 등록한다. 아래 예시의 공개키 값은 실제 PEM으로 바꾼다.

```json
{
  "tenant_id": "local",
  "account": "111122223333",
  "region": "ap-northeast-2",
  "forwarder_public_key_pem": "<Ed25519 공개키 PEM>",
  "principals": {
    "AWS-PRINCIPAL:session": {
      "subject_id": "demo-user",
      "resource_id": "zt-demo-documents"
    }
  }
}
```

전달자는 UTF-8 finding 파일의 정확한 바이트에 64바이트 Ed25519 서명을 붙인다. 아래 명령에는 앱을 실행한 로컬 origin을 넣고 수집기 API 키는 기존 방식대로 환경 변수 `SIGNAL_COLLECTOR_API_KEY`로 전달한다. mTLS를 쓰는 경우 아래 두 수집기 명령에 동일한 HTTPS origin과 `--tls-profile`을 지정한다.

```sh
openssl pkeyutl -sign -rawin -inkey forwarder.pem -in finding.json -out finding.sig
python -m scripts.continuous_signal_collector append-guardduty \
  --directory runtime/guardduty-collector --base-url http://127.0.0.1:18080 \
  --event-signature finding.sig < finding.json
python -m scripts.continuous_signal_collector run \
  --directory runtime/guardduty-collector --base-url http://127.0.0.1:18080
```

앱과 같은 설정의 worker는 `python -m scripts.signal_worker`로 실행한다. `append-guardduty` 성공은 로컬 입력 저장, 수집기 `acknowledged`는 서버 접수, Inbox `completed`는 정책 처리 완료를 의미한다. 경보 원문을 읽은 뒤 변환하거나 다시 인코딩하면 원래 서명과 일치하지 않는다.

## 중복과 지연

- EventBridge `id`는 전달 식별자다. 수집기 이벤트 ID는 계정·리전·finding ID·UTC 갱신 시각으로 결정한다. 같은 상세의 재전달은 전달 ID가 달라도 한 번만 접수한다. 갱신 시각이 바뀌면 새 관측을 만들고, 같은 버전의 상세가 달라지면 spool의 충돌 검사에서 처리 중단과 오류를 기록한다.
- 최초 접수는 finding 갱신 시각부터 5분 이내에만 허용한다. 새 전달 시각이나 서명 발급 시각으로 이 한도를 늘릴 수 없다. 이미 접수된 경보는 큐에서 지연돼도 worker가 현재 출처·키·주체·자원 권한을 재확인한 뒤 제한을 적용한다.
- 관측은 해당 자원의 기존 허용을 회수하고 후속 허용을 차단한다. 갱신 순서 역전, 재시작, 보관 이관에는 기존 Inbox·정책 저널의 중복 처리 규칙을 적용한다.

로컬 운영자는 매핑과 수집기 입력 디렉터리를 보호하고 서명 전 원문의 출처를 확인한다. 수신 형식은 AWS 문서를 따르며, 원문을 서명하는 주체는 등록된 로컬 전달자다. 실제 AWS 수신과 계정 비활성화·키 폐기 같은 외부 조치는 별도 작업이다.

```sh
python -m pytest -q tests/test_guardduty_eventbridge.py
```

통합 시험은 실제 loopback HTTP 접수와 SQLite를 사용한다. 정책 반영 직후 worker를 강제 종료하고 별도 프로세스로 재시작해 영수증을 복구한다. 대상은 HTTP `403`과 콘텐츠 없음, 무관한 사용자와 같은 사용자의 다른 자원은 `200`과 콘텐츠 반환을 확인한다.
