# extra 개발: 암호화 공유 실행 참조와 프로세스 재시작 검증

2026-11-18. [HTTP 분석·감사 연결](extra-native-http-audit-20261118.md)의 후속이며 기준 커밋은 `43cf3b1`이다. 이번 변경도 로컬 extra에만 저장한다. 원격 push·CI·main/aitest 병합·AWS 배포는 하지 않는다.

## 기존 한계에서 발전한 부분

기존 등록부는 콜백과 검증 입력을 한 프로세스 메모리에 보관해 다른 프로세스나 재시작한 서버에서 실행 참조를 사용할 수 없었다. 이번에는 선택적으로 **로컬 SQLite에 암호화한 서명 입력 묶음**을 보관하고, 각 프로세스가 자신의 운영 객체와 고정된 출처 설정으로 다시 검증한다. 모델이나 클라이언트가 신뢰 문맥을 등록하는 API는 추가하지 않았다.

| 항목 | 기존 기본 모드 | 새 공유 모드 |
|---|---|---|
| 저장 | 메모리의 콜백·입력 | SQLite의 AES-256-GCM 암호문 |
| 프로세스 재시작 | 기존 참조 소멸 | 남은 원래 유효기간 안에서 다시 조회·검증 |
| 다른 프로세스의 철회 | 메모리를 공유하지 못함 | 삭제 트랜잭션 확정 후 각 reader가 조회/전달 시 재확인 |
| 신뢰 판단 | 현재 출처/세션 재검증 | 동일하게 현재 출처/세션 재검증. 저장된 판정이나 권한을 재사용하지 않음 |
| 실행 근거 DB | 읽기 전용 조회 | HTTP reader 초기화부터 읽기 전용. 신규 관측 등록도 차단 |
| 감사 파일 | 단일 프로세스 JSONL 체인 | JSONL 사용 시 프로세스별 파일로 분리해 동시 writer의 체인 분기 방지 |

공유 모드는 명시적으로 설정해야 한다. 설정이 없으면 기존 메모리 모드가 유지된다. 잘못된 공유 설정·핀·키·DB가 주어지면 메모리 모드로 대체하지 않는다. production에서 로컬 native 분석을 차단하는 기존 동작도 유지한다.

## 구현과 검증 경계

- `EncryptedNativeReferenceStore`는 기본 128건, 설정 최대 1,024건과 입력 묶음 최대 65,536바이트를 제한한다. 등록·철회·만료 정리는 SQLite 트랜잭션으로 처리하고 기록 쓰기에는 `synchronous=FULL`을 사용한다. 동시 등록에서도 용량 한도를 적용한다.
- DB에는 실행 참조 원문 대신 SHA-256, 소유 tenant/호출자 조합의 해시, 생성/만료 시각과 암호문을 보관한다. AES-GCM의 추가 인증 데이터에 저장소 ID·참조 해시·소유자 해시·시각을 묶어 행 간 암호문 이동과 메타데이터 변경을 검출한다.
- 암호화 대상은 서명된 세션/실행 근거·broker 영수증·원래 실행 요청이다. 재검증에 필요한 원래 nonce와 서명은 **암호문 안에** 존재한다. 원문 JWT, API 키, 수집기/CA 개인키, Python 콜백이나 pickle은 저장하지 않는다. 암호화 키는 별도 고정 파일에서 읽으며 DB에 넣지 않는다.
- 키의 32바이트 길이·SHA-256 핀·일반 파일·hardlink/symlink 여부를 확인한다. POSIX에서는 소유자/접근 모드도 확인한다. 키는 매 조회마다 다시 읽으므로 추론 중 삭제·변경도 차단된다. Windows의 NTFS ACL은 운영자가 별도로 보호해야 하며 POSIX 권한 시험과 동일하다고 주장하지 않는다.
- `SharedNativeAnalysisRegistry`는 고정된 `NativeServiceBundle` 스키마만 복원한다. DB 데이터가 파일 경로·URL·디코더·모듈을 지정하지 못한다. 복호화 성공만으로 근거를 신뢰하지 않는다.
- 각 reader는 현재 앱 정책·서명 출처·호출자 영수증·현재 세션·정확한 grant 소비·실행 근거 ledger를 다시 검증한다. 다른 앱 저장소나 다른 소유자에 연결하지 못한다. HTTP reader가 실행 근거 DB를 열 때는 SQLite 읽기 전용 연결을 사용하며 `check`로 새 근거를 등록할 수도 없다.
- 유효기간은 원래 근거 중 최단 시점, 실행 후 최대 30초다. 재시작·재조회가 만료를 연장하지 않는다. DB의 마지막 쓰기 시각보다 시간이 역행하면 거부한다. 조회 자체는 clock이나 실행/권한 이력을 갱신하지 않는다.
- 설정/키/근거/참조 DB는 서로 다른 파일이어야 하며 참조 DB를 앱 정책 DB나 설정 파일로 지정할 수 없다. 설정 오류 때문에 원래 근거 저장소에 새 테이블을 쓰지 않도록 검사한다.

## 설정과 시작

소스 checkout 또는 수집기 스크립트가 포함된 Docker runtime에서 사용한다. 기본 app wheel만 설치한 환경에 수집기 스크립트를 추가한 것은 아니다. 서버 운영자가 다음 형식의 JSON을 만들고 파일 전체의 SHA-256을 고정한다. 예시의 경로와 해시는 실제 로컬 파일 값으로 바꾼다.

```json
{
  "schema_version": "native-shared-analysis-config-1",
  "reference_db_path": "/var/lib/secops/native/references.sqlite3",
  "encryption_key_path": "/var/lib/secops/private/reference-key.bin",
  "encryption_key_sha256": "<32바이트 키 파일의 SHA-256>",
  "service_registry_path": "/var/lib/secops/trust/service-registry.json",
  "service_registry_sha256": "<서비스 등록부 SHA-256>",
  "service_ledger_path": "/var/lib/secops/evidence/service.sqlite3",
  "caller_registry_path": "/var/lib/secops/trust/caller-registry.json",
  "caller_registry_sha256": "<호출자 등록부 SHA-256>",
  "caller_environment": "local_oidc",
  "capacity": 128
}
```

```text
NATIVE_ANALYSIS_SHARED_CONFIG_PATH=<위 JSON의 절대 경로>
NATIVE_ANALYSIS_SHARED_CONFIG_SHA256=<위 JSON 파일 전체의 SHA-256>
```

두 설정은 함께 제공해야 한다. 설정 파일은 16KiB 이하의 엄격한 JSON이고 모든 파일 경로는 절대 경로다. 임의 HTTP 요청으로 이 값을 바꿀 수 없다. 기존 `ZERO_TRUST_DB_PATH`·정책·`TRUSTED_SIGNAL_SOURCES_PATH`도 동일한 실제 앱 이력을 읽도록 설정한다. 핀과 경로를 담은 설정 파일은 운영자 소유의 신뢰된 시작 설정이다.

서버 시작 시 `create_native_analysis_registry`가 선택한 backend를 구성한다. 신뢰된 수집기는 기존 `publish_service_analysis`를 그대로 사용한다. 공유 backend이면 고정 스키마의 서명 입력을 암호화해 등록한다. HTTP는 기존 `POST /analysis/native-service`에 `execution_ref` 하나만 보내며 tenant·호출자·analyst 이상 역할 검사를 유지한다.

## 감사 기록의 분리

공유 모드에서 JSONL 감사 backend는 설정한 `audit.jsonl` 대신 `audit.worker-<PID>.jsonl` 형태를 사용한다. 독립 프로세스가 같은 해시 체인의 마지막 해시를 각자 캐시한 채 쓰는 문제를 피하기 위한 조치다. 각 파일은 기존 `AuditStore`의 무결성·취소/쓰기 오류 처리로 검증한다.

기존 `audit.jsonl`은 보존하며 새 worker 파일로 자동 이관하지 않는다. 공유 모드를 켜면 앱의 분석 감사 스트림 전체가 worker 파일로 기록된다. 과거 파일과 다른 worker 파일은 현재 worker의 조회·metrics에 자동 합산되지 않는다.

**감사 조회·metrics는 현재 worker의 기록 기준**이다. 여러 worker의 감사 기록을 하나로 집계하거나 다른 worker의 `/results`를 자동 조회하는 기능은 이번에 구현하지 않았다. 단일 worker로 사용하거나 조회를 해당 writer에 연결하고, 이후 공동 감사 저장소/조회 계층을 추가해야 한다. 이 변경을 전역 감사 조회까지 완성된 다중 worker 서비스로 설명하면 안 된다.

모델 호출 전·후와 감사 저장 후 전달 직전의 재검증을 유지한다. 다른 프로세스가 실행 참조를 철회하거나 키/암호문이 바뀌면 결과를 반환하지 않는다. 감사 확정 후 철회된 경우에는 당시에 계산한 과거 분석을 보존하고 HTTP 성공 전달은 거부한다. 과거 감사 기록이 현재 권한이나 응답 수신을 증명하지 않는다.

## 무료 로컬 검증

[회귀 결과·소스 해시](infrastructure-results/extra-shared-native-analysis-20261118.json)와 [실제 systemd·프로세스·TCP HTTP 인수](infrastructure-results/extra-shared-native-analysis-20261118-systemd.json)를 기준으로 한다.

실제 systemd 인수 **29조건 통과**: 기존 24조건에 독립 프로세스의 참조 재구성, 새 프로세스의 동일 만료 유지, DB 평문 미노출, 재시작 후 철회 지속, 다른 reader의 추론 문맥 철회 인지 5조건을 더했다. 실제 TCP 요청은 공유 backend의 별도 운영 객체로 처리했고 프로세스별 감사 파일을 저장·재로딩해 응답 일치를 확인했다. 모델 응답은 명시적인 stub이며 유료 API와 AWS 호출은 모두 0회다.

Linux 관련 회귀 **744건 통과**이며 이 안에 새 공유 참조 회귀 **43건**이 포함된다. Windows 관련 시험은 **102통과·1skip**이다. skip은 POSIX 키 권한 시험이며 Linux에서 통과했다. Ruff와 `git diff --check`도 통과했다. 전체 프로젝트 테스트를 새로 모두 실행한 것은 아니다.

회귀에는 암호문/시각/저장소 ID/키 변조, 키/DB 삭제, 다른 소유자, 재시작, 만료/시각 역행, 경쟁 등록 용량 제한, 암호화됐지만 위조된 서명 입력, 임의 타입 복원 차단, 읽기 전용 ledger, 설정 핀/경로 충돌, 감사 파일 분리, 다른 프로세스의 모델 전/중/감사 후 철회를 포함했다. 독립 프로세스 시험은 새 reader 프로세스가 실제 운영 저장소와 시작 설정을 다시 여는 시험이다. HTTP 서버 강제 종료·호스트 재부팅 전체를 시험한 것은 아니다.

```sh
python -m pytest tests/test_shared_native_analysis.py tests/test_native_analysis_http.py tests/test_native_analysis_registry.py -q
python -m scripts.run_exec_history_controls --directory <새_결과_폴더> --shared-analysis
```

마지막 명령은 systemd PID1·Linux root·로컬 수집기 의존성 환경용이다. `--shared-analysis`는 기존 HTTP/내부 LLM 입력 시험도 포함한다. 실행기는 자신이 만든 UUID unit, 키·참조 DB·설정·TCP 서버와 임시 의존성만 정리했다. 과거 평가자료·정답·보고서·다른 프로젝트 리소스를 삭제하지 않았다.

## 남은 범위

- 이번 공유 저장소는 **같은 호스트의 로컬 SQLite 파일**이다. 다중 호스트 장애 전환, NFS 상의 동시 쓰기, 네트워크 분할을 검증하지 않았다.
- 오래된 DB 백업을 복원하는 rollback 공격에 대한 원격 증명은 없다. 로컬 clock 검사는 신뢰된 외부 단조 시계가 아니다. DB 복원으로 참조 철회가 되돌아오는 문제까지 해결했다고 주장하지 않는다. 현재 정책/원본 서명/만료 재검증은 유지한다.
- 만료된 행은 조회할 수 없고 다음 등록 시 정리된다. SQLite 여유 페이지의 암호문을 즉시 물리적으로 지우는 보안 삭제나 자동 키 교체는 이번 범위가 아니다. 공유 키 배포/백업/교체와 호스트 관리자 권한 보호는 별도 운영 작업이다.
- 실제 기업 SSO, 호스트 전체/PAM 감사, 원격 attestation, 독립 모델 품질 목표는 여전히 별도다. 이번 시험은 새 F1 평가가 아니다. 원본·정답·탐지 임계값을 바꾸지 않았고 기존 개발 360건 F1 93.41%를 그대로 이전 결과로 유지한다.

다음 우선 작업은 프로세스별 감사 기록의 통합 조회/무결성 확인과 공동 감사 쓰기 방식이다. 그 뒤 호스트 간 근거 전송과 운영 인증원을 연결하고 고정된 새 실행 사례로 실제 모델 품질을 비교한다.
