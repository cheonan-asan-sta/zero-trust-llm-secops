# 최종 실행 이미지와 앱 입력 경계 검토

아래 이미지 검사 수치는 PR #54 시점의 고정 이미지에 관한 이력이다. 이후 행위 기록 보관 구현은
[자정 마감 기록](kim-midnight-closeout-20261113.md)에 따로 기록한다. 이전 이미지의 검사 수를
새 이미지의 검사 결과로 옮기거나 운영 승인으로 취급하지 않는다.

검사 기준 소스는 `e8b3e1ebd2685ef69ea8eb5167a52f7793153516`이다. 원래 `aitest`의
`835b911`과 비교해 `app` 트리는 동일하다. 채희주의 extra F1 개선과 탐지 기준은 변경하지 않았다.
이번 기록은 김택희 담당의 앱 입력 연결과 복원 검증, 현재 이미지의 발견 결과를 대조한 기록이다.

## 실행 근거

PR #54의 해당 커밋에서 CI 16개가 모두 통과했다. 일반 시험 3,452건과 제외 2건,
Docker 시험 3,454건, 실행 증거 mTLS 종단 검증 22개를 확인했다.
[CI 실행 기록](https://github.com/cheonan-asan-sta/zero-trust-llm-secops/actions/runs/43291251304)을 기준으로 한다.
로컬에서 시각이 전진해 미만료 토큰 전제에 실패한 시험과 Git 설치 의존으로 실패한 초기 시험은
성공 결과에 합산하지 않았다. GuardDuty 재처리 시험은 실제 저장된 임대 만료 시각을 기다리도록 보완했다.

앱과 프록시 두 이미지를 같은 최신 공개 취약점 DB 사본으로 검사했다. 각 이미지는 예열 1회와
반복 3회를 수행했으며, 검사 중 네트워크를 차단했다. 도구와 DB의 지문, 버전, 동일 입력,
반복 결과와 정상 및 취약 대조군, Java DB와 설치 패키지 목록을 대조했다.
도구는 기존 공급망 검사 실행기와 검증기를 재사용했다.

| 이미지 | Docker가 반환한 고정 해시 | Grype 발견 | Trivy 발견 |
| --- | --- | ---: | ---: |
| 앱 | `sha256:85a0a9f0bd83ab4e5b39c8fdca9d1d41edd7653c3101495a196eb66c3a6be756` | 213 | 213 |
| NGINX | `sha256:b565a9579cdabe43de09a5a278dc95ceee721dae1cacf85247effc4f6630d511` | 448 | 501 |

발견 수는 패키지, 버전, 각 도구의 advisory 단위다. 두 도구의 차이를 탐지 정확도나 확정된 악용 수로
계산하지 않는다. 원본 발견은 모두 보존했으며 자동 억제 항목은 없다.

현재 Docker는 OCI 목록 또는 manifest 해시를, 검사 도구는 설정 객체 해시를 반환했다.
OCI 원본 아카이브의 root, 해당 linux/amd64 manifest, 설정과 모든 선택된 파일 계층의 SHA-256,
크기 및 실행 이미지의 diff ID를 검증해 연결했다. 원래 요약과 검사 결과는 보존하고,
설정 객체를 대상으로 하는 파생 요약과 검증 기록을 별도로 작성했다.
이 구분은 [OCI ImageID 설명](https://github.com/opencontainers/image-spec/blob/main/config.md#imageid)과
[manifest의 설정 참조 규칙](https://github.com/opencontainers/image-spec/blob/main/manifest.md#image-manifest-property-descriptions)을 따른다.
공식 빌드 서명이나 원격 증명 완료를 뜻하지 않는다.

상세 지문은 [검사 요약 JSON](infrastructure-results/kim-final-runtime-20261113.json)에 기록했다.
실제 원자료는 `runtime/c03/kim-final-runtime-20261113-r5`에 보존한다.
별도 임시 Docker 환경에서 검사했고 소유한 검사 컨테이너와 볼륨의 잔여 수는 0이다.
처음 실행의 파일 공유, 권한, 디스크 부족 및 해시 계층 차이로 실패한 기록도 별도 디렉터리에 남겼다.

## 앱에서 확인한 입력 경계

| 경로 | 확인 내용 | 남겨 두는 범위 |
| --- | --- | --- |
| HTTP와 mTLS 응답 | 실행 증거 전송은 기존 urllib 또는 고정 mTLS http.client 경로를 사용한다. 관측 이미지의 Python은 3.12.16이며 HTTP framing 보완을 포함한 런타임 검증 23개가 통과했다 | 모든 HTTP 취약점이나 외부 의존성의 안전 증명으로 확대하지 않는다 |
| 세션과 행동 DB | 앱의 SQL은 서버가 정한 쿼리와 매개변수 바인딩을 사용한다. 일반 API가 원시 SQL, DB 파일, WAL 또는 changeset을 접수하는 경로는 확인되지 않았다 | 파일 시스템 권한을 가진 신뢰 주체와 향후 DB 업로드 기능은 별도 경계다 |
| 복원 입력 | 정지한 기록자 경계에서 백업을 만들고 서명, 해시, 세대와 저장 계약을 검증한다. 격리 복원 뒤 승인된 사본을 기동한다 | 서명을 검증했다는 사실만으로 모든 악성 DB나 archive 공격을 막는다고 판단하지 않는다 |
| 서명과 base64 | 신호, 행동 수집과 실행 증거는 canonical 내용과 서명, 출처 범위, 원문 해시를 검증한다. base64의 재인코딩 일치 검사도 있다 | 일반 decoder의 허용 범위를 다른 입력 경로의 인증 보장으로 대신하지 않는다 |
| 실행 관측 파일 | 소유자 전용 디렉터리와 일반 파일, 크기 제한, 서명 권한, 전체 수집 연결을 검증한다. 불완전하거나 과도하게 중첩된 JSON이 뒤의 정상 자료를 막지 않는지 확인했다 | 신뢰된 상위 관측기의 사실성을 대신 증명하는 EDR 기능은 없다 |
| 접근 집행 | 검증된 불리한 신호는 관련 접근을 403으로 바꾸고 무관 접근은 200을 유지한다. 행동 평가 자체의 집행 권한은 false다 | 모의 대응 결과를 실제 계정 변경으로 표시하지 않는다 |

이 대조의 소스는 `app/services/trusted_signals.py`, `app/services/behavior_context_store.py`,
`scripts/app_state_recovery.py`, `scripts/mtls_transport.py`와 실행 증거 수집기다.
공개 API에서의 도달성 검토와 공급자별 취약점 판정은 구분한다.

## 주요 발견의 현재 판단

관측 이미지의 SQLite는 **3.54.1**이고 FTS5와 session 기능이 포함돼 있다.
실행 중인 라이브러리 버전, source ID와 빌드 설정을 런타임 검증 결과에 남겼다.
다음 세 항목의 CNA 기록은 영향 범위를 3.54.0 미만으로 명시한다.
현재 관측 버전과 공급자 패키지 기록의 차이로 분류하고 원본 발견은 유지했다.

- [CVE-2026-119373 CNA 기록](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/119xxx/CVE-2026-119373.json): FTS5 관련 입력 조건과 영향 버전을 대조했다.
- [CVE-2026-119374 CNA 기록](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/119xxx/CVE-2026-119374.json): 손상된 FTS5 DB와 삭제 동작 조건을 대조했다.
- [CVE-2026-119379 CNA 기록](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/119xxx/CVE-2026-119379.json): 조작된 changeset 접수 조건을 대조했다.

APT 3.0.3은 [Debian의 CVE-2026-109518 기록](https://security-tracker.debian.org/tracker/CVE-2026-109518)에서
영향 버전이며 3.0.4가 수정 버전이다. 현재 Docker 빌드에는 root의 apt-get 실행이 있으므로
앱 컨테이너의 nonroot 설정만으로 빌드 중 위험을 해소했다고 판단할 수 없다.
**인프라의 기반 이미지와 패키지 설치 경로를 갱신할 때 우선 확인할 항목으로 남긴다.**

setuptools 70.3.0도 이미지에 남아 있다. [PyPA의 CVE-2025-47273 공지](https://github.com/pypa/setuptools/security/advisories/GHSA-5rjg-fvgr-3xxf)는
PackageIndex 다운로드 경로와 78.1.1 수정 버전을 설명한다. 앱 요청에서 해당 다운로드 함수를
호출하는 경로는 확인하지 못했다. 빌드는 해시가 고정된 wheel과 로컬 project wheel을 사용하지만,
이를 설치 도구 자체의 패치로 취급하지 않는다. 다른 setuptools advisory도 원본에 유지했다.

NGINX와 나머지 OS 패키지 발견은 각 공급자의 조건과 실제 기능 사용을 추가 대조할 대상으로 유지한다.
이번 검사 결과의 `security_gate_passed`, `production_approved`, `independent_review_complete`는 모두 false다.
이 기록으로 로컬 기능 인수와 이미지 검사는 정리하며 운영 배포 승인을 대신하지 않는다.
