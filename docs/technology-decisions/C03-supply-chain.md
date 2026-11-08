# C03 공급망 검사 비교: 로컬 첫 시험

11/8 3주차 잔여 묶음: [인프라 조건부 선정·현재 mTLS 부하/복구](../infrastructure-selection-acceptance.md). 채희주가 동시성1/4/8·3반복의576요청(153허용/423거부), gateway장애3회 전달0·새 grant복구, 인증된 관측·37개 인수와 Linux2560개를 검증했다. 과거 후보 비교 지문과 현재 실행 증거를 연결해 C01/C02는 로컬 조건부, C03는 현재 이미지 재검사/앱 영향 독립 대조 전 보류한다. 운영 승인·대안 후보의 현재 부하 새 비교·팀원 독립 재현·3주차 전체 완료와 구분하며 정확한 head/병합 후 CI는 PR을 따른다.

11/5 후속 [우선 런타임 패치·새 이미지 재검사](../supply-chain-priority-patches.md)를 추가했다.
과거 b466 이미지 비교는 아래에 보존하고 새 이미지/동일 DB 결과는 별도 JSON으로 구분한다.
검사기 잔여·배포판/로컬 패키지 매칭·공급자 기록 차이를 억제 없이 기록하며 최종 도구 선정은 미완료다.

11/5 추가 [인프라 영향 조건 검토](../supply-chain-impact-review.md)는 공식 자료와 고정 이미지 실물3회로
200항목의 조건·source mapping을 대조했다. P1 검증17·특정 pip 완화2, 수정/억제/실제 악용 확인0이다.
현재 이미지의 새 검사·앱 독립 도달성 검토·최종 도구 선정은 남아 있다.

11/5 후속 [발견 차이 재분석기](../supply-chain-findings-review.md)를 추가했다. 고정 요약/원본 27개와
반복·대조군을 다시 확인해 native180·직접 alias6·한쪽 전용14, 심각도 차이78을 재현했다.
200항목 모두 실제 영향 미평가이며 아래 11/3 검사 결과를 최신 이미지 새 검사로 바꾸지 않는다.

2026년 11월 3일 · 실행·측정: 채희주 작업 브랜치에서 Codex 도구 사용.
독립 팀원 재현·운영 채택은 미완료다. 신규 검사기를 제품/CI의 필수 게이트로 연결하지 않았다.

## 목적과 사전 고정 조건

제로트러스트 서비스가 사용하는 이미지의 구성과 취약점 정보를 재현 가능하게 확인한다.
서명된 관찰·정책·집행 기능을 바꾸는 시험이 아니다. Syft+Grype 파이프라인과 Trivy를 같은
**이미지 archive SHA-256**에서 실행하고 패키지 식별·발견·시간/자원을 비교한다.
발견 수가 많다는 이유만으로 정확도가 높은 검사기로 선정하지 않는다.

| 항목 | 고정 조건 |
|---|---|
| 소스 | `aitest` PR #2 병합 `b4660ad1915fc3e2d39159f003940ec085f9f19c`의 git archive |
| 앱 이미지 | 해당 소스 Dockerfile의 FROM만 아래 base digest로 고정. 한 번 빌드·저장한 tar를 양 후보가 공유 |
| 기반 이미지 | `python@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704` |
| 후보 | Syft 1.56.0 + Grype 0.121.1 / Trivy 0.76.1, Linux amd64 |
| 바이너리 | [공식 release URL·SHA-256 고정 목록](../../infra/supply-chain/tools.lock.json) |
| 출처 검증 | 공식 release API digest 일치 + Cosign으로 체크섬 파일의 Sigstore bundle·정확한 workflow identity·GitHub OIDC issuer 확인 + archive가 검증된 체크섬과 일치 |
| 컨테이너 | 동일한 digest 기반 runner, UID/GID 10001, CPU 2개·메모리/합산 swap 2GiB·PID 128, read-only root, 모든 capability 제거, no-new-privileges |
| 노출 범위 | 공개 실행 파일·앱 이미지 tar·DB cache·결과 디렉터리만 사용. Docker socket·호스트 홈·키·`.env.local` 마운트 없음 |
| 통신 | 서명 검증 신뢰 자료와 DB 준비에만 네트워크 허용. 버전 확인·검사·양/음성 대조군은 `network=none` |
| 검사 범위 | 최종 이미지의 OS/Python 패키지와 취약점. Syft squashed → Grype SBOM / Trivy image input + list-all-pkgs |
| 반복 | Docker 내부 Linux 볼륨에 DB 준비 1회, warm-up 1회, 준비 후 검사 3회씩. DB 준비/첫 검사와 반복을 구분 |
| 대조군 | CycloneDX metadata만 사용: requests 2.31.0/2.32.0에서 CVE-2024-35195 존재/부재 확인. 취약한 코드를 설치·실행하지 않음 |

Sigstore identity는 Syft/Grype의 공식 `release.yaml@refs/heads/main`, Trivy의
`reusable-release.yaml@refs/tags/v0.76.1`로 정확히 제한한다. 서명은 게시자 경로와 파일 무결성의 근거이며
코드가 악성이 아니라는 증명은 아니다. Cosign 3.1.4 bootstrap은 공식 release SHA-256을 HTTPS로 확인했다.
해당 자산의 GitHub SLSA attestation 조회는 HTTP 404였다. **Cosign 자체의 독립 provenance 검증을 완료했다고 주장하지 않는다.**
[Anchore 공식 검증 절차](https://oss.anchore.com/docs/installation/verification/).

Trivy 공식 공지의 영향받은 배포본(v0.69.4 및 특정 DockerHub 배포본 등)을 피하고 고정된 GitHub release를 사용했다.
이것이 신규 버전에 대한 절대적 안전 보증이나 다른 후보 대비 우위는 아니다.
[Trivy 공식 보안 공지](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23),
[공식 설치·서명 안내](https://trivy.dev/docs/latest/getting-started/installation/).

요청 라이브러리의 해당 공지는 `<2.32.0` 영향·`2.32.0` 수정과 CVE/GHSA 대응을 명시한다.
음성 대조군은 **이 공지에만** 음성이다. 2.32.0에서 다른 취약점이 없어야 한다는 조건이 아니다.
[requests 작성자 공지](https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56).

## 실행과 원자료

저장소 루트에서 Python 3.12·Docker Linux amd64 엔진을 준비한 뒤 다음을 실행한다.
공개 배포 파일과 DB 다운로드에는 인터넷·로컬 디스크가 필요하다. AWS/유료 모델 API는 호출하지 않는다.

```powershell
.\.venv\Scripts\python.exe -m scripts.compare_supply_chain --source-ref b4660ad --repeats 3
```

스크립트는 이 실행에서 만든 고유 이름 컨테이너·앱 익명 볼륨·이미지 태그만 정리한다.
`runtime/c03/`의 도구·DB·스캔한 이미지 tar·raw 결과는 재현용으로 남기며 Git/Docker build context에서 제외한다.
실제 검사 DB는 요약에 이름을 남긴 Docker 내부 named volume에 보관한다. 실행 프로세스가 없는 로컬 자료이며
후속 실행에서 원본을 덮어쓰지 않는다. 이름과 지문을 확인한 뒤 동일 snapshot 재현에 사용하거나 필요 종료 시 삭제한다.
호스트 전체 prune, 다른 컨테이너 중지·삭제, 호스트 서비스/키 변경은 수행하지 않는다.
실행 디렉터리 변경은 `runtime/c03/` 내부로만 허용한다.

주요 원본은 `input/app.tar`, `out/run-*-{syft,grype,trivy}.json`, `out/*.metrics.json`,
`out/installed.json`, `out/*db-status.stdout`, `out/verify-*.stderr`다.
공개 요약은 결과 파일에 원본 SHA-256·도구/DB 버전·조건과 실제 결과를 남긴다.
이미지 tar와 큰 DB는 GitHub에 올리지 않으며 동일 tar 재현은 보관자가 원본을 전달해야 한다.

패키지 식별은 이미지 안의 `importlib.metadata`와 설치 상태가 `installed`인 `dpkg-query` 결과에 대조한다.
Python 이름은 PEP 503 형식으로 맞추고 Debian epoch/version은 보존한다.
설치 metadata가 절대적인 실제 코드 존재의 정답은 아니며, 바이너리 내장 패키지 등 다른 범위는 따로 해석한다.
발견은 package/version/native advisory ID별로 중복 제거한다. CVE와 GHSA 등의 alias 차이로 단순 교집합이 줄 수 있다.

시간은 컨테이너 안 scanner 자식 프로세스의 고해상도 경과 시간·user/system CPU 시간과
Docker 호출 전체 시간을 분리한다. 자원은 `ru_maxrss`와 cgroup `memory.peak`/`memory.events`다.
Syft+Grype의 지연은 두 단계 합계, 메모리는 두 컨테이너 중 큰 값으로 비교한다.
세 번 측정의 P95는 최댓값에 해당하므로 안정적인 운영 지연 추정으로 일반화하지 않는다.
네트워크 DB 준비·이미지/결과의 Windows bind mount·cache warm-up·OS 캐시와 실행 순서의 영향을 명시한다.

## 첫 적용에서 확인한 내용

[공개 원자료 요약](../infrastructure-results/c03-windows-20261103.json)에 도구·DB 지문,
최종 재측정과 선행 탐색 기록·중단 시도·원본 파일 지문을 보존했다.
스캔 이미지 ID는 `sha256:5a64e8c43d9e1712996f29ff9bf6adbb3b19270f67facea535ee428ec754fe54`,
공유 tar SHA-256은 `5d8dd0efd36b464767f465368d178d8a1ae692e7768d966188623cb5dc8940f7`다.
검사 전후와 재사용 전 DB 지문이 일치했다.

설치 metadata 기준은 OS 패키지 87개·Python 배포 패키지 44개, 합계 131개다.
Syft와 Trivy 모두 이 범위의 이름·전체 버전 131개가 일치했고 반복 간 목록도 같았다.
Trivy의 Debian `Version`·`Release`·`Epoch` 분리 필드를 합쳐 비교했으며 이를 실제 패키지 누락으로 오인하지 않았다.
앱 탐지 정규화·규칙은 수정하지 않았다. requests의 지정 CVE 양성/음성 대조군은 각 후보 2개, 합계 4개 통과했다.

| 발견 단위: 패키지/버전/native advisory ID | Grype | Trivy | 해석 |
|---|---:|---:|---|
| Debian | 180 | 185 | Trivy에만 있는 5행은 `TEMP-*` 식별자. 실제 영향·오탐 판정은 미완료 |
| PyPI | 6 | 6 | pip 25.0.1의 GHSA/CVE 표현 차이. Grype `relatedVulnerabilities`에서 6개 alias 대응 확인 |
| 별도 binary catalog | 9 | 0 | Grype의 Python 3.12.15 binary 발견. 이번 Trivy 설정/출력의 별도 binary 범위와 같지 않음 |
| 합계 | 195 | 191 | 개수로 탐지 정확도·우위를 판정하지 않음 |

native ID 그대로 같은 행은 180개다. 위 provider-reported alias 6개를 대응하면 공통 186행,
Grype 고유 binary 9행·Trivy 고유 TEMP 5행으로 차이를 분류할 수 있다.
이는 **검사 결과 metadata의 첫 분류**이며 각 취약점의 벤더 수정/백포트·도달 가능성·실제 악용성을 독립 확인한 결과가 아니다.
195/191을 보안 이벤트 탐지의 TP/FP로 사용하지 않는다.

Windows 폴더에 Grype DB를 직접 준비한 선행 시도는 Docker 호출 약 488.894초 시점에 작업자가 중단했다.
종료 137은 이 중단의 결과이며 OOM으로 판정하지 않았다. 해당 시도는 비교 결과에 포함하지 않는다.
Docker 내부 Linux 볼륨에서는 Grype 약 126.518초, Trivy 약 45.695초에 DB 준비를 마쳤다.
이 값은 서로 다른 DB 크기·출처·전송/압축·캐시를 포함하므로 도구의 검사 지연 순위가 아니다.
실제 DB 파일은 각각 3,381,301,248바이트와 1,680,371,712바이트였다. 사용한 snapshot은 로컬 Docker 볼륨에 보관한다.
중단된 Windows 준비의 부분 DB 폴더 삭제는 자동 실행 검토에서 `blocked by policy`로 거부되어
`runtime/c03/cache/`에 파일만 남겼다. 실행 프로세스나 클라우드 자원이 아니며 구체적인 차단 사유는 제공되지 않았다.

첫 성공 반복은 전체 회귀 검증 작업과 병행했으므로 시간/자원은 탐색적 기록으로 보존한다.
후속 측정은 같은 이미지 tar와 변경되지 않은 DB 볼륨을 재사용하고, 다른 빌드/전체 테스트가 끝난 뒤 수행했다.
두 단계 기록과 준비 시간을 구분하고 이 작은 로컬 표본으로 최종 도구를 선정하지 않는다.

| 후속 측정: 조건당 3회 | 검사 시간 P50 | P95/최댓값 | 자식 RSS 최댓값 | CPU 시간 P50 |
|---|---:|---:|---:|---:|
| Syft → Grype 합계 | 9.315초 | 13.711초 | 286.418MiB | 10.609초 |
| Trivy | 17.585초 | 26.077초 | 135.457MiB | 1.957초 |

이 이미지·로컬 조건에서는 단계 합계 지연과 CPU/RSS의 양상이 다르다.
준비 완료 cache·고정 실행 순서·Windows 이미지/결과 마운트와 호스트 잡음이 있어 시장 전체 순위로 해석하지 않는다.
3회 중 P95는 최댓값이고 독립 호스트 재현도 아니다. 다음 비교에는 실행 순서 교차와 Linux 내부 이미지 보관 조건을 추가한다.

기능·회귀 검증은 Windows Python 3.12.9의 전체 566건(기존 경고 3개), Linux Docker의 전체 566건
(기존 경고 2개)과 Ruff가 통과했다. 신규 21건은 다운로드/체크섬·압축 경로·버전·집계의 보안/정합성 시험이다.
이 통과 수를 이벤트 탐지 품질 목표 통과로 표시하지 않는다.

현재 Docker는 cgroup v1이며 수집기의 v2 경로 `memory.peak`·`cpu.stat`·`memory.events`는 노출되지 않아 `null`이다.
이를 0으로 해석하지 않는다. 실제 메모리 비교는 scanner 자식의 `ru_maxrss`이며 컨테이너 전체/파일 cache 메모리를 포함하는 수치가 아니다.
Grype의 버전 조회는 네트워크 차단 로그를 남겼지만 검사 exit 0·JSON·지정 advisory 대조군을 확인했다.
검사 중 외부 통신 성공이나 DB 갱신으로 해석하지 않는다.

## 한계와 다음 판정

첫 적용 후 패키지 누락/추가, 공급자 advisory와 실제 영향 범위의 불일치를 검토하고 11/15 비교 초안을 만든다.
11/22 선정은 탐지 수 합계 대신 요구 범위·재현·오탐/누락 조사·지원/유지보수·운영 비용을 근거로 한다.
이 작은 대조군으로 스캐너의 전체 정밀도·재현율을 계산하지 않는다. 보안 이벤트 탐지 95%/5% 목표와도 별개다.

DB별 출처·생성 시각·수록 범위가 다르므로 동일 이미지라도 발견 수는 달라질 수 있다.
소스의 범위 의존성 설치는 새 빌드마다 달라질 수 있다. 이번 비교는 **공유 tar 내부**에서만 바이트 동일성을 보장하며
재빌드가 같은 이미지 digest를 만든다고 주장하지 않는다. 앱/의존성 lock과 실제 개선은 별도 작업이다.
비밀값·IaC·서명 정책 집행·실제 취약점 악용 가능성·SBOM 서명/보존 운영은 이 시험의 검증 범위 밖이다.
다른 팀원이 아직 재현하지 않았으므로 독립 검증자를 임의로 기재하지 않는다.
