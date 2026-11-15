# C03 우선 취약점 런타임 패치

2026년 11월 5일 · 채희주 인프라·컨테이너·빌드 담당 / Codex 도구 보조.

[이전 영향 검토](supply-chain-impact-review.md)의 P1 17항목을 먼저 대상으로 삼았다.
앱·테스트·Lambda Dockerfile에 고정한 Python 3.12.16, 검증한 SQLite 3.54.1,
pip 26.3과 HTTP 프레이밍의 로컬 보안 패치를 연결했다. 탐지 규칙·정책·앱 API 구현은 변경하지 않았다.
이는 배포 후보의 런타임 보완이며, 과거 200항목의 전면 해결·운영 승인·독립 팀원 검토 완료는 아니다.

실행 근거는 [패치·검증 JSON](infrastructure-results/c03-priority-patches-20261105.json),
검사 비교는 [새 이미지 재검사 JSON](infrastructure-results/c03-patched-scan-20261105.json)에 둔다.
과거 이미지·평가 대장·원본 결과는 보존하고 이 후속 기록으로 연결한다.

## 우선 조치와 남은 판단

| 기존 항목 | 적용 내용 | 판정 범위 |
|---|---|---|
| C03-0005 / CVE-2026-114583 | Python 3.12.16의 tar 필터 수정 포함 | 공식 보안 릴리스 적용. 모든 tar 사용의 안전성 증명은 아님 |
| C03-0006 / CVE-2026-115557 | Python 3.12.16의 유출 eMudhra 키 거부 포함 | Python SSL 경계의 수정. Windows/호스트 OS 신뢰 저장소 변경 없음 |
| C03-0004 / CVE-2026-103995 | Content-Length 숫자·chunk-size 16진수 문법 검사와 정상 SP/HTAB 처리 | 로컬 유지보수 패치. 3.12 공식 릴리스에 병합됐다고 표시하지 않음 |
| C03-0116~0127 / SQLite 12항목 | SQLite 3.54.1 원본을 고정·컴파일해 실제 Python이 연결하는 공유 라이브러리 교체 | upstream 수정 버전과 런타임 source ID 확인. 개별 악용 12건 재현/앱 도달성 검토 완료는 아님 |
| C03-0115 / CVE-2025-70873 | zipfile 확장·SQLite CLI가 이번 런타임에 포함되지 않음 | upstream은 3.52.0 수정으로 기록하지만 동결 Debian snapshot은 open. 검사 결과는 억제하지 않고 차이를 남김 |
| C03-0114 / CVE-2021-45346 | 공급자의 disputed 판단·불신 DB 입력 경계를 유지 | 버전 상승으로 해결됐다고 닫지 않음. 김택희의 입력 경계 독립 검토 남음 |
| C03-0195~0200 / pip 6항목 | pip 26.3, 외부 wheel 버전·SHA-256 고정, 소스 배포 설치 차단, 프로젝트 wheel 별도 생성·해시 검증 | 설치 경로 보완. 임의 wheel/빌드 코드가 신뢰 가능해졌다는 뜻은 아님 |

Python 릴리스의 수정 범위는 [PSF 릴리스 기록](https://www.python.org/downloads/release/python-31216/),
SQLite의 실제 배포 원본/source ID는 [릴리스 기록](https://www.sqlite.org/changes.html),
zipfile·disputed 해석은 [SQLite 공급자 CVE 설명](https://www.sqlite.org/cves.html)을 따른다.
SQLite 12항목은 기존 [동결 vendor 입력](infrastructure-results/c03-impact-inputs-20261105.json)과
[Debian tracker](https://security-tracker.debian.org/tracker/source-package/sqlite3)의 sid 수정 기록도 대조했다.
trixie의 패키지 상태와 우리 로컬 빌드의 upstream 코드를 같은 것으로 취급하지 않는다.

## HTTP 패치의 출처와 유지보수

3.12용 [CPython PR #160772](https://github.com/python/cpython/pull/160772)는 확인 시점에 **open**이다.
그 head `1c8d928392cf0b4e84e392eb12f34557c9a0373f`와 이미 main에 병합된
[정상 공백 보정](https://github.com/python/cpython/commit/9f52b443c002cccfb54bda0706a9276b6b4a109d)을
바탕으로 작은 로컬 patch를 유지한다. 원본 파일·patch·적용 결과의 SHA-256이 모두 맞아야 설치한다.
원본이 바뀌거나 문맥/offset이 어긋나면 빌드는 실패한다. 공식 새 보안 릴리스가 나오면 이 로컬 patch의
필요성과 중복 여부를 먼저 재검토하고, 해시만 바꿔 실패를 우회하지 않는다.

작은 in-memory 응답으로 정상 길이·chunk extension을 유지하고, 부호·밑줄·0x 접두사·청크 앞 공백을
거부하는지 확인했다. 구 런타임과 비교되는 문법 검사는 7개다. SQL 인가 점검은 새 런타임의 회귀
확인으로, 구 런타임에서도 통과하므로 해당 CVE의 차등 악용 재현이라고 부르지 않는다.
중복 Content-Length 등 HTTP parser 전체의 적합성 검사를 완료했다고 주장하지 않는다.

## 실제 설치 경로

- Debian 앱/테스트: `libsqlite3-0`을 로컬 `3.54.1-0secops1` 패키지로 교체한다. 기존 util-linux 등의
  ABI 의존성을 유지하고 dpkg 설치 metadata와 실제 파일을 함께 검증한다. Debian 보안팀 발행 패키지나
  DSA가 아니며, 로컬 담당자가 source·compiler·패키지 유지보수를 책임진다.
- Lambda: Amazon Linux 빌드 단계에서 컴파일한 라이브러리를 Python의 실제 `/var/lang/lib` 경로에
  원자적으로 교체한다. 실행 중인 ELF inode를 덮어 쓰지 않는다. `/usr/lib64`의 OS RPM SQLite는
  별도 구성요소로 남을 수 있으므로 Lambda 전체 OS 취약점 해결로 확대하지 않는다.
- FTS3/4/5·RTree·Session·WAL·threads 지원을 유지했다. 기존 배포판의 모든 compile option이 동일하다는
  보장은 없다. 실제 옵션·모듈 목록과 source ID는 공개 검증 JSON에서 확인한다.
- 컴파일러·SQLite 소스 tar·CLI·zipfile 확장은 최종 앱 실행 단계에 복사하지 않는다. Debian 앱 실행 사용자는 기존
  UID10001을 유지한다. 라이브러리 버전·source ID·파일 해시를 빌드 때 검증하고 설치 후 `pip check`를 실행한다.

base digest·원본 URL·SHA-256/SHA3-256·patch 지문은
[`sources.lock.json`](../infra/runtime/sources.lock.json), 설치 코드는
[`build_runtime.py`](../infra/runtime/build_runtime.py), 출처/라이선스는
[`NOTICE.md`](../infra/runtime/NOTICE.md)에 있다. 앱/테스트/Lambda의 base와 핵심 소스·외부 wheel은
고정했지만 빌더의 APT·Lambda DNF 저장소 전체는 동결하지 않았다. 비트 단위 동일 빌드를 보장하지 않는다.
Docker 하위 레이어에 남는 이전 파일 바이트의 완전 삭제나 all-layers 스캔도 이번 검증 범위가 아니다.

## 의존성과 재현

[`requirements/`](../infra/runtime/requirements/)는 build 6개·runtime 42개·test 48개 패키지의
정확한 버전과 non-yanked wheel 해시를 고정한다. Debian과 Lambda의 glibc 차이에 맞는 wheel을
선택할 수 있도록 같은 버전의 여러 wheel 해시를 포함하며 sdist는 허용하지 않는다.
프로젝트 자체 wheel은 신뢰하는 로컬 코드에서 `--no-index --no-deps --no-build-isolation`으로 별도
생성하고 그 파일의 해시를 확인해 설치한다. 의존성의 버전 상한·앱 동작은 기존 pyproject 계약을 유지한다.
Windows 가상환경을 이 Linux lock으로 재설치하지 않는다.

설치된 pip뿐 아니라 `ensurepip` 안의 이전 25.0.1 wheel도 같은 검증된 26.3 wheel로 교체했다.
CPython ensurepip의 버전 상수 한 곳을 로컬 포장 변경으로 갱신하며 원본/결과·구/신 wheel 지문을
전부 대조한 뒤에만 쓴다. bootstrap 알고리즘은 유지한다. 새 오프라인 venv가 실제 pip26.3으로
시작하는지 컨테이너 테스트를 추가했다. Trivy의 setuptools70.3.0 세 항목은 최종 pip26.3에서도
남는다. 설치된 top-level setuptools는 없지만 pip26.3과 새 bundle의 vendor.txt에 같은 버전의
pkg_resources가 남아 있음을 확인했다. package_index·egg_info·setuptools/wheel 모듈은 이 vendor
트리에 없었다. 이는 범위 차이 관측이며 자동 오탐/예외 승인이나 세 항목 패치 완료가 아니다.
upstream wheel을 임의로 다시 포장하거나 vendor metadata를 지우지 않고 독립 검토 대상으로 남긴다.
[pip vendoring 정책](https://pip.pypa.io/en/stable/development/vendoring-policy/),
[PackageIndex 공지](https://github.com/pypa/setuptools/security/advisories/GHSA-5rjg-fvgr-3xxf),
[sdist 공지](https://github.com/pypa/setuptools/security/advisories/GHSA-h35f-9h28-mq5c),
[legacy wheel 공지](https://github.com/pypa/setuptools/security/advisories/GHSA-xmj3-9gf7-h52w)를 함께 본다.

후속 업데이트는 별도 브랜치에서 PyPI resolver 보고서와 배포 wheel SHA를 대조해 세 lock을 함께
갱신하고 앱/테스트/Lambda 빌드·전체 회귀·mTLS·동일 DB 재검사를 다시 실행한다.
단순 `pip install -U`로 lock을 우회하지 않는다. CI의 호스트 Python 의존성 설치는 기존 방식이며,
이 lock 적용 범위는 세 Dockerfile이다.

## 비용 없는 검증 방법

```powershell
docker build --platform linux/amd64 -t secops-patched -f Dockerfile .
docker build --platform linux/amd64 -t secops-tests -f Dockerfile.test .
docker run --rm --network none secops-tests
docker build --platform linux/amd64 -t secops-lambda -f Dockerfile.lambda .
docker run --rm --network none --read-only --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges:true --tmpfs /tmp:rw,nosuid,nodev,size=64m --entrypoint python secops-patched /opt/secops-runtime/install/verify_security.py --require-patched
.venv/Scripts/python.exe -m pytest -q tests/test_runtime_patches.py
.venv/Scripts/python.exe -m scripts.test_continuous_mtls_runtime --directory runtime/c02/patch-check-fresh
```

오프라인 런타임 점검은 앱/Lambda 각각 23개다. 별도로 같은 현재 앱 코드·같은 runtime dependency lock을
사용한 구 Python 3.12.15 / SQLite 3.46.1 대조 이미지를 만들었다. 그 환경에서 소비·회수·대기 허용과
압축 보관 이력을 생성하고 SQLite backup을 만든 뒤, 새 런타임에서 18개 검사를 통과했다.
합성 시각을 고정해 대기 허용이 한 번 성공하는지도 확인하므로 단순 TTL 만료로 인한 거부와 구분된다.
이 대조 이미지는 11/3의 과거 b466 앱 이미지와 별개다. 운영 데이터 복원/rollback 승인으로 해석하지 않는다.
재현용 [구 런타임 Dockerfile](../infra/testing/Dockerfile.runtime-before)은 동일한 현재 앱·runtime lock을
사용한다. 배포 후보가 아니라 격리된 합성 DB 준비용이다. 같은 전용 scratch 디렉터리를 두 이미지에
마운트하고 `python -m scripts.verify_runtime_upgrade prepare --directory /scratch`를 구 이미지에서,
`verify --directory /scratch`를 새 이미지에서 실행한다. 결과에는 토큰을 출력하지 않는다.
복구 시 이전 이미지로의 자동 rollback을 이 시험으로 승인하지 않으며, 접속을 봉쇄하고 데이터/소비/폐기
이력을 보존한 상태에서 수정된 이미지와 호환성을 다시 확인한다.

재검사 실행기는 이미 빌드한 이미지 ID의 tar를 저장해 양 후보가 공유한다.

```powershell
.venv/Scripts/python.exe -m scripts.recheck_supply_chain --directory runtime/c03/new-recheck --image secops-patched --source-ref HEAD --previous-summary runtime/c03/idle-2/summary.json
```

원본 scanner release 자산 해시를 재확인하고 이전 Sigstore 검증 기록을 재사용한다. 새로운 서명 검증을
했다고 표시하지 않는다. 기존 DB는 읽기 전용으로 마운트해 전용 볼륨으로 복사한 뒤 지문을 비교한다.
복사 단계만 root의 CHOWN/DAC_READ_SEARCH를 사용하며 검사 자체는 기존 UID10001·capability0·
read-only root·network none·CPU2·2GiB·PID128로 수행한다. DB 갱신은 하지 않는다.
warm-up과 3회 반복, requests metadata 양/음성 대조군, 검사 전후 DB 지문을 보존한다.
동결 DB·원본 release 자산·기존 summary는 ignored runtime 자료다. 새 clone만으로 이 snapshot이
생기지는 않으므로 독립 재현에는 해당 지문의 자료를 인계해야 한다. 새 DB를 받으면 별도 시점의 새 결과로 기록한다.
현재 앱/스크립트와 이미지 내부 파일 지문이 다르면 중단한다. 입력 이미지·과거 DB·이전 결과를 삭제하지 않는다.

다운로드는 공개 upstream·패키지/이미지 배포처만 사용했다. AWS 배포·유료 LLM 호출·호스트 Docker
재시작·OS 신뢰 저장소 변경은 없다. 합성 토큰/원본 대용량 결과는 ignored runtime에만 두고 공개하지 않는다.

## 검토 인계

채희주는 런타임/이미지·빌드 입력·실제 실행·측정·정리를 담당한다. 김택희는 SQL/DB/WAL/changeset의
실제 앱 도달성, HTTP 간접 호출 영향과 소비·회수·복원 의미를 독립 확인한다. 독립 재현 완료는 별도로 남긴다.
남은 Debian·Python·Lambda OS·프록시/CA/DB/격리 DinD·실제 호스트의 취약점은 이번 패치만으로 닫지 않는다.
현재 검사기의 잔여 발견·scope 차이와 disputed 항목은 억제 없이 기록하고, C03 최종 도구 선정과
11/22 통합·11/29 동결·12/6 제출 계획은 유지한다. 탐지 정밀도·재현율·F1의 95% 목표와 이 패치 검증은 별개다.

## 장기 장애 시험의 시간 경계

첫 로컬 통합 시도는 보관 소비의 reason 확인에서, 두 번째는 무관한 사용자의 접근 확인에서 실패했다.
두 번째의 보관 소비/회수 검사는 통과했다. 긴 Docker 장애 시험 중 60초 grant와 90초 증거가 만료될 수
있으므로, 소비 marker 자체를 보관 이력에서 별도로 확인하고 HTTP 재사용 거부와 함께 검증하도록 했다.
무관한 원래 세션에는 회수가 전파되지 않았는지 확인하고, 만료된 원래 허용은 거부해야 하며 복구 후
가용성은 새 증거·새 세션으로 확인한다. 이때 HOLD는 SIGNAL_PROOF_EXPIRED에 의한 상태만 허용한다.
잘못된 회수·예상 밖의 거부 원인·만료 토큰 허용을 통과시키지 않는 회귀 6개를 추가했다.
서비스 TTL·정책·탐지 코드를 바꿔 시험을 통과시키지 않는다. 최초 실패 원자료와 최종 재검증을 구분해 남긴다.

## 최종 검사 결과의 해석

| 로컬 검증 | 실제 결과/범위 |
|---|---|
| Linux 전체 회귀(캐시 포장 보완 전) | 전체 1,892 통과, 경고2. 새 패치 테스트55개 포함 |
| Windows 전체 병렬 실행 | 1,877 통과·4 skip·3 실패. 실패는 watchdog 프로세스의 15초/10초 deadline 초과 |
| Windows 전체 순차 최종 | 1,888 통과·4 skip·경고3. 앞선 병렬 실행의 프로세스 시간 초과를 전체 재검증 |
| Windows 분리 재검증 | 새 패치·mTLS 계약·watchdog 프로세스 파일: 118 통과·2 skip. skip은 패치된 Linux 전용 native 점검2개 |
| 캐시 제외 이미지 집중 회귀 | 106 통과. Linux native 2개 포함 |
| 앱/Lambda 런타임 | 각각23개 통과, 두 이미지의 새 오프라인 venv가 pip26.3으로 시작 |
| 실제 로컬 mTLS | 41 통과, 910.81초. 전용 컨테이너·볼륨·네트워크 잔여0. 포장 경계는 아래 참조 |
| 구→신 DB·백업 | 18개 통과. 소비·회수·대기 허용·보관 이력·테넌트 경계 보존 |
| 동일 frozen DB 재검사 | Syft→Grype187 / Trivy188 native package-advisory 행. warm-up 후 각각3회 동일 |
| 설치 metadata 대비 inventory | Syft131/131·추가0, Trivy131/131·추가14. 추가는 vendor scope 등이며 새 설치14개를 뜻하지 않음 |
| 대조군/DB | 양 후보 requests 양/음성 metadata 대조군 통과, 검사 전후 DB 지문 동일 |

이전 Grype195/Trivy191과 이번 수치를 비교할 수 있지만 앱 소스·의존성·런타임이 함께 바뀌었으므로
단일 패치의 효과 크기나 검사 정확도라고 해석하지 않는다. Python 공식 릴리스의 두 항목과 설치 pip의
기존 여섯 advisory가 후보 결과에서 사라졌고, HTTP 로컬 backport는 버전 기준으로 계속 보고된다.
SQLite14개도 trixie DB 기준으로 계속 보고된다. 해당 행을 지우거나 distro의 수정 승인으로 바꾸지 않았다.
Trivy의 setuptools 세 항목과 다른 Debian/Python 잔여도 그대로 남긴다.

Windows의 실패한 전체 실행을 성공으로 덮어 쓰지 않았다. 분리한 재검증·앞선 실패와 최종 mTLS 결과를
공개 JSON에서 각각 구분한다. CI의 정확한 head/병합 후 결과와 source ID는 이 변경의 PR에 추가 기록한다.

보관/복원 snapshot 구간은 테스트용 expiry watchdog을 잠시 정지하고 `finally`에서 재개한다.
이후의 만료/회수/장애 시험에서는 감시기를 실제 실행한다. 유효한 시간 기반 HOLD 이력을 저장 손상으로
오판하지 않기 위한 시험 격리이며 운영 감시기·서비스 TTL·인가 정책 변경은 아니다. 실패 시 재개 보장도 검사한다.

GitHub 저장소는 공개이며 기존 CI는 표준 `ubuntu-latest` runner를 사용한다. 별도 유료 runner나 배포를
추가하지 않는다. 공개 저장소의 표준 runner 무료 범위는
[GitHub 공식 과금 문서](https://docs.github.com/en/billing/concepts/product-billing/github-actions)로 확인했다.

## 빌드 context의 바이트코드 경계

최종 점검에서 Windows의 로컬 바이트코드가 앱/스크립트 COPY에 포함되는 것을 관측했다.
`.dockerignore`에 중첩 `__pycache__`와 `*.py[cod]` 제외 규칙을 추가했다. 소스 지문 검사가
의도한 실행 코드와 연결되도록 빌드 context의 파생 캐시를 제외한다. 이미지에서 실제로 해당
app/scripts 캐시가 사라졌는지 별도 확인한다. 설치된 wheel로부터 컨테이너 안에서 생성된
site-packages의 캐시는 이 제외 규칙과 별개다. 앱/인가/탐지 소스는 변경하지 않았다.
로컬 mTLS41개를 통과한 런타임·소스와 이 포장 변경을 구분하며, 최종 PR CI는 캐시를 제외한
새 이미지에서 전체 회귀와 mTLS를 다시 실행한다.

버전200 watchdog 대조군의 실패는 코어 응답 `GRANT_EXPIRED`와 기존 ACTIVE 세션으로 확인했다.
같은 만료 분리 검증을 이 대조군에도 적용해, 원래 권한은 만료되면 거부하고 새 증거/새 세션으로만
무관한 사용자의 가용성을 확인한다. 이 검사를 포함한 로컬 mTLS 최종 합계는41개다.
캐시 제외 전후 앱/스크립트 소스와 활성 SQLite 바이너리 SHA-256은 동일하지만 이미지 ID는 다르다.
이 차이와 캐시 제외 후106개 집중 검사, 최종 CI의 새 이미지 검증을 별도 근거로 남긴다.
