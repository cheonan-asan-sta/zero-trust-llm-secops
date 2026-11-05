# C03 공급망 발견 차이의 재현 가능한 검토

2026년 11월 5일 · I8/C03 · 채희주 인프라 구현·실행, Codex 도구 보조.

[첫 스캐너 비교](technology-decisions/C03-supply-chain.md)는 Grype 195행·Trivy 191행과
일부 alias 대응을 수작업으로 정리했다. 이번에는 **보관한 원본의 무결성과 시험 조건을 다시 검사한 뒤**
같은 ID·직접 alias·한쪽 전용 발견·심각도/수정 버전 차이를 JSON 검토 목록으로 만든다.
제로트러스트 서비스가 사용하는 소프트웨어의 출처와 검사 근거를 확인하는 인프라 작업이다.
접근 정책·탐지 규칙·임계값·의존성은 변경하지 않는다.

## 입력과 실패 조건

`scripts.review_supply_chain`은 Python 표준 라이브러리와 기존 패키지 정규화 함수를 사용한다.
Docker·스캐너·DB를 실행하거나 다운로드하지 않으며 네트워크 요청도 없다.

1. 호출자가 별도로 신뢰한 기존 공개 요약의 SHA-256을 지정한다. 현재 파일에서 임의로 다시 해시해
   변조 판정을 우회하지 않는다. 해시는 서명이나 snapshot rollback 방어가 아니다.
2. 읽는 JSON/metrics 27개의 크기·SHA-256을 요약 manifest와 대조한다. 고정 파일명만 읽으며 경로 탈출,
   Windows/Linux 구분자 중복, symlink, 중복 JSON 키·비유한 숫자·크기 초과는 거부한다.
3. 완료된 오프라인 캠페인, DB 전후 지문 일치, 3회 이상의 반복, scanner exit 0을 확인한다.
   성공 플래그만 믿지 않고 원본의 이미지 ID·도구 버전·설치 metadata 대비 패키지 목록을 검사한다.
4. 매 반복의 발견·alias·심각도·수정 버전·공급자 상태·PURL이 같아야 한다. native 발견 목록은 기존 요약과
   대조한다. requests의 지정 advisory 양성/음성 대조군도 패키지명·버전을 포함해 다시 검사한다.
5. 누락·변조·불일치 때 새 보고서를 만들지 않는다. 기존 보고서나 원본도 덮어쓰지 않는다.

DB 지문은 보관된 요약 안의 전후 기록을 검증한다. 이번에 수 GB DB나 이미지 tar를 다시 읽거나
스캔하지 않았다. JSON의 이미지 ID와 요약의 archive 지문을 연결하며 당시 스캔/서명 검증 실적을
이번 코드로 다시 실행했다고 표현하지 않는다.

## 대응과 검토 규칙

동일 생태계·패키지명·설치 버전 안에서 native advisory ID를 대조한다. Grype의
`relatedVulnerabilities`와 Trivy의 `VendorIDs`가 **상대 native ID를 직접 지목**하는 경우에만
`direct_provider_alias`로 대응한다. 설명·URL에서 ID를 추출하거나 전역/추이적 alias 집합으로 합치지 않는다.
하나가 여러 발견에 대응하면 모두 `ambiguous_alias`로 남기며 기존 native 대응도 강제로 선택하지 않는다.

각 항목에 양쪽 native ID·공급자·PURL·원래 심각도/수정 버전·상태·alias를 보존한다. 서로 다른 공급자의
상태 열거형을 같은 의미로 변환하지 않으며 심각도 중 큰 값으로 자동 대체하지 않는다.
한쪽 전용·binary 범위·TEMP ID·심각도/수정 버전 차이는 별도 flag다. flag는 서로 겹칠 수 있다.
모든 발견은 `unreviewed`, 실제 영향은 `not_assessed`로 남긴다. 대응 성공도 오탐/진양성 판정이 아니다.

## 실행

보관한 11/3 공개 요약의 신뢰 지문은 아래 명령에 고정했다. 원본 소유자가 보관한
`runtime/c03/idle-2/out`을 사용하며 GitHub 복제본만으로 큰 비공개 원자료가 생기지는 않는다.
다른 보관 위치의 원자료도 27개 지문이 같아야 한다. 출력은 존재하지 않는 새 파일을 지정한다.

```powershell
.venv\Scripts\python.exe -m scripts.review_supply_chain --summary docs/infrastructure-results/c03-windows-20261103.json --summary-sha256 4860aaeec2d02019afcef1c74b475fc67e2198e7f7dbdd71d2f25ce9bfcb932f --raw-directory runtime/c03/idle-2/out --output runtime/c03/review-new.json --require-reviewed

.venv\Scripts\python.exe -m pytest tests/test_supply_chain_review.py tests/test_supply_chain_comparison.py -q
```

종료 0은 유효한 보고서 생성, 1은 입력/출력 거부다. `--require-reviewed`를 지정하면 미검토 발견이 있는
유효한 보고서도 생성한 뒤 **종료 2**를 반환한다. 이번 실제 실행은 종료 2이며 보안 통과로 표시하지 않는다.
현재 명령은 검토 결과 승인/예외 입력 기능을 제공하지 않는다. 승인 전 자동 억제나 제품/CI 게이트 연결도 없다.
CLI 오류는 고정 코드와 예외 종류만 출력하며 원본 텍스트·사설 경로를 traceback으로 내보내지 않는다.

## 실제 재분석 결과

[공개 JSON](infrastructure-results/c03-findings-review-20261105.json)은 11/3에 스캔한
`b4660ad1915fc3e2d39159f003940ec085f9f19c` 이미지의 원본을 다시 분석한 결과다.
최신 앱이나 복구용 CA/DB 이미지의 새 검사로 해석하지 않는다. 설치 metadata 131개와 반복 3회,
입력 27개를 확인했으며 실행 코드의 LF 정규화 지문도 결과에 기록했다.

| 분류 | 건수 | 현재 해석 |
|---|---:|---|
| 같은 native advisory ID | 180 | 같은 패키지/버전의 양 후보 발견 |
| 직접 공급자 alias 대응 | 6 | pip GHSA/CVE metadata 대응; 독립 동등성 확인은 별도 |
| Grype에만 존재 | 9 | Python 3.12.15 binary catalog 범위 |
| Trivy에만 존재 | 5 | Debian 패키지의 TEMP ID; 고유 TEMP ID 자체는 4개 |
| 총 검토 항목 | 200 | 전부 미검토·실제 영향 미평가 |
| 심각도 표기 차이 | 78 | 위 대응 항목의 추가 flag, 총 발견 수에 더하지 않음 |
| 수정 버전 차이/모호한 alias | 0 / 0 | 이번 고정 표본에서만 해당 |

심각도 차이 78건 중 46건은 Grype `NEGLIGIBLE` / Trivy `LOW`다. 나머지 32건도 원래 공급자 값을
보존했다. 이 차이로 누가 맞는지, 어떤 취약점을 무시해도 되는지 판정하지 않는다.
긴 설명·링크·이미지 설정 원문은 복사하지 않고 비교에 필요한 구조화 필드만 공개한다.
기존 C03 원본/요약과 CA 복구 실험 결과는 그대로 보존한다.

## 검증과 인계

신규 실패 경로 테스트는 원본 변조·다른 이미지/도구·반복 metadata 변경·DB 변경·실패 exit·패키지 누락·
대조군 실패·패키지 범위 혼동·alias 충돌/추이적 합침·경로 탈출·덮어쓰기를 다룬다.
신규 **48개**·기존 C03 **21개**, 집중 시험 총 **69개**가 통과했다. 전체 회귀는
**Windows 1,797 통과·2 건너뜀·3 경고(484.47초)**, 네트워크 없는 **Linux Docker 1,799 통과·2 경고
(367.84초)**와 양쪽 Ruff 통과다. 건너뜀/경고는 기존 항목이다. 두 전체 시험은 병행했으므로 이 시간으로
환경별 성능 순위를 매기지 않는다. Windows pytest 자체는 종료 0이었으나 뒤따른 로그 표시 보조 스크립트가
콘솔 CP949 인코딩으로 종료 1이 됐다. 표시 처리를 수정했으며 실제 결과/원본 로그 지문을 보존한다.

동일 원본 27개의 실제 재분석도 Windows와 network-none·비루트·읽기 전용 rootfs·capability 제거
Linux에서 각각 수행했다. 보고서는 공개 JSON과 **바이트 단위로 동일**했고 `--require-reviewed`는
양쪽 모두 의도한 종료 2였다. 시험 이미지의 앱·스크립트·테스트 Python 파일 **175개**를 작업 파일의
raw 지문과 대조했다. 시험 컨테이너·이미지 태그를 정리했고 기존 kind 컨테이너/두 ZIP은 보존했다.
AWS·유료 LLM·실계정/OS 신뢰 설정은 사용하지 않았다.
[실행 검증 요약](infrastructure-results/c03-findings-validation-20261105.json)에 지문·결과·정리 범위를 기록한다.

채희주는 재분석기·시험 실행·원자료와 차이 목록을 인계한다. 김택희의 독립 재현과 앱 영향 검토는
미완료다. 다음 C03 작업은 14개 한쪽 전용 발견과 78개 심각도 차이의 벤더 공지·백포트·앱 도달 가능성을
우선 조사하고, **현재 배포 후보 이미지**를 다시 고정해 두 후보로 검사하는 것이다.
실제 영향과 운영 부담을 확인한 뒤 11/22 선정 근거를 작성하며 11/29 동결·12/6 제출 준비 일정을 유지한다.
스캐너 정밀도/재현율이나 보안 이벤트 탐지 95%/5% 목표를 이 결과에서 계산하지 않는다.
