# 일곱 이미지 종류의 동일 DB 공급망 검사

11월 개발 로드맵 C03/I8의 채희주 담당 후속이다. 날짜·주차 전체 완료를 뜻하지 않는다.
기존 앱·관측 검사에 CA·PostgreSQL·NGINX·Lambda·테스트 이미지를 추가한다.
팀원의 M6/M7 변경을 받은 최신 기반에서 앱·관측도 다시 빌드해 동일 소스 코호트로 검사한다.

| 종류 | 실제 빌드/참조 | 소스·구성요소 확인 | 설치 목록 |
|---|---|---|---|
| 앱 | Dockerfile | 앱/도우미/설치 파일 지문, 런타임 보안23개 | DEB·Python |
| 관측 | 기존 관측 빌더 | 앱 상속, Prometheus·promtool·Alertmanager·amtool 실제 지문 | DEB·Python·내장 바이너리 발견 |
| CA | 기존 PersistentAuthorityRuntime 빌더 | 관측 상속, step·step-ca까지 실제6개 바이너리 지문 | DEB·Python·내장 바이너리 발견 |
| DB | 고정 PostgreSQL digest에서 UID10001로 파생 | 고정 upstream·레이어 상속·postgres 버전. DB 초기화/기동 없음 | 실제 OS 관리자 |
| NGINX | 고정 nginx digest | upstream·nginx -v. 프록시 기동 없음 | 실제 OS 관리자 |
| Lambda | Dockerfile.lambda | /var/task 앱·설치 파일 지문, 런타임 보안23개. AWS/RIE 실행 없음 | RPM·Python |
| 테스트 | Dockerfile.test | /workspace 빌드 입력과 /opt 설치 파일, 런타임 보안23개 | DEB·Python |

공식 빌더의 prepare_extra_images만 이용하며 up/make_assets는 호출하지 않는다. 서비스 키·CA 등록·
PostgreSQL 데이터·클라우드 리소스를 만들지 않는다. 검사 도구의 고정 자산과 과거 서명 검증 기록을
재사용하되 새 Sigstore 검증이나 원격 attestation으로 확대하지 않는다.

## 검사 조건과 원자료

과거 DB는 읽기 전용으로 확인하고 소유 복사본 하나만 갱신한다. 일곱 이미지가 같은 복사본과
runner를 순차 사용해 반복 다운로드·DB 복사를 줄인다. 검사 전후 및 전체 마지막 DB 파일 지문이
동일해야 한다. Grype/Trivy DB 모두 UTC·120시간 이내·미래 편차10분 이하 조건을 유지한다.
NGINX의 libintl JAR 분석에 필요한 Trivy Java index도 준비 단계에서 별도로 내려받는다.
`trivy-java.db`와 Java metadata까지 같은 스냅샷의 지문에 포함하고, 각 이미지의 오프라인 상태·나이를
검증한다. Java 분석을 끄거나 누락한 채 성공으로 처리하지 않는다.
[Trivy DB 준비 옵션](https://trivy.dev/docs/latest/configuration/db/)을 따른다.

모든 이미지의 소스·런타임·OS metadata 사전 확인을 먼저 수행한 후 DB 갱신과 반복 검사를 시작한다.
DB 갱신만 bridge 네트워크를 허용하며 실제 검사·버전·metadata·양/음성 대조군은 network none,
읽기 전용 루트·UID10001·capability 제거·CPU2·메모리/메모리+swap3GiB·PID128로 실행한다.
스캐너 /tmp는2048MiB tmpfs, Trivy 분석 제한시간은15분이다. 입력 이미지 크기는1900MiB 미만이며
tar 출력 전 로컬 여유 공간도 확인한다. 한도를 넘으면 실패를 기록하며 검사를 생략하지 않는다.
사전 확인에서 CA 이미지가1,474,105,593바이트로 기존1400MiB 입력 예산을 넘었다. DB 갱신과
스캔 전 중단·소유 자원0을 보존한 뒤 이미지 전체 레이어와 분석 메모리를 위한 새 예산을 정했다.
선행 앱/관측 검사의2GiB 메모리·1536MiB 임시공간 조건은 변경하지 않으며 직접 성능 비교하지 않는다.

각 이미지에 warm-up과3반복, requests2.31.0/2.32.0의 특정 공지 양/음성 대조군을 적용한다.
요약 SHA256·원본 크기/지문·이미지 ID·검사기 버전·종료 코드·반복 일치·동일 DB를 검증한다.
모든 native package/version/advisory 발견을 억제하지 않고 독립 영향 검토 대장으로 남긴다.

설치 목록은 dpkg-query/rpm/APK DB와 Python metadata에서 읽는다. RPM의 epoch/release와
Debian epoch/revision을 유지하고, Trivy의 OS별 명칭은 **설치 목록 비교에만** 정규화한다.
발견의 native ecosystem/advisory ID는 원래대로 보존한다. OS 목록 전체를 읽지 못한 결과는
성공으로 처리하지 않는다. 부분 누락/추가는 그대로 보여 주며 정확도나 악용 가능성으로 해석하지 않는다.
형식 근거는 [Syft RPM metadata](https://github.com/anchore/syft/blob/v1.56.0/syft/pkg/rpm.go)와
[Grype/Trivy DB 조건을 정리한 선행 검사](current-image-supply-chain.md)를 따른다.
Syft의 RPM DB metadata와 ELF package note metadata는 구분한다. ELF note의 버전은
[공식 변환 코드](https://github.com/anchore/syft/blob/v1.56.0/syft/pkg/cataloger/binary/elf_package.go)처럼
최상위 Package.Version을 그대로 읽어 epoch/release를 보존한다. 알 수 없거나 모순된 형식은 거부한다.
앞선 묶음은 다섯 이미지 검증 후 Lambda 원자료 정리에서 이 차이를 처리하지 못해 중단됐다.
Lambda의 실제 검사 종료0과 전체 묶음 검증 실패를 구분해 보존하며, 해당 원자료 재검증은 진단으로 표시한다.

## 소스 경계와 정리

이 기록은 **실제 실행 커밋에서 빌드한 이미지 ID**에 묶인다. 텍스트 입력은 LF, 바이너리 입력은
원래 바이트 SHA256으로 비교한다. 테스트 이미지는 docs도 포함하므로, 결과 문서를 추가한 후의
CI 테스트 이미지와 실제 스캔 이미지가 바이트까지 같다고 주장하지 않는다. 최종 문서 커밋의
실행 코드·레시피·lock 변경 여부와 CI 회귀는 별도로 대조하고 해당 한계를 명시한다.

한 번에 이미지 tar 하나만 만들고 검증 후 해당 임시 tar만 제거한다. 이미지 ID·tar 지문·원자료는
기록하며 입력 Docker 이미지는 보존한다. 모든 소유 컨테이너를 먼저 정리한 후 공유 DB/runner를
제거한다. 원본 DB·이전 결과·다른 실습 컨테이너·ZIP은 건드리지 않는다.
갱신 DB 복사본을 제거하므로 정확한 미래 재실행에는 같은 DB 바이트가 별도로 필요하다.

대상은 위 일곱 이미지 종류다. 중간 빌더·검사 helper·DinD·GitHub runner/Actions 이미지나
모든 과거 tag를 검사한 것은 아니다. CA/DB/NGINX의 마운트된 운영 설정과 실서비스 동작은 별도
통합 검증으로 다룬다. C03 운영 선정·앱 영향 독립 검토·운영 승인은 이번 검사 성공만으로 완료하지 않는다.
탐지 규칙·임계값·평가 데이터는 유지한다. AWS·유료 모델 호출은 없다.

```powershell
.venv/Scripts/python.exe -m scripts.test_image_matrix_runtime --directory runtime/c03/seven-images-fresh
```

## 결과

실행 소스 `0930faa94c90faaa007bc144021f1414f0e20fee`에서 일곱 이미지의 사전 확인·warm-up/3반복·특정 공지
양/음성 대조군·원본/요약 지문·DB 불변성 검증을 통과했다. 모든 발견은 독립 영향 검토 대기다.

| 이미지 | Grype native package/version/advisory | Trivy native package/version/advisory |
|---|---:|---:|
| application | 191 | 194 |
| monitoring | 196 | 197 |
| authority | 322 | 320 |
| database | 453 | 463 |
| nginx | 357 | 414 |
| lambda | 14 | 8 |
| tests | 192 | 195 |

이 수치는 각 이미지·검사기 내 고유 native 항목 수다. 이미지/검사기 간 중복을 합친 독립 취약점 수나
실제 악용/오탐 수가 아니다. 모든 발견을 남겼으며 억제/예외/운영 승인0이다. RPM/DEB/APK·Python
설치 목록의 부분 누락/추가와 Grype Go 모듈 대체 매칭·Trivy SBOM 경고 여부도 기록에 포함한다.

집중289개 통과/기존2skip, 신규55사례, **같은 스캔 이미지 ID에 Git 원본 LF 자료를 읽기 전용으로
제공한 Linux 회귀2728개 통과**
(경고2개)를 확인했다. 과거 DB를 보존했고 이번 소유 컨테이너·복사 DB 잔여0이다.
입력 tar는 지문 확인 후 각 이미지 차례가 끝날 때 제거했다. 원본 Docker 이미지와 raw 결과는 로컬에 남긴다.
정확한 미래 재실행에 필요한 새 DB 바이트는 정리되었음을 명시한다.
다른 실습 컨테이너가 함께 실행되고 호스트 시간 관측 간격도 있어, 이 회차의 실행 시간은
독립적인 부하 성능 비교나 검사기 성능 순위로 사용하지 않는다.

추가 자료 마운트 없이 실행한 첫 테스트 이미지 회귀는4실패/2724통과였다. Windows `core.autocrlf=true`의 체크아웃이
M7 pilot의 LF를 CRLF로 바꿔 원래 지문과 달라졌고, 무결성 검사가 이를 거부했다. 실패 원문을
보존하고 Git의 정확한 원본4파일을 별도 준비해 같은 이미지에 읽기 전용으로 제공했다. 입력의
라벨·관측값·행순서·분할과 M7 처리·시험·해시 검증 코드는 변경하지 않았다. 재실행은 전체2728개다.
M7 pilot만 LF로 유지하는 `.gitattributes` 규칙과 현재 작업본의 Git 원본 바이트 복원을 추가했다.
이는 체크아웃·시험 입력 보완이며 평가 수치 보정이나 해시 검증 완화가 아니다. 후속 LF 정책 지문,
fixture의 원본/Windows 지문과 마운트 범위를 JSON에 별도로 기록한다. 원래 이미지 내부의
CRLF 자료가 수정됐거나 추가 마운트 없는 원본 이미지 회귀가 통과했다고 주장하지 않는다.

앞선 두 번째 묶음에서는 앱·관측·CA·DB 검증 뒤 NGINX의 libintl JAR 분석에 필요한 Java index가 없어
Trivy가 종료1로 거부했다. 실패·완료 범위·정리0을 보존하고 Java 분석을 끄지 않은 채 별도 DB 준비,
Java DB/metadata 파일 지문·오프라인 상태·나이 검증을 추가했다. 최종 코호트는 세 DB를 함께 고정한다.
NGINX의 warm-up/3반복에서 Syft는 libintl0.23.1 JAR를 식별했으나 Trivy는 OS 결과만 내고
언어별 파일0을 보고했다. 해당 관측과 원자료 지문을 보존하며 JAR 탐지 범위의 독립 검토는 남긴다.

최종 CI 테스트 이미지는 LF로 체크아웃한 M7 자료와 추가 문서/JSON을 포함한다. 이 기록의 테스트 이미지와
바이트까지 같다고 확대하지 않는다. 실행 코드·레시피·lock의 지문 및 실제 checkout 소스·전체 CI는
PR에 별도로 기록한다. C03 운영 선정·앱 영향 독립 인수·전체 빌더/helper 공급망 승인은 남아 있다.

[코호트·이미지 지문·전체 발견 대장·DB·정리·한계 JSON](infrastructure-results/c03-seven-images-20261109.json)
