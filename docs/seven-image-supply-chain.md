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

실제 실행이 끝난 뒤 원자료 재검증을 통과한 결과와 소스·DB 지문을 별도 JSON으로 기록한다.
절차 정의만으로 일곱 이미지 검사 완료나 운영 보안 게이트 통과를 표시하지 않는다.
