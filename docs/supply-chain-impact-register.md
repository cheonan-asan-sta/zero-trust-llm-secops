# C03 인프라 영향 조건 200항목 대장

후속 패치/현재 이미지 상태는 [런타임 패치 기록](supply-chain-priority-patches.md)을 따른다.
아래 내용과 200항목 JSON은 과거 이미지의 패치 전 snapshot으로 보존한다.

2026년 11월 5일 · 채희주 인프라 검토 / Codex 도구 보조.

대상·실제 probe·출처와 해석은 [영향 검토 본문](supply-chain-impact-review.md)을 따른다.
P1/P2/P3는 조치/검증 순서이며 CVSS나 확정 악용 등급이 아니다. 모든 행의 독립 검토는 pending이고
실제 악용/수정/억제는0이다. 전제 완화·문서-only 관측을 공급자 패치나 운영 승인으로 읽지 않는다.
기존 C03 ID·패키지/버전·native advisory를 유지한다. 공급자 페이지는 현재 내용이 바뀔 수 있으므로
동결한 [입력 JSON](infrastructure-results/c03-impact-inputs-20261105.json)과 함께 확인한다.

| ID | 설치 패키지/버전 | advisory/공식 기록 | 우선순위 | 인프라 판단 | 공급자 snapshot 상태 |
|---|---|---|---|---|---|
| C03-0001 | python 3.12.15 | [CVE-2025-12781](https://www.cve.org/CVERecord?id=CVE-2025-12781) | P2 | 앱 입력/정규화 독립 검토 | PSF PUBLISHED |
| C03-0002 | python 3.12.15 | [CVE-2025-15366](https://www.cve.org/CVERecord?id=CVE-2025-15366) | P2 | 특정 기능/입력 조건 필요 | PSF PUBLISHED |
| C03-0003 | python 3.12.15 | [CVE-2025-15367](https://www.cve.org/CVERecord?id=CVE-2025-15367) | P2 | 특정 기능/입력 조건 필요 | PSF PUBLISHED |
| C03-0004 | python 3.12.15 | [CVE-2026-103995](https://www.cve.org/CVERecord?id=CVE-2026-103995) | P1 | 실행 기반 패치 우선 검증 | PSF PUBLISHED |
| C03-0005 | python 3.12.15 | [CVE-2026-114583](https://www.cve.org/CVERecord?id=CVE-2026-114583) | P1 | 특정 기능/입력 조건 필요 | PSF PUBLISHED |
| C03-0006 | python 3.12.15 | [CVE-2026-115557](https://www.cve.org/CVERecord?id=CVE-2026-115557) | P1 | 실행 기반 패치 우선 검증 | PSF PUBLISHED |
| C03-0007 | python 3.12.15 | [CVE-2026-3446](https://www.cve.org/CVERecord?id=CVE-2026-3446) | P2 | 앱 입력/정규화 독립 검토 | PSF PUBLISHED |
| C03-0008 | python 3.12.15 | [CVE-2026-3479](https://www.cve.org/CVERecord?id=CVE-2026-3479) | P2 | 공급자 disputed·사용 문맥 검토 | PSF PUBLISHED / disputed |
| C03-0009 | python 3.12.15 | [CVE-2026-6019](https://www.cve.org/CVERecord?id=CVE-2026-6019) | P2 | 특정 기능/입력 조건 필요 | PSF PUBLISHED |
| C03-0010 | apt 3.0.3 | [CVE-2011-3374](https://security-tracker.debian.org/tracker/CVE-2011-3374) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / unimportant |
| C03-0011 | bash 5.2.37-2+b10 | [TEMP-0841856-B18BAF](https://security-tracker.debian.org/tracker/TEMP-0841856-B18BAF) | P2 | 로컬/관리 호출 조건 필요 | trixie open / unimportant |
| C03-0012 | bsdutils 1:2.41.5-0+deb13u1 | [CVE-2022-0563](https://security-tracker.debian.org/tracker/CVE-2022-0563) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / unimportant |
| C03-0013 | bsdutils 1:2.41.5-0+deb13u1 | [CVE-2026-3184](https://security-tracker.debian.org/tracker/CVE-2026-3184) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / not yet assigned |
| C03-0014 | bsdutils 1:2.41.5-0+deb13u1 | [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / not yet assigned |
| C03-0015 | bsdutils 1:2.41.5-0+deb13u1 | [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / not yet assigned |
| C03-0016 | bsdutils 1:2.41.5-0+deb13u1 | [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / not yet assigned |
| C03-0017 | bsdutils 1:2.41.5-0+deb13u1 | [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / not yet assigned |
| C03-0018 | coreutils 9.7-3 | [CVE-2017-18018](https://security-tracker.debian.org/tracker/CVE-2017-18018) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / unimportant |
| C03-0019 | coreutils 9.7-3 | [CVE-2025-5278](https://security-tracker.debian.org/tracker/CVE-2025-5278) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / unimportant |
| C03-0020 | coreutils 9.7-3 | [CVE-2026-56391](https://security-tracker.debian.org/tracker/CVE-2026-56391) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / unimportant |
| C03-0021 | coreutils 9.7-3 | [CVE-2026-56392](https://security-tracker.debian.org/tracker/CVE-2026-56392) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / unimportant |
| C03-0022 | dash 0.5.12-12 | [CVE-2026-102473](https://security-tracker.debian.org/tracker/CVE-2026-102473) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / unimportant |
| C03-0023 | dash 0.5.12-12 | [CVE-2026-102474](https://security-tracker.debian.org/tracker/CVE-2026-102474) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / unimportant |
| C03-0024 | diffutils 1:3.10-4 | [CVE-2026-53910](https://security-tracker.debian.org/tracker/CVE-2026-53910) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / unimportant |
| C03-0025 | gcc-14-base 14.2.0-19 | [CVE-2026-102010](https://security-tracker.debian.org/tracker/CVE-2026-102010) | P3 | 문서-only 패키지 source 매칭 | trixie open / not yet assigned |
| C03-0026 | gcc-14-base 14.2.0-19 | [CVE-2026-114690](https://security-tracker.debian.org/tracker/CVE-2026-114690) | P3 | 문서-only 패키지 source 매칭 | trixie open / not yet assigned |
| C03-0027 | gcc-14-base 14.2.0-19 | [CVE-2026-114691](https://security-tracker.debian.org/tracker/CVE-2026-114691) | P3 | 문서-only 패키지 source 매칭 | trixie open / not yet assigned |
| C03-0028 | gcc-14-base 14.2.0-19 | [CVE-2026-115455](https://security-tracker.debian.org/tracker/CVE-2026-115455) | P3 | 문서-only 패키지 source 매칭 | trixie open / not yet assigned |
| C03-0029 | gcc-14-base 14.2.0-19 | [CVE-2026-95619](https://security-tracker.debian.org/tracker/CVE-2026-95619) | P3 | 문서-only 패키지 source 매칭 | trixie open / not yet assigned |
| C03-0030 | libacl1 2.3.2-2+b1 | [CVE-2026-54369](https://security-tracker.debian.org/tracker/CVE-2026-54369) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0031 | libacl1 2.3.2-2+b1 | [CVE-2026-54370](https://security-tracker.debian.org/tracker/CVE-2026-54370) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0032 | libapt-pkg7.0 3.0.3 | [CVE-2011-3374](https://security-tracker.debian.org/tracker/CVE-2011-3374) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / unimportant |
| C03-0033 | libattr1 1:2.5.2-3 | [CVE-2026-54371](https://security-tracker.debian.org/tracker/CVE-2026-54371) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0034 | libblkid1 2.41.5-0+deb13u1 | [CVE-2022-0563](https://security-tracker.debian.org/tracker/CVE-2022-0563) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / unimportant |
| C03-0035 | libblkid1 2.41.5-0+deb13u1 | [CVE-2026-3184](https://security-tracker.debian.org/tracker/CVE-2026-3184) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0036 | libblkid1 2.41.5-0+deb13u1 | [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0037 | libblkid1 2.41.5-0+deb13u1 | [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0038 | libblkid1 2.41.5-0+deb13u1 | [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0039 | libblkid1 2.41.5-0+deb13u1 | [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0040 | libbz2-1.0 1.0.8-6 | [CVE-2026-42250](https://security-tracker.debian.org/tracker/CVE-2026-42250) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0041 | libc-bin 2.41-12+deb13u4 | [CVE-2010-4756](https://security-tracker.debian.org/tracker/CVE-2010-4756) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / unimportant |
| C03-0042 | libc-bin 2.41-12+deb13u4 | [CVE-2018-20796](https://security-tracker.debian.org/tracker/CVE-2018-20796) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / unimportant |
| C03-0043 | libc-bin 2.41-12+deb13u4 | [CVE-2019-1010022](https://security-tracker.debian.org/tracker/CVE-2019-1010022) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / unimportant |
| C03-0044 | libc-bin 2.41-12+deb13u4 | [CVE-2019-1010023](https://security-tracker.debian.org/tracker/CVE-2019-1010023) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / unimportant |
| C03-0045 | libc-bin 2.41-12+deb13u4 | [CVE-2019-1010024](https://security-tracker.debian.org/tracker/CVE-2019-1010024) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / unimportant |
| C03-0046 | libc-bin 2.41-12+deb13u4 | [CVE-2019-1010025](https://security-tracker.debian.org/tracker/CVE-2019-1010025) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / unimportant |
| C03-0047 | libc-bin 2.41-12+deb13u4 | [CVE-2019-9192](https://security-tracker.debian.org/tracker/CVE-2019-9192) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / unimportant |
| C03-0048 | libc-bin 2.41-12+deb13u4 | [CVE-2026-18374](https://security-tracker.debian.org/tracker/CVE-2026-18374) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0049 | libc-bin 2.41-12+deb13u4 | [CVE-2026-19499](https://security-tracker.debian.org/tracker/CVE-2026-19499) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0050 | libc-bin 2.41-12+deb13u4 | [CVE-2026-19542](https://security-tracker.debian.org/tracker/CVE-2026-19542) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0051 | libc-bin 2.41-12+deb13u4 | [CVE-2026-5435](https://security-tracker.debian.org/tracker/CVE-2026-5435) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0052 | libc-bin 2.41-12+deb13u4 | [CVE-2026-6238](https://security-tracker.debian.org/tracker/CVE-2026-6238) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0053 | libc-bin 2.41-12+deb13u4 | [CVE-2026-6368](https://security-tracker.debian.org/tracker/CVE-2026-6368) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0054 | libc-bin 2.41-12+deb13u4 | [CVE-2026-6791](https://security-tracker.debian.org/tracker/CVE-2026-6791) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0055 | libc-bin 2.41-12+deb13u4 | [CVE-2026-77117](https://security-tracker.debian.org/tracker/CVE-2026-77117) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0056 | libc-bin 2.41-12+deb13u4 | [CVE-2026-80489](https://security-tracker.debian.org/tracker/CVE-2026-80489) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0057 | libc-bin 2.41-12+deb13u4 | [CVE-2026-84243](https://security-tracker.debian.org/tracker/CVE-2026-84243) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0058 | libc-bin 2.41-12+deb13u4 | [CVE-2026-8674](https://security-tracker.debian.org/tracker/CVE-2026-8674) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0059 | libc-bin 2.41-12+deb13u4 | [CVE-2026-86805](https://security-tracker.debian.org/tracker/CVE-2026-86805) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0060 | libc-bin 2.41-12+deb13u4 | [CVE-2026-89092](https://security-tracker.debian.org/tracker/CVE-2026-89092) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0061 | libc-bin 2.41-12+deb13u4 | [CVE-2026-95818](https://security-tracker.debian.org/tracker/CVE-2026-95818) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0062 | libc-bin 2.41-12+deb13u4 | [CVE-2026-97399](https://security-tracker.debian.org/tracker/CVE-2026-97399) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0063 | libc6 2.41-12+deb13u4 | [CVE-2010-4756](https://security-tracker.debian.org/tracker/CVE-2010-4756) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / unimportant |
| C03-0064 | libc6 2.41-12+deb13u4 | [CVE-2018-20796](https://security-tracker.debian.org/tracker/CVE-2018-20796) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / unimportant |
| C03-0065 | libc6 2.41-12+deb13u4 | [CVE-2019-1010022](https://security-tracker.debian.org/tracker/CVE-2019-1010022) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / unimportant |
| C03-0066 | libc6 2.41-12+deb13u4 | [CVE-2019-1010023](https://security-tracker.debian.org/tracker/CVE-2019-1010023) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / unimportant |
| C03-0067 | libc6 2.41-12+deb13u4 | [CVE-2019-1010024](https://security-tracker.debian.org/tracker/CVE-2019-1010024) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / unimportant |
| C03-0068 | libc6 2.41-12+deb13u4 | [CVE-2019-1010025](https://security-tracker.debian.org/tracker/CVE-2019-1010025) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / unimportant |
| C03-0069 | libc6 2.41-12+deb13u4 | [CVE-2019-9192](https://security-tracker.debian.org/tracker/CVE-2019-9192) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / unimportant |
| C03-0070 | libc6 2.41-12+deb13u4 | [CVE-2026-18374](https://security-tracker.debian.org/tracker/CVE-2026-18374) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0071 | libc6 2.41-12+deb13u4 | [CVE-2026-19499](https://security-tracker.debian.org/tracker/CVE-2026-19499) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0072 | libc6 2.41-12+deb13u4 | [CVE-2026-19542](https://security-tracker.debian.org/tracker/CVE-2026-19542) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0073 | libc6 2.41-12+deb13u4 | [CVE-2026-5435](https://security-tracker.debian.org/tracker/CVE-2026-5435) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0074 | libc6 2.41-12+deb13u4 | [CVE-2026-6238](https://security-tracker.debian.org/tracker/CVE-2026-6238) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0075 | libc6 2.41-12+deb13u4 | [CVE-2026-6368](https://security-tracker.debian.org/tracker/CVE-2026-6368) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0076 | libc6 2.41-12+deb13u4 | [CVE-2026-6791](https://security-tracker.debian.org/tracker/CVE-2026-6791) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0077 | libc6 2.41-12+deb13u4 | [CVE-2026-77117](https://security-tracker.debian.org/tracker/CVE-2026-77117) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0078 | libc6 2.41-12+deb13u4 | [CVE-2026-80489](https://security-tracker.debian.org/tracker/CVE-2026-80489) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0079 | libc6 2.41-12+deb13u4 | [CVE-2026-84243](https://security-tracker.debian.org/tracker/CVE-2026-84243) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0080 | libc6 2.41-12+deb13u4 | [CVE-2026-8674](https://security-tracker.debian.org/tracker/CVE-2026-8674) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0081 | libc6 2.41-12+deb13u4 | [CVE-2026-86805](https://security-tracker.debian.org/tracker/CVE-2026-86805) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0082 | libc6 2.41-12+deb13u4 | [CVE-2026-89092](https://security-tracker.debian.org/tracker/CVE-2026-89092) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0083 | libc6 2.41-12+deb13u4 | [CVE-2026-95818](https://security-tracker.debian.org/tracker/CVE-2026-95818) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0084 | libc6 2.41-12+deb13u4 | [CVE-2026-97399](https://security-tracker.debian.org/tracker/CVE-2026-97399) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0085 | libgcc-s1 14.2.0-19 | [CVE-2026-102010](https://security-tracker.debian.org/tracker/CVE-2026-102010) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0086 | libgcc-s1 14.2.0-19 | [CVE-2026-114690](https://security-tracker.debian.org/tracker/CVE-2026-114690) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0087 | libgcc-s1 14.2.0-19 | [CVE-2026-114691](https://security-tracker.debian.org/tracker/CVE-2026-114691) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0088 | libgcc-s1 14.2.0-19 | [CVE-2026-115455](https://security-tracker.debian.org/tracker/CVE-2026-115455) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0089 | libgcc-s1 14.2.0-19 | [CVE-2026-95619](https://security-tracker.debian.org/tracker/CVE-2026-95619) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0090 | liblastlog2-2 2.41.5-0+deb13u1 | [CVE-2022-0563](https://security-tracker.debian.org/tracker/CVE-2022-0563) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / unimportant |
| C03-0091 | liblastlog2-2 2.41.5-0+deb13u1 | [CVE-2026-3184](https://security-tracker.debian.org/tracker/CVE-2026-3184) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0092 | liblastlog2-2 2.41.5-0+deb13u1 | [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0093 | liblastlog2-2 2.41.5-0+deb13u1 | [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0094 | liblastlog2-2 2.41.5-0+deb13u1 | [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0095 | liblastlog2-2 2.41.5-0+deb13u1 | [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0096 | libmount1 2.41.5-0+deb13u1 | [CVE-2022-0563](https://security-tracker.debian.org/tracker/CVE-2022-0563) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / unimportant |
| C03-0097 | libmount1 2.41.5-0+deb13u1 | [CVE-2026-3184](https://security-tracker.debian.org/tracker/CVE-2026-3184) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0098 | libmount1 2.41.5-0+deb13u1 | [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0099 | libmount1 2.41.5-0+deb13u1 | [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0100 | libmount1 2.41.5-0+deb13u1 | [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0101 | libmount1 2.41.5-0+deb13u1 | [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0102 | libncursesw6 6.5+20250216-2 | [CVE-2025-6141](https://security-tracker.debian.org/tracker/CVE-2025-6141) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0103 | libncursesw6 6.5+20250216-2 | [CVE-2025-69720](https://security-tracker.debian.org/tracker/CVE-2025-69720) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0104 | libpam-modules 1.7.0-5 | [CVE-2026-54411](https://security-tracker.debian.org/tracker/CVE-2026-54411) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0105 | libpam-modules-bin 1.7.0-5 | [CVE-2026-54411](https://security-tracker.debian.org/tracker/CVE-2026-54411) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / not yet assigned |
| C03-0106 | libpam-runtime 1.7.0-5 | [CVE-2026-54411](https://security-tracker.debian.org/tracker/CVE-2026-54411) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / not yet assigned |
| C03-0107 | libpam0g 1.7.0-5 | [CVE-2026-54411](https://security-tracker.debian.org/tracker/CVE-2026-54411) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0108 | libsmartcols1 2.41.5-0+deb13u1 | [CVE-2022-0563](https://security-tracker.debian.org/tracker/CVE-2022-0563) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / unimportant |
| C03-0109 | libsmartcols1 2.41.5-0+deb13u1 | [CVE-2026-3184](https://security-tracker.debian.org/tracker/CVE-2026-3184) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0110 | libsmartcols1 2.41.5-0+deb13u1 | [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0111 | libsmartcols1 2.41.5-0+deb13u1 | [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0112 | libsmartcols1 2.41.5-0+deb13u1 | [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0113 | libsmartcols1 2.41.5-0+deb13u1 | [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0114 | libsqlite3-0 3.46.1-7+deb13u2 | [CVE-2021-45346](https://security-tracker.debian.org/tracker/CVE-2021-45346) | P1 | 실제 DB 라이브러리·앱 입력 검토 | trixie open / unimportant |
| C03-0115 | libsqlite3-0 3.46.1-7+deb13u2 | [CVE-2025-70873](https://security-tracker.debian.org/tracker/CVE-2025-70873) | P1 | 실제 DB 라이브러리·앱 입력 검토 | trixie open / unimportant |
| C03-0116 | libsqlite3-0 3.46.1-7+deb13u2 | [CVE-2026-119371](https://security-tracker.debian.org/tracker/CVE-2026-119371) | P1 | 실제 DB 라이브러리·앱 입력 검토 | trixie open / not yet assigned |
| C03-0117 | libsqlite3-0 3.46.1-7+deb13u2 | [CVE-2026-119372](https://security-tracker.debian.org/tracker/CVE-2026-119372) | P1 | 실제 DB 라이브러리·앱 입력 검토 | trixie open / not yet assigned |
| C03-0118 | libsqlite3-0 3.46.1-7+deb13u2 | [CVE-2026-119373](https://security-tracker.debian.org/tracker/CVE-2026-119373) | P1 | 실제 DB 라이브러리·앱 입력 검토 | trixie open / not yet assigned |
| C03-0119 | libsqlite3-0 3.46.1-7+deb13u2 | [CVE-2026-119374](https://security-tracker.debian.org/tracker/CVE-2026-119374) | P1 | 실제 DB 라이브러리·앱 입력 검토 | trixie open / not yet assigned |
| C03-0120 | libsqlite3-0 3.46.1-7+deb13u2 | [CVE-2026-119375](https://security-tracker.debian.org/tracker/CVE-2026-119375) | P1 | 실제 DB 라이브러리·앱 입력 검토 | trixie open / not yet assigned |
| C03-0121 | libsqlite3-0 3.46.1-7+deb13u2 | [CVE-2026-119376](https://security-tracker.debian.org/tracker/CVE-2026-119376) | P1 | 실제 DB 라이브러리·앱 입력 검토 | trixie open / not yet assigned |
| C03-0122 | libsqlite3-0 3.46.1-7+deb13u2 | [CVE-2026-119377](https://security-tracker.debian.org/tracker/CVE-2026-119377) | P1 | 실제 DB 라이브러리·앱 입력 검토 | trixie open / not yet assigned |
| C03-0123 | libsqlite3-0 3.46.1-7+deb13u2 | [CVE-2026-119378](https://security-tracker.debian.org/tracker/CVE-2026-119378) | P1 | 실제 DB 라이브러리·앱 입력 검토 | trixie open / not yet assigned |
| C03-0124 | libsqlite3-0 3.46.1-7+deb13u2 | [CVE-2026-119379](https://security-tracker.debian.org/tracker/CVE-2026-119379) | P1 | 실제 DB 라이브러리·앱 입력 검토 | trixie open / not yet assigned |
| C03-0125 | libsqlite3-0 3.46.1-7+deb13u2 | [CVE-2026-119591](https://security-tracker.debian.org/tracker/CVE-2026-119591) | P1 | 실제 DB 라이브러리·앱 입력 검토 | trixie open / not yet assigned |
| C03-0126 | libsqlite3-0 3.46.1-7+deb13u2 | [CVE-2026-50812](https://security-tracker.debian.org/tracker/CVE-2026-50812) | P1 | 실제 DB 라이브러리·앱 입력 검토 | trixie open / not yet assigned |
| C03-0127 | libsqlite3-0 3.46.1-7+deb13u2 | [CVE-2026-50813](https://security-tracker.debian.org/tracker/CVE-2026-50813) | P1 | 실제 DB 라이브러리·앱 입력 검토 | trixie open / not yet assigned |
| C03-0128 | libstdc++6 14.2.0-19 | [CVE-2026-102010](https://security-tracker.debian.org/tracker/CVE-2026-102010) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0129 | libstdc++6 14.2.0-19 | [CVE-2026-114690](https://security-tracker.debian.org/tracker/CVE-2026-114690) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0130 | libstdc++6 14.2.0-19 | [CVE-2026-114691](https://security-tracker.debian.org/tracker/CVE-2026-114691) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0131 | libstdc++6 14.2.0-19 | [CVE-2026-115455](https://security-tracker.debian.org/tracker/CVE-2026-115455) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0132 | libstdc++6 14.2.0-19 | [CVE-2026-95619](https://security-tracker.debian.org/tracker/CVE-2026-95619) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0133 | libsystemd0 257.13-1~deb13u1 | [CVE-2013-4392](https://security-tracker.debian.org/tracker/CVE-2013-4392) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / unimportant |
| C03-0134 | libsystemd0 257.13-1~deb13u1 | [CVE-2023-31437](https://security-tracker.debian.org/tracker/CVE-2023-31437) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / unimportant |
| C03-0135 | libsystemd0 257.13-1~deb13u1 | [CVE-2023-31438](https://security-tracker.debian.org/tracker/CVE-2023-31438) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / unimportant |
| C03-0136 | libsystemd0 257.13-1~deb13u1 | [CVE-2023-31439](https://security-tracker.debian.org/tracker/CVE-2023-31439) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / unimportant |
| C03-0137 | libsystemd0 257.13-1~deb13u1 | [CVE-2026-15059](https://security-tracker.debian.org/tracker/CVE-2026-15059) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0138 | libsystemd0 257.13-1~deb13u1 | [CVE-2026-16742](https://security-tracker.debian.org/tracker/CVE-2026-16742) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0139 | libsystemd0 257.13-1~deb13u1 | [CVE-2026-40228](https://security-tracker.debian.org/tracker/CVE-2026-40228) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0140 | libtinfo6 6.5+20250216-2 | [CVE-2025-6141](https://security-tracker.debian.org/tracker/CVE-2025-6141) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0141 | libtinfo6 6.5+20250216-2 | [CVE-2025-69720](https://security-tracker.debian.org/tracker/CVE-2025-69720) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0142 | libudev1 257.13-1~deb13u1 | [CVE-2013-4392](https://security-tracker.debian.org/tracker/CVE-2013-4392) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / unimportant |
| C03-0143 | libudev1 257.13-1~deb13u1 | [CVE-2023-31437](https://security-tracker.debian.org/tracker/CVE-2023-31437) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / unimportant |
| C03-0144 | libudev1 257.13-1~deb13u1 | [CVE-2023-31438](https://security-tracker.debian.org/tracker/CVE-2023-31438) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / unimportant |
| C03-0145 | libudev1 257.13-1~deb13u1 | [CVE-2023-31439](https://security-tracker.debian.org/tracker/CVE-2023-31439) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / unimportant |
| C03-0146 | libudev1 257.13-1~deb13u1 | [CVE-2026-15059](https://security-tracker.debian.org/tracker/CVE-2026-15059) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0147 | libudev1 257.13-1~deb13u1 | [CVE-2026-16742](https://security-tracker.debian.org/tracker/CVE-2026-16742) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0148 | libudev1 257.13-1~deb13u1 | [CVE-2026-40228](https://security-tracker.debian.org/tracker/CVE-2026-40228) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0149 | libuuid1 2.41.5-0+deb13u1 | [CVE-2022-0563](https://security-tracker.debian.org/tracker/CVE-2022-0563) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / unimportant |
| C03-0150 | libuuid1 2.41.5-0+deb13u1 | [CVE-2026-3184](https://security-tracker.debian.org/tracker/CVE-2026-3184) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0151 | libuuid1 2.41.5-0+deb13u1 | [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0152 | libuuid1 2.41.5-0+deb13u1 | [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0153 | libuuid1 2.41.5-0+deb13u1 | [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0154 | libuuid1 2.41.5-0+deb13u1 | [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0155 | login 1:4.16.0-2+really2.41.5-0+deb13u1 | [CVE-2022-0563](https://security-tracker.debian.org/tracker/CVE-2022-0563) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / unimportant |
| C03-0156 | login 1:4.16.0-2+really2.41.5-0+deb13u1 | [CVE-2026-3184](https://security-tracker.debian.org/tracker/CVE-2026-3184) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / not yet assigned |
| C03-0157 | login 1:4.16.0-2+really2.41.5-0+deb13u1 | [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / not yet assigned |
| C03-0158 | login 1:4.16.0-2+really2.41.5-0+deb13u1 | [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / not yet assigned |
| C03-0159 | login 1:4.16.0-2+really2.41.5-0+deb13u1 | [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / not yet assigned |
| C03-0160 | login 1:4.16.0-2+really2.41.5-0+deb13u1 | [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / not yet assigned |
| C03-0161 | login.defs 1:4.17.4-2 | [CVE-2007-5686](https://security-tracker.debian.org/tracker/CVE-2007-5686) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / unimportant |
| C03-0162 | login.defs 1:4.17.4-2 | [CVE-2024-56433](https://security-tracker.debian.org/tracker/CVE-2024-56433) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / not yet assigned |
| C03-0163 | login.defs 1:4.17.4-2 | [TEMP-0628843-DBAD28](https://security-tracker.debian.org/tracker/TEMP-0628843-DBAD28) | P2 | 로컬/관리 호출 조건 필요 | trixie open / unimportant |
| C03-0164 | mount 2.41.5-0+deb13u1 | [CVE-2022-0563](https://security-tracker.debian.org/tracker/CVE-2022-0563) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / unimportant |
| C03-0165 | mount 2.41.5-0+deb13u1 | [CVE-2026-3184](https://security-tracker.debian.org/tracker/CVE-2026-3184) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / not yet assigned |
| C03-0166 | mount 2.41.5-0+deb13u1 | [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / not yet assigned |
| C03-0167 | mount 2.41.5-0+deb13u1 | [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / not yet assigned |
| C03-0168 | mount 2.41.5-0+deb13u1 | [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / not yet assigned |
| C03-0169 | mount 2.41.5-0+deb13u1 | [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / not yet assigned |
| C03-0170 | ncurses-base 6.5+20250216-2 | [CVE-2025-6141](https://security-tracker.debian.org/tracker/CVE-2025-6141) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / not yet assigned |
| C03-0171 | ncurses-base 6.5+20250216-2 | [CVE-2025-69720](https://security-tracker.debian.org/tracker/CVE-2025-69720) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / not yet assigned |
| C03-0172 | ncurses-bin 6.5+20250216-2 | [CVE-2025-6141](https://security-tracker.debian.org/tracker/CVE-2025-6141) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / not yet assigned |
| C03-0173 | ncurses-bin 6.5+20250216-2 | [CVE-2025-69720](https://security-tracker.debian.org/tracker/CVE-2025-69720) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / not yet assigned |
| C03-0174 | passwd 1:4.17.4-2 | [CVE-2007-5686](https://security-tracker.debian.org/tracker/CVE-2007-5686) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / unimportant |
| C03-0175 | passwd 1:4.17.4-2 | [CVE-2024-56433](https://security-tracker.debian.org/tracker/CVE-2024-56433) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / not yet assigned |
| C03-0176 | passwd 1:4.17.4-2 | [TEMP-0628843-DBAD28](https://security-tracker.debian.org/tracker/TEMP-0628843-DBAD28) | P2 | 로컬/관리 호출 조건 필요 | trixie open / unimportant |
| C03-0177 | perl-base 5.40.1-6+deb13u1 | [CVE-2011-4116](https://security-tracker.debian.org/tracker/CVE-2011-4116) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / unimportant |
| C03-0178 | perl-base 5.40.1-6+deb13u1 | [CVE-2026-15534](https://security-tracker.debian.org/tracker/CVE-2026-15534) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0179 | perl-base 5.40.1-6+deb13u1 | [CVE-2026-82560](https://security-tracker.debian.org/tracker/CVE-2026-82560) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0180 | perl-base 5.40.1-6+deb13u1 | [CVE-2026-9538](https://security-tracker.debian.org/tracker/CVE-2026-9538) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0181 | sysvinit-utils 3.14-4 | [TEMP-0517018-A83CE6](https://security-tracker.debian.org/tracker/TEMP-0517018-A83CE6) | P2 | 검사 프로필에 부팅 전제 없음 | trixie open / unimportant |
| C03-0182 | tar 1.35+dfsg-3.1 | [CVE-2005-2541](https://security-tracker.debian.org/tracker/CVE-2005-2541) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / unimportant |
| C03-0183 | tar 1.35+dfsg-3.1 | [CVE-2026-18477](https://security-tracker.debian.org/tracker/CVE-2026-18477) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / not yet assigned |
| C03-0184 | tar 1.35+dfsg-3.1 | [CVE-2026-18508](https://security-tracker.debian.org/tracker/CVE-2026-18508) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / not yet assigned |
| C03-0185 | tar 1.35+dfsg-3.1 | [CVE-2026-5704](https://security-tracker.debian.org/tracker/CVE-2026-5704) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / not yet assigned |
| C03-0186 | tar 1.35+dfsg-3.1 | [TEMP-0290435-0B57B5](https://security-tracker.debian.org/tracker/TEMP-0290435-0B57B5) | P2 | 로컬/관리 호출 조건 필요 | trixie open / unimportant |
| C03-0187 | util-linux 2.41.5-0+deb13u1 | [CVE-2022-0563](https://security-tracker.debian.org/tracker/CVE-2022-0563) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / unimportant |
| C03-0188 | util-linux 2.41.5-0+deb13u1 | [CVE-2026-3184](https://security-tracker.debian.org/tracker/CVE-2026-3184) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / not yet assigned |
| C03-0189 | util-linux 2.41.5-0+deb13u1 | [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / not yet assigned |
| C03-0190 | util-linux 2.41.5-0+deb13u1 | [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / not yet assigned |
| C03-0191 | util-linux 2.41.5-0+deb13u1 | [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / not yet assigned |
| C03-0192 | util-linux 2.41.5-0+deb13u1 | [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410) | P2 | vendor open·도구/데이터 조건 검토 | trixie open / not yet assigned |
| C03-0193 | zlib1g 1:1.3.dfsg+really1.3.1-1+b1 | [CVE-2026-27171](https://security-tracker.debian.org/tracker/CVE-2026-27171) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0194 | zlib1g 1:1.3.dfsg+really1.3.1-1+b1 | [CVE-2026-85091](https://security-tracker.debian.org/tracker/CVE-2026-85091) | P2 | vendor open·공유 라이브러리 조건 검토 | trixie open / not yet assigned |
| C03-0195 | pip 25.0.1 | [CVE-2025-8869 / GHSA-4xh5-x5gv-qwph](https://github.com/advisories/GHSA-4xh5-x5gv-qwph) | P2 | 관측 경로에서 pip fallback 전제 완화 | pip <= 25.2 |
| C03-0196 | pip 25.0.1 | [CVE-2026-3219 / GHSA-58qw-9mgm-455v](https://github.com/advisories/GHSA-58qw-9mgm-455v) | P2 | 조건부 빌드/설치 입력 위험 | pip <= 26.0.1 |
| C03-0197 | pip 25.0.1 | [CVE-2026-1703 / GHSA-6vgw-5pg2-w6jp](https://github.com/advisories/GHSA-6vgw-5pg2-w6jp) | P2 | 조건부 빌드/설치 입력 위험 | pip < 26.0 |
| C03-0198 | pip 25.0.1 | [CVE-2026-6357 / GHSA-jp4c-xjxw-mgf9](https://github.com/advisories/GHSA-jp4c-xjxw-mgf9) | P2 | 관측 설정에서 pip self-check 전제 완화 | pip < 26.1 |
| C03-0199 | pip 25.0.1 | [CVE-2026-13346 / GHSA-qwm4-qh6w-59xr](https://github.com/advisories/GHSA-qwm4-qh6w-59xr) | P2 | 조건부 빌드/설치 입력 위험 | pip < 26.2.0 |
| C03-0200 | pip 25.0.1 | [CVE-2026-8643 / GHSA-wf93-45jw-7689](https://github.com/advisories/GHSA-wf93-45jw-7689) | P2 | 조건부 빌드/설치 입력 위험 | pip < 26.1.2 |
