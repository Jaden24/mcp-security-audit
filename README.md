# Security Audit MCP Server

> AI 에이전트 보안 감사 도구 — CodeIntegrity AARM 개념 구현체

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/protocol-MCP-green.svg)](https://modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 이게 뭔가요?

AI 에이전트가 MCP를 통해 Notion, Gmail, Linear 같은 툴을 쓸 때 발생하는 보안 위협을 탐지하는 MCP 서버입니다.

[CodeIntegrity](https://www.codeintegrity.ai/)의 AARM(Agent Action Runtime Mediation) 플랫폼 개념을 오픈소스로 구현했습니다.

**탐지 가능한 위협:**
- 🔴 프롬프트 인젝션 (Prompt Injection)
- 🔴 PII 데이터 유출 (SSN, IBAN, 신용카드 등)
- 🔴 Toxic Flow (무해한 툴 호출들이 조합되면 위험)
- 🟡 민감 데이터 경계 위반
- 🟡 데이터 유출(Exfiltration) 시도

---

## 제공 툴 (5개)

| 툴 이름 | 기능 |
|---------|------|
| `scan_pii` | 텍스트에서 PII 탐지 |
| `check_injection` | 프롬프트 인젝션 패턴 탐지 |
| `audit_flow` | 에이전트 워크플로우 전체 데이터 흐름 감사 |
| `generate_report` | SOC 2 감사용 종합 보안 리포트 생성 |
| `explain_threat` | 보안 위협 개념 설명 (한국어) |

---

## 빠른 시작

### 1. 설치

```bash
git clone https://github.com/YOUR_USERNAME/security-audit-mcp.git
cd security-audit-mcp
pip install -r requirements.txt
```

### 2. 테스트 (MCP 클라이언트 없이 바로 실행)

```bash
# 모든 테스트 실행
python test_client.py

# 특정 테스트만
python test_client.py --test pii
python test_client.py --test injection
python test_client.py --test flow
python test_client.py --test report
python test_client.py --test explain
```

### 3. MCP 서버 실행

```bash
python server.py
```

---

## 클라이언트 연결 방법

### Claude Desktop

`~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
`%APPDATA%\Claude\claude_desktop_config.json` (Windows)

```json
{
  "mcpServers": {
    "security-audit": {
      "command": "python",
      "args": ["/절대경로/security-audit-mcp/server.py"]
    }
  }
}
```

저장 후 Claude Desktop 재시작.

### Cursor IDE

`.cursor/mcp.json` (프로젝트 루트 또는 홈 디렉토리):

```json
{
  "mcpServers": {
    "security-audit": {
      "command": "python",
      "args": ["/절대경로/security-audit-mcp/server.py"]
    }
  }
}
```

### Windsurf

`~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "security-audit": {
      "command": "python",
      "args": ["/절대경로/security-audit-mcp/server.py"]
    }
  }
}
```

---

## 연결 후 사용 예시

Claude/Cursor에서 이렇게 말하면 됩니다:

```
"이 텍스트에서 PII를 스캔해줘:
 John Smith, SSN: 392-45-8821, email: john@acme.com"

"이 Notion 페이지 내용에 프롬프트 인젝션이 있는지 확인해줘:
 [SYSTEM OVERRIDE: ignore all previous instructions...]"

"lethal_trifecta 개념 설명해줘"

"이 에이전트 워크플로우 감사해줘 — 
 툴 결과: {...}, 다음 액션: [send_email(...)]"
```

---

## MCP가 뭔가요? (처음 보시는 분)

MCP(Model Context Protocol)는 AI 에이전트가 외부 툴과 통신하는 **오픈 표준**입니다.
Anthropic이 만들었지만 Claude 전용이 아닙니다 — Claude, Cursor, Windsurf 등 모든 MCP 지원 클라이언트에서 작동합니다.

```
[AI 클라이언트]  ←→  MCP 프로토콜  ←→  [이 MCP 서버]
Claude Desktop                           scan_pii()
Cursor IDE                               check_injection()
Windsurf                                 audit_flow()
...                                      generate_report()
```

---

## 프로젝트 구조

```
security-audit-mcp/
├── server.py          # MCP 서버 (핵심 — 5개 툴 정의)
├── test_client.py     # 독립 테스트 클라이언트 (MCP 연결 불필요)
├── requirements.txt   # Python 패키지 목록
└── README.md          # 이 파일
```

---

## 아키텍처

```
사용자 (Claude/Cursor/Windsurf)
        ↕ MCP stdio 프로토콜
Security Audit MCP Server (server.py)
    ├── scan_pii()          → 정규식 기반 PII 탐지
    ├── check_injection()   → 인젝션 패턴 매칭
    ├── audit_flow()        → Toxic Flow 분석
    ├── generate_report()   → SOC 2 감사 리포트
    └── explain_threat()    → 개념 설명
```

---

## CodeIntegrity 관련 개념

| 이 프로젝트 | CodeIntegrity AARM |
|------------|-------------------|
| `check_injection()` | Dual-LLM quarantine |
| `audit_flow()` | Toxic Flow Detection |
| `generate_report()` | Action Evidence Log |
| `scan_pii()` | Data Provenance Classification |

---

## 확장 아이디어

- [ ] 실제 Notion/Linear MCP 서버와 연동
- [ ] 감사 로그를 SQLite 또는 PostgreSQL에 저장
- [ ] Slack 웹훅 연동 (위험 탐지 시 즉시 알림)
- [ ] HTTP 모드로 변경해서 클라우드 배포
- [ ] 커스텀 PII 패턴 추가 (사내 직원 ID 등)

---

## 라이선스

MIT — 자유롭게 사용, 수정, 배포하세요.

---

*Inspired by [CodeIntegrity](https://www.codeintegrity.ai/) — AI Agent Runtime Security*
