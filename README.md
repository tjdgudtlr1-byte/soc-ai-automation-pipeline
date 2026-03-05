# SOC AI Automation Pipeline

온프레미스 보안 환경에서 **Splunk 알람을 AI로 자동 분석하고 Discord 기반 SOC 대응 워크플로우를 구축한 프로젝트**입니다.

Splunk에서 발생한 보안 이벤트를 수집하여 AI 분석을 수행하고, 결과를 Discord Incident Thread 형태로 전달하여 분석가가 빠르게 대응할 수 있도록 자동화된 관제 파이프라인을 구현했습니다.

---

# Architecture


Splunk Alert
↓
FastAPI AI Bridge
↓
OpenAI Analysis
↓
Splunk HEC 저장
↓
Discord Incident Thread 생성
↓
SOC Analyst 질문 / 추가 분석


---

# Features

### Splunk Alert Webhook 수집
Splunk Alert Webhook을 통해 보안 이벤트를 수신합니다.

### AI 기반 보안 이벤트 분석
OpenAI 모델을 활용하여 다음 정보를 자동 분석합니다.

- 공격 여부 판단
- 공격 요약
- 대응 우선순위
- 대응 액션 제안

### Prompt Injection 방어
LLM 입력 payload를 최소화하고 JSON 형식 출력을 강제하여  
LLM Prompt Injection 공격을 방지했습니다.

### Discord Incident Thread 자동 생성
알람 발생 시 Discord 채널에 Incident Thread가 생성되며  
SOC 분석가가 해당 스레드에서 추가 질문을 할 수 있습니다.

### Analyst Q&A 인터페이스
Discord Thread에서 질문하면 AI가 추가 분석을 제공합니다.

예:


FP 가능성?
대응 우선순위
추가 SPL 쿼리


---

# Project Components

## bridge.py

FastAPI 기반 AI 분석 서버

기능

- Splunk Alert Webhook 수신
- Alert payload 정규화
- OpenAI 기반 이벤트 분석
- JSON 결과 검증
- Splunk HEC로 분석 결과 전송

---

## discord_bot.py

Discord 기반 SOC Incident Bot

기능

- Alert 발생 시 Incident Thread 생성
- Incident 정보 저장 (SQLite)
- Thread 기반 분석 대화 지원
- AI Bridge와 연동하여 추가 분석 수행

---

# Security Design

본 프로젝트는 보안 환경을 고려하여 다음 설계를 적용했습니다.

### Secret 관리

모든 API Key는 환경변수로 관리합니다.


OPENAI_API_KEY
DISCORD_BOT_TOKEN
SPLUNK_HEC_TOKEN


### LLM Output Validation

AI 결과를 JSON Schema 형태로 검증하여  
예측 불가능한 응답을 방지합니다.

### Payload Sanitization

Splunk Alert payload를 최소 필드로 축소하여  
Prompt Injection 공격을 방지합니다.

---

# Environment Variables


OPENAI_API_KEY=

SPLUNK_HEC_URL=
SPLUNK_HEC_TOKEN=

DISCORD_BOT_TOKEN=
DISCORD_ALERT_CHANNEL_ID=

AI_BRIDGE_URL=http://127.0.0.1:9000


---

# Run

## Install dependencies

pip install -r requirements.txt

## Bridge Server

python bridge.py

## Discord Bot

python discord_bot.py

---

# Example Workflow

1. Splunk Alert 발생
2. FastAPI AI Bridge가 Alert 수신
3. OpenAI 모델을 통해 공격 여부 분석
4. 결과를 Splunk HEC로 저장
5. Discord 채널에 Incident Thread 생성
6. 분석가는 Thread에서 AI에게 추가 질문 가능

---

# Future Improvements

- Local LLM 기반 분석 파이프라인 구축
- SOC Playbook 자동 대응 기능
- Slack / Teams 연동
- SIEM 룰 자동 생성 기능

---

# Author

hahaman  

Blog  
https://sik13579.tistory.com/

# discord-incident.png
<img width="449" height="403" alt="image" src="https://github.com/user-attachments/assets/d0c43c6d-cf38-472d-be38-265379b523a6" />

# splunk-alert.png
<img width="733" height="533" alt="image" src="https://github.com/user-attachments/assets/d834acc0-79ae-45b0-8715-972de434948b" />



