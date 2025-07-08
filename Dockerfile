FROM python:3.9-slim

LABEL "com.github.actions.name"="VulnAlerts"
LABEL "com.github.actions.description"="Daily customized CVE Alerts straight to your Slack Inbox for Free."
LABEL "version"="1.0"
LABEL "com.github.actions.icon"="shield"
LABEL "com.github.actions.color"="blue"
LABEL "repository"="https://github.com/y-mehta/vulnalerts"
LABEL "homepage"="https://github.com/y-mehta/vulnalerts"

RUN apt-get update && apt-get install -y unzip
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY README.md main.py entrypoint.sh cpe.txt  ./

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
