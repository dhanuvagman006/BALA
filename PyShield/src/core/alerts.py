from __future__ import annotations

import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List, Optional, Dict, Any

import requests


class AlertSender:
    def __init__(self, *,
                 smtp_host: str = "",
                 smtp_port: int = 587,
                 smtp_username: str = "",
                 smtp_password: str = "",
                 from_email: str = "",
                 to_emails: Optional[List[str]] = None,
                 discord_webhook_url: Optional[str] = None,
                 slack_webhook_url: Optional[str] = None) -> None:
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_username = smtp_username
        self.smtp_password = smtp_password
        self.from_email = from_email
        self.to_emails = to_emails or []
        self.discord_webhook_url = discord_webhook_url
        self.slack_webhook_url = slack_webhook_url

    def send_email(self, subject: str, html_body: str, *, timeout: int = 10) -> None:
        if not (self.smtp_host and self.from_email and self.to_emails):
            return
        msg = MIMEMultipart()
        msg["From"] = self.from_email
        msg["To"] = ", ".join(self.to_emails)
        msg["Subject"] = subject
        msg.attach(MIMEText(html_body, "html"))

        context = ssl.create_default_context()
        with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=timeout) as server:
            server.starttls(context=context)
            if self.smtp_username and self.smtp_password:
                server.login(self.smtp_username, self.smtp_password)
            server.sendmail(self.from_email, self.to_emails, msg.as_string())

    def send_discord(self, content: str, *, timeout: int = 10) -> None:
        if not self.discord_webhook_url:
            return
        requests.post(self.discord_webhook_url, json={"content": content}, timeout=timeout)

    def send_slack(self, text: str, *, timeout: int = 10) -> None:
        if not self.slack_webhook_url:
            return
        requests.post(self.slack_webhook_url, json={"text": text}, timeout=timeout)

    def alert(self, title: str, message: str, *, context: Optional[Dict[str, Any]] = None) -> None:
        content = f"{title}: {message}"
        if context:
            content += "\n" + "\n".join([f"- {k}: {v}" for k, v in context.items()])
        # Fan-out to enabled channels
        self.send_discord(content)
        self.send_slack(content)
        self.send_email(title, f"<pre>{content}</pre>")
