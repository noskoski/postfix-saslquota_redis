POSTFIX_SASLQUOTA_REDIS

Objective

Lightweight Postfix policy daemon to enforce per-sasl_username quotas using Redis.

Requirements

- Python 3
- Redis
- Postfix (policy service)

Quick start (Docker Compose)

1) Build and start

   docker-compose up --build

2) The service listens on _bind:_bindport (default 0.0.0.0:10008)

Configuration

The daemon reads saslquota.json and then overwrites values with environment
variables (useful for Docker). Example (src/saslquota.json.orig):

{
  "_bind": "127.0.0.1",
  "_bindport": 10008,
  "_bindtimeout": 120,
  "_redishost": "redis",
  "_redisport": 6379,
  "_redisdb": 0,
  "_logaddress": "127.0.0.1",
  "_logport": 514,
  "_logfacility": "mail",
  "_loglevel": "DEBUG",
  "_quotafile": "quotarules.json",
  "_loghandler": "syslog"
}

Quota rules

Create quotarules.json with per-user, per-domain, or default rules:

{
  "default": {
    "period": 120,
    "msgquota": 500,
    "msg": "Você já atingiu o limite, tente novamente mais tarde."
  },
  "example.com": {
    "period": 1200,
    "msgquota": 5000,
    "msg": "Limite do domínio atingido."
  },
  "user@example.com": {
    "period": 300,
    "msgquota": 50,
    "msg": "Limite do usuário atingido."
  }
}

Postfix integration

1) Add to /etc/postfix/main.cf

   saslquota = check_policy_service inet:127.0.0.1:10008

2) Enable in master.cf for submission/smtps (not on port 25):

   submission inet n       -       y       -       -       smtpd
     -o syslog_name=postfix/submission
     -o smtpd_tls_security_level=may
     -o smtpd_sasl_auth_enable=yes
     -o smtpd_tls_auth_only=no
     -o smtpd_reject_unlisted_recipient=no
     -o smtpd_client_restrictions=$saslquota

3) Reload postfix

   service postfix reload

Testing

1) Verify the daemon is listening

   netstat -nl | grep 10008

2) Send a policy request

   cat src/Testfile | netcat 127.0.0.1 10008

Response should be:

   action=OK

Logs

- If _loghandler is syslog, check mail/syslog for policy logs.
- If _loghandler is stdout, logs go to console (Docker logs).
