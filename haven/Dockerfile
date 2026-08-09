FROM python:3.13.14@sha256:36f5673ec01bd1001d7cbb8f12215101aa4ee5d70ddbbb72e01b2930d7c12f19 AS builder

COPY flag.txt server.py run /app/

FROM pwn.red/jail
COPY --from=builder / /srv

ENV JAIL_TIME=120
ENV JAIL_PIDS=16
ENV JAIL_MEM=32M
ENV JAIL_CPU=1000
