FROM kalilinux/kali-rolling:latest

RUN apt update && apt install -y git nodejs npm && npm install -g rms-runtime-mobile-security

ENTRYPOINT ["/usr/local/bin/rms"]
