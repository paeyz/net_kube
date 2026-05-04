FROM python:3.12-slim

# kubectl 설치 (외부 레지스트리 없이 minikube image load 사용)
ARG KUBECTL_VERSION=v1.30.8
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -LO "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" \
    && chmod +x kubectl && mv kubectl /usr/local/bin/ \
    && apt-get purge -y curl \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /attack

# 소스 복사 (외부 Python 패키지 없음 — 표준 라이브러리만 사용)
COPY poc/ ./poc/
COPY results/.gitkeep ./results/.gitkeep

ENV PYTHONUNBUFFERED=1

# 클러스터 내부 실행 시 port-forward 없이 서비스 DNS로 직접 접근
ENTRYPOINT ["python3", "poc/attack_chain.py"]
CMD ["--target", "https://ingress-nginx-controller-admission.ingress-nginx.svc.cluster.local:443", \
     "--out", "/attack/results"]
