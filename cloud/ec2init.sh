#!/bin/bash
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive
# This script is passed to the ec2 instance when deployed and runs this on startup


BT_IMAGE="ghcr.io/tenki2/btclient:dev"
HOST_SAVE_PATH="/opt/btclient/data"
HOST_ARTIFACTS_DIR="/opt/btclient/artifacts"


# install dependencies
apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates \
  curl \
  unzip


# install aws cli
cd /tmp
curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip -q awscliv2.zip
./aws/install
/usr/local/bin/aws --version


# get tailscale auth key from the parameter store
set +x
TS_AUTHKEY=""
for attempt in $(seq 1 30); do
  if TS_AUTHKEY="$(/usr/local/bin/aws ssm get-parameter --name /tailscale --with-decryption --output text --region eu-central-1 --query 'Parameter.Value' 2>/tmp/tailscale-ssm.err)"; then
    break
  fi

  echo "Waiting for AWS instance profile credentials/SSM access (${attempt}/30)..." >&2
  cat /tmp/tailscale-ssm.err >&2 || true
  sleep 5
done

if [ -z "${TS_AUTHKEY}" ]; then
  echo "Failed to read /tailscale from SSM after waiting for instance profile credentials." >&2
  exit 1
fi
set -x


# install docker
curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
sh /tmp/get-docker.sh
systemctl enable --now docker
docker --version

# install tailscale
curl -fsSL https://tailscale.com/install.sh | sh
systemctl enable --now tailscaled

set +x
tailscale up --auth-key="${TS_AUTHKEY}"
set -x


# make important directories for btclient
mkdir -p "${HOST_SAVE_PATH}" "${HOST_ARTIFACTS_DIR}"


# pull the btclient image early because its 2gb and will take a bit to download
docker pull "${BT_IMAGE}"
touch /home/ubuntu/bootstrap.finished
# clean up environment
rm -rf /tmp/aws /tmp/awscliv2.zip /tmp/get-docker.sh
apt-get clean
rm -rf /var/lib/apt/lists/*
