#!/usr/bin/env bash
PRIMARY='\033[1;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color
echo -e "${PRIMARY}
▀▀█▀▀ █▀▀█ ░▀░ ▀█░█▀ ░▀░ █▀▀█ █░░ █▀▀ █▀▀ █▀▀█ █▀▀▄
░░█░░ █▄▄▀ ▀█▀ ░█▄█░ ▀█▀ █▄▄█ █░░ ▀▀█ █░░ █▄▄█ █░░█
░░▀░░ ▀░▀▀ ▀▀▀ ░░▀░░ ▀▀▀ ▀░░▀ ▀▀▀ ▀▀▀ ▀▀▀ ▀░░▀ ▀░░▀${NC}"

if [[ -f .env ]]; then
  source .env
fi
if [[ -f .env.local ]]; then
  source .env.local
fi
export TF_VAR_aws_access_key_id=${TF_VAR_aws_access_key_id:-$AWS_ACCESS_KEY_ID}
export TF_VAR_aws_secret_access_key=${TF_VAR_aws_secret_access_key:-$AWS_SECRET_ACCESS_KEY}
[ -z "${TF_VAR_aws_access_key_id}" ] && echo -e "${RED}AWS_ACCESS_KEY_ID (or TF_VAR_aws_access_key_id) not set${NC}"
[ -z "${TF_VAR_aws_secret_access_key}" ] && echo -e "${RED}AWS_SECRET_ACCESS_KEY (or TF_VAR_aws_secret_access_key) not set${NC}"
aws sts get-caller-identity
readonly default_env=Dev
readonly default_name=$(id -nu)-$(cat /etc/hostname)
export APP_ENV=${APP_ENV:-${default_env}}
export APP_NAME=${APP_NAME:-${default_name}}
export TF_VAR_app_env=${APP_ENV}
export TF_VAR_app_name=${APP_NAME}
git fetch
git status
echo -e "${PRIMARY}$(make --version)${NC}\n$(make help)"
# [ -f .venv/bin/activate ] && source .venv/bin/activate
