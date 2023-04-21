SHELL := /bin/bash
.PHONY: help
primary := '\033[1;36m'
err := '\033[0;31m'
bold := '\033[1m'
clear := '\033[0m'

-include .env
export $(shell sed 's/=.*//' .env)
ifndef CI_BUILD_REF
CI_BUILD_REF=local
endif
ifeq ($(CI_BUILD_REF), local)
-include .env.local
export $(shell sed 's/=.*//' .env.local)
endif

help: ## This help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

ifndef BUILD_ENV
BUILD_ENV=development
endif
ifndef APP_ENV
APP_ENV=Dev
endif
ifndef RUNNER_NAME
RUNNER_NAME=$(shell basename $(shell pwd))
endif
ifndef PKG_PATH
PKG_PATH=.$(BUILD_ENV)
endif

deps: ## install dependancies for development of this project
	pip install -U pip
	pip install -U -r requirements-dev.txt
	pip install -e .
	pre-commit autoupdate

setup: ## setup for development of this project
	pre-commit install --hook-type pre-push --hook-type pre-commit
	@ [ -f .secrets.baseline ] || ( detect-secrets scan > .secrets.baseline )
	detect-secrets audit .secrets.baseline

clean: ## Cleanup tmp files
	@rm -rf .development/amass_linux_amd64
	@find . -type f -name '*.pyc' -delete 2>/dev/null
	@find . -type d -name '__pycache__' -delete 2>/dev/null
	@find . -type f -name '*.DS_Store' -delete 2>/dev/null
	@rm -f **/*.zip **/*.tar **/*.tgz **/*.gz

env:
	@echo -e $(bold)$(primary)BUILD_ENV$(clear) = $(BUILD_ENV)
	@echo -e $(bold)$(primary)APP_ENV$(clear) = $(APP_ENV)
	@echo -e $(bold)$(primary)CI_BUILD_REF$(clear) = $(CI_BUILD_REF)

output: env
	@echo -e $(bold)$(primary)trivialscan_subdomains_queue_arn$(clear) = $(shell terraform -chdir=plans output trivialscan_subdomains_queue_arn)
	@echo -e $(bold)$(primary)trivialscan_subdomains_queue_role$(clear) = $(shell terraform -chdir=plans output trivialscan_subdomains_queue_role)
	@echo -e $(bold)$(primary)trivialscan_subdomains_queue_role_arn$(clear) = $(shell terraform -chdir=plans output trivialscan_subdomains_queue_role_arn)
	@echo -e $(bold)$(primary)trivialscan_subdomains_queue_policy_arn$(clear) = $(shell terraform -chdir=plans output trivialscan_subdomains_queue_policy_arn)

build: env ## makes the lambda zip archive
	./.$(BUILD_ENV)/bin/build-archive

tfinstall:
	curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
	sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(shell lsb_release -cs) main"
	sudo apt-get update
	sudo apt-get install -y terraform
	terraform -install-autocomplete || true

.ONESHELL:
amass:
	[ -f $(PKG_PATH)/amass_linux_amd64-$(AMASS_VERSION).zip ] || \
	wget -q https://github.com/OWASP/Amass/releases/download/v$(AMASS_VERSION)/amass_linux_amd64.zip -O $(PKG_PATH)/amass_linux_amd64-$(AMASS_VERSION).zip
	unzip -qo $(PKG_PATH)/amass_linux_amd64-$(AMASS_VERSION).zip -d $(PKG_PATH)/
	mkdir -p src/vendored/amass
	cp $(PKG_PATH)/amass_linux_amd64/amass src/vendored/amass/amass
	chmod a+x src/vendored/amass/amass
	[ -f src/vendored/amass/all.txt ] || \
	wget -q https://raw.githubusercontent.com/OWASP/Amass/v$(AMASS_VERSION)/examples/wordlists/all.txt -O src/vendored/amass/all.txt
	[ -f src/vendored/amass/deepmagic.com_top500prefixes.txt ] || \
	wget -q https://raw.githubusercontent.com/OWASP/Amass/v$(AMASS_VERSION)/examples/wordlists/deepmagic.com_top500prefixes.txt -O src/vendored/amass/deepmagic.com_top500prefixes.txt
	[ -f src/vendored/amass/bitquark_subdomains_top100K.txt ] || \
	wget -q https://raw.githubusercontent.com/OWASP/Amass/v$(AMASS_VERSION)/examples/wordlists/bitquark_subdomains_top100K.txt -O src/vendored/amass/bitquark_subdomains_top100K.txt
	[ -f src/vendored/amass/sorted_knock_dnsrecon_fierce_recon-ng.txt ] || \
	wget -q https://raw.githubusercontent.com/OWASP/Amass/v$(AMASS_VERSION)/examples/wordlists/sorted_knock_dnsrecon_fierce_recon-ng.txt -O src/vendored/amass/sorted_knock_dnsrecon_fierce_recon-ng.txt

init: env ## Runs tf init tf
	terraform -chdir=plans init -backend-config=${APP_ENV}-backend.conf -reconfigure -upgrade=true

plan: ## Runs tf validate and tf plan
	terraform -chdir=plans fmt
	terraform -chdir=plans validate
	terraform -chdir=plans plan -no-color -out=.tfplan
	terraform -chdir=plans show --json .tfplan | jq -r '([.resource_changes[]?.change.actions?]|flatten)|{"create":(map(select(.=="create"))|length),"update":(map(select(.=="update"))|length),"delete":(map(select(.=="delete"))|length)}' > plans/tfplan.json

apply: ## tf apply -auto-approve -refresh=true
	terraform -chdir=plans apply -auto-approve -refresh=true .tfplan

destroy: init ## tf destroy -auto-approve
	terraform -chdir=plans validate
	terraform -chdir=plans plan -destroy -no-color -out=.tfdestroy
	terraform -chdir=plans show --json .tfdestroy | jq -r '([.resource_changes[]?.change.actions?]|flatten)|{"create":(map(select(.=="create"))|length),"update":(map(select(.=="update"))|length),"delete":(map(select(.=="delete"))|length)}' > plans/tfdestroy.json
	terraform -chdir=plans apply -auto-approve -destroy .tfdestroy

test-local: ## Prettier test outputs
	pre-commit run --all-files
	semgrep -q --strict --timeout=0 --config=p/r2c-ci --lang=py src/**/*.py

unit-test: ## run unit tests with coverage
	coverage run -m pytest --nf
	coverage report -m

local-runner: ## local setup for a gitlab runner
	@docker volume create --name=gitlab-cache 2>/dev/null || true
	docker pull -q docker.io/gitlab/gitlab-runner:latest
	docker build -t $(RUNNER_NAME)/runner:${CI_BUILD_REF} -f Dockerfile-runner .
	@echo $(shell [ -z "${RUNNER_TOKEN}" ] && echo "RUNNER_TOKEN missing" )
	@docker run -d --rm \
		--name $(RUNNER_NAME) \
		-v "gitlab-cache:/cache:rw" \
		-v "/var/run/docker.sock:/var/run/docker.sock:rw" \
		-e RUNNER_TOKEN=${RUNNER_TOKEN} \
		$(RUNNER_NAME)/runner:${CI_BUILD_REF}
	@docker exec -ti $(RUNNER_NAME) gitlab-runner register --non-interactive \
		--tag-list 'jager' \
		--name $(RUNNER_NAME) \
		--request-concurrency 10 \
		--url https://gitlab.com/ \
		--registration-token '$(RUNNER_TOKEN)' \
		--cache-dir '/cache' \
		--executor shell

tail-aws-logs: ## Install using pipx install awscliv2
	awsv2 logs tail "/aws/lambda/$(shell sed -e 's/\(.*\)/\L\1/' <<< "${APP_ENV}")-trivialscan-subdomains-queue" --follow
