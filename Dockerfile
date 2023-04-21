FROM public.ecr.aws/lambda/python:3.10

LABEL org.opencontainers.image.authors="Christopher Langton"
LABEL org.opencontainers.image.version="0.0.1"
LABEL org.opencontainers.image.source="https://gitlab.com/trivialsec/trivialscan-subdomains-queue"

ENV PYTHONPATH ${PYTHONPATH}

WORKDIR ${LAMBDA_TASK_ROOT}
COPY pyproject.toml .

RUN echo "Installing from pyproyect.toml" \
    && python -m pip install --progress-bar off -U --no-python-version-warning pip \
    && python -m pip install --progress-bar off -U --no-cache-dir .
CMD [ "app.handler" ]
