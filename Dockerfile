FROM astral/uv:python3.13-alpine AS builder

WORKDIR /app
# virtual env is created in "/app/.venv" directory
RUN uv init
COPY ./backend/pyproject.toml /app
RUN uv sync --no-dev

ENTRYPOINT [ "/bin/sh" ]

# build frontend and copy dist to backend static files
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend
COPY ./frontend/e2ee-fe/pnpm-lock.yaml ./frontend/e2ee-fe/package.json ./
RUN corepack enable && pnpm install --frozen-lockfile
COPY ./frontend/e2ee-fe/ .
RUN pnpm build

FROM python:3.13-alpine AS runner
COPY ./backend/src /app/src
COPY ./backend/*.pem /app/
COPY --from=builder /app/.venv /app/.venv
COPY --from=frontend-builder /app/frontend/dist /app/static
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH=/app/.venv/lib/python3.13/site-packages

WORKDIR /app
EXPOSE 8000
ENTRYPOINT ["python", "src/main.py"]
