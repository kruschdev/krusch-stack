FROM node:22-slim

WORKDIR /app

ENV NODE_ENV=production
ENV KRUSCH_STACK_HOST=0.0.0.0
ENV KRUSCH_STACK_PORT=3780
ENV KRUSCH_WORKSPACE_ROOT=/workspace
ENV DB_PATH=/app/.krusch-stack/stack.db
ENV OLLAMA_HOST=http://127.0.0.1:11434

COPY package*.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

COPY bin ./bin
COPY src ./src
COPY db ./db
COPY spec.md INSTALL.md README.md LICENSE ./

RUN mkdir -p /workspace /app/.krusch-stack && chown -R node:node /workspace /app

USER node

EXPOSE 3780

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:' + (process.env.KRUSCH_STACK_PORT || 3780) + '/health').then((r) => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"]

CMD ["node", "bin/krusch-stack.js", "serve"]
