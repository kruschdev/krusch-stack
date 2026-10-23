FROM node:22-slim

WORKDIR /app

ENV NODE_ENV=production
ENV KRUSCH_STACK_PORT=3780
ENV KRUSCH_WORKSPACE_ROOT=/workspace
ENV OLLAMA_HOST=http://127.0.0.1:11434

COPY package*.json ./
RUN npm install --omit=dev --ignore-scripts && npm cache clean --force

COPY bin ./bin
COPY src ./src
COPY db ./db
COPY spec.md ./

RUN mkdir -p /workspace /app/.krusch-stack

EXPOSE 3780

CMD ["node", "bin/krusch-stack.js", "serve"]
