FROM node:22-bookworm-slim AS build
WORKDIR /src/apps/control-web
COPY apps/control-web/package*.json ./
RUN npm ci
COPY apps/control-web/ ./
COPY contracts/ /src/contracts/
RUN ZEKVAR_STANDALONE=1 NEXT_TELEMETRY_DISABLED=1 npm run build \
    && mkdir -p .next/standalone/.next \
    && cp -R .next/static .next/standalone/.next/static

FROM node:22-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 HOSTNAME=127.0.0.1 PORT=3000
COPY --chown=node:node --from=build /src/apps/control-web/.next/standalone/ ./
USER node
CMD ["node", "server.js"]
