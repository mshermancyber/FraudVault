FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/shared ./packages/shared
COPY packages/dynamic-analysis ./packages/dynamic-analysis
RUN npm install --ignore-scripts
RUN npx tsc -b --force packages/dynamic-analysis/tsconfig.json

FROM node:22-alpine
RUN apk add --no-cache ffmpeg tcpdump docker-cli
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/packages/shared/dist ./packages/shared/dist
COPY --from=build /app/packages/shared/package.json ./packages/shared/
COPY --from=build /app/packages/dynamic-analysis/dist ./packages/dynamic-analysis/dist
COPY --from=build /app/packages/dynamic-analysis/src/container-security-scan.py ./packages/dynamic-analysis/dist/docker-sandbox/container-security-scan.py
COPY --from=build /app/packages/dynamic-analysis/seccomp-sandbox.json ./packages/dynamic-analysis/seccomp-sandbox.json
COPY --from=build /app/packages/dynamic-analysis/package.json ./packages/dynamic-analysis/
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
EXPOSE 3009
CMD ["node", "packages/dynamic-analysis/dist/index.js"]
