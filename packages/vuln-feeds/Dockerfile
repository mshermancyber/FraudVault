FROM node:22-alpine AS build
# better-sqlite3 needs native compilation
RUN apk add --no-cache python3 make g++
WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/vuln-feeds ./packages/vuln-feeds
RUN npm install --ignore-scripts
# Build better-sqlite3 native addon
RUN cd node_modules/better-sqlite3 && npx --yes node-gyp rebuild
RUN npx tsc -b --force packages/vuln-feeds/tsconfig.json

FROM node:22-alpine
# better-sqlite3 needs libstdc++ at runtime
RUN apk add --no-cache libstdc++
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/packages/vuln-feeds/dist ./packages/vuln-feeds/dist
COPY --from=build /app/packages/vuln-feeds/package.json ./packages/vuln-feeds/
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
RUN mkdir -p /data /data/osv-cache
EXPOSE 9000
CMD ["node", "packages/vuln-feeds/dist/index.js"]
