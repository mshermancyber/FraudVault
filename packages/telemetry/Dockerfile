FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/shared ./packages/shared
COPY packages/telemetry ./packages/telemetry
RUN npm install --ignore-scripts
RUN npx tsc -b --force packages/telemetry/tsconfig.json

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/packages/shared/dist ./packages/shared/dist
COPY --from=build /app/packages/shared/package.json ./packages/shared/
COPY --from=build /app/packages/telemetry/dist ./packages/telemetry/dist
COPY --from=build /app/packages/telemetry/package.json ./packages/telemetry/
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
EXPOSE 3007
CMD ["node", "packages/telemetry/dist/index.js"]
