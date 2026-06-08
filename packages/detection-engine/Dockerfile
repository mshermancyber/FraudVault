FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/shared ./packages/shared
COPY packages/detection-engine ./packages/detection-engine
RUN npm install --ignore-scripts
RUN npx tsc -b --force packages/detection-engine/tsconfig.json

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/packages/shared/dist ./packages/shared/dist
COPY --from=build /app/packages/shared/package.json ./packages/shared/
COPY --from=build /app/packages/detection-engine/dist ./packages/detection-engine/dist
COPY --from=build /app/packages/detection-engine/package.json ./packages/detection-engine/
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
EXPOSE 3004
CMD ["node", "packages/detection-engine/dist/index.js"]
