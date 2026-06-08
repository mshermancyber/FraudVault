FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/shared ./packages/shared
COPY packages/orchestrator ./packages/orchestrator
RUN npm install --ignore-scripts
RUN npx tsc -b --force packages/orchestrator/tsconfig.json

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/packages/shared/dist ./packages/shared/dist
COPY --from=build /app/packages/shared/package.json ./packages/shared/
COPY --from=build /app/packages/orchestrator/dist ./packages/orchestrator/dist
COPY --from=build /app/packages/orchestrator/src/extractors-library.py ./packages/orchestrator/dist/extractors-library.py
COPY --from=build /app/packages/orchestrator/package.json ./packages/orchestrator/
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
EXPOSE 3001
CMD ["node", "packages/orchestrator/dist/index.js"]
