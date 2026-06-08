FROM node:22-alpine AS build
RUN apk add --no-cache python3 make g++
WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/shared ./packages/shared
COPY packages/api-gateway ./packages/api-gateway
RUN npm install
RUN npx tsc -b --force packages/api-gateway/tsconfig.json

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/packages/shared/dist ./packages/shared/dist
COPY --from=build /app/packages/shared/package.json ./packages/shared/
COPY --from=build /app/packages/api-gateway/dist ./packages/api-gateway/dist
COPY --from=build /app/packages/api-gateway/package.json ./packages/api-gateway/
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
EXPOSE 3000
CMD ["node", "packages/api-gateway/dist/index.js"]
