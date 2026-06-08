FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/shared ./packages/shared
COPY packages/static-analysis ./packages/static-analysis
RUN npm install --ignore-scripts
RUN npx tsc -b --force packages/static-analysis/tsconfig.json

FROM node:22-alpine
RUN apk add --no-cache python3 py3-pip file
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/packages/shared/dist ./packages/shared/dist
COPY --from=build /app/packages/shared/package.json ./packages/shared/
COPY --from=build /app/packages/static-analysis/dist ./packages/static-analysis/dist
COPY --from=build /app/packages/static-analysis/package.json ./packages/static-analysis/
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
EXPOSE 3002
CMD ["node", "packages/static-analysis/dist/index.js"]
