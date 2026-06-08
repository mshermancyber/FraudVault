FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/shared ./packages/shared
COPY packages/search ./packages/search
RUN npm install --ignore-scripts
RUN npx tsc -b --force packages/search/tsconfig.json

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/packages/shared/dist ./packages/shared/dist
COPY --from=build /app/packages/shared/package.json ./packages/shared/
COPY --from=build /app/packages/search/dist ./packages/search/dist
COPY --from=build /app/packages/search/package.json ./packages/search/
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
EXPOSE 3005
CMD ["node", "packages/search/dist/index.js"]
