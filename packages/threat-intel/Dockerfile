FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/shared ./packages/shared
COPY packages/threat-intel ./packages/threat-intel
RUN npm install --ignore-scripts
RUN npx tsc -b --force packages/threat-intel/tsconfig.json

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/packages/shared/dist ./packages/shared/dist
COPY --from=build /app/packages/shared/package.json ./packages/shared/
COPY --from=build /app/packages/threat-intel/dist ./packages/threat-intel/dist
COPY --from=build /app/packages/threat-intel/package.json ./packages/threat-intel/
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
EXPOSE 3003
CMD ["node", "packages/threat-intel/dist/index.js"]
