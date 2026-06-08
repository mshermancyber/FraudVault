FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/shared ./packages/shared
COPY packages/sandbox-manager ./packages/sandbox-manager
RUN npm install --ignore-scripts
RUN npx tsc -b --force packages/sandbox-manager/tsconfig.json

FROM node:22-alpine
RUN apk add --no-cache qemu-system-x86_64 qemu-img iptables iproute2
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/packages/shared/dist ./packages/shared/dist
COPY --from=build /app/packages/shared/package.json ./packages/shared/
COPY --from=build /app/packages/sandbox-manager/dist ./packages/sandbox-manager/dist
COPY --from=build /app/packages/sandbox-manager/package.json ./packages/sandbox-manager/
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
EXPOSE 3008
CMD ["node", "packages/sandbox-manager/dist/index.js"]
