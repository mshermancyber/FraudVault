FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/shared ./packages/shared
COPY packages/reporting ./packages/reporting
RUN npm install --ignore-scripts
RUN npx tsc -b --force packages/reporting/tsconfig.json

FROM node:22-alpine
RUN apk add --no-cache py3-pip pango cairo gdk-pixbuf font-noto \
    && pip3 install --break-system-packages weasyprint
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/packages/shared/dist ./packages/shared/dist
COPY --from=build /app/packages/shared/package.json ./packages/shared/
COPY --from=build /app/packages/reporting/dist ./packages/reporting/dist
COPY --from=build /app/packages/reporting/package.json ./packages/reporting/
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
EXPOSE 3006
CMD ["node", "packages/reporting/dist/index.js"]
