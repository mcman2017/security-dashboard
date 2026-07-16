# syntax=docker/dockerfile:1.7
# Builds the plugin and packs it into a tiny image that Headlamp uses as an
# initContainer to seed /headlamp/plugins/headlamp-security-dashboard/.

FROM mirror.gcr.io/library/node:20-alpine AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM mirror.gcr.io/library/alpine:3.20
RUN adduser -D -u 1000 plugin
WORKDIR /plugins
COPY --from=build /src/dist/main.js     /plugins/headlamp-security-dashboard/main.js
COPY --from=build /src/package.json     /plugins/headlamp-security-dashboard/package.json
# The init-container entrypoint will copy /plugins/* into the shared volume.
# Keep the image idle if someone runs it directly.
ENTRYPOINT ["/bin/sh", "-c", "echo 'plugin image — use as init-container'; sleep infinity"]
