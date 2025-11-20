FROM node:22-alpine

COPY ./drakrun/web/frontend /app
RUN cd /app \
    && npm install --unsafe-perm . \
    && CI=true npm run build \
    && npm cache clean --force

ENV PROXY_BACKEND_URL=http://backend.:8080
WORKDIR /app
CMD ["npm", "run", "dev"]
