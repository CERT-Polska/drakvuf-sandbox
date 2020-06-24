# Build frontend
FROM node:14-buster as frontend

COPY drakcore/frontend /app
WORKDIR /app

RUN npm install --no-save
RUN npm run build


FROM python:3.8

COPY . /app
COPY --from=frontend /app/build /app/drakcore/frontend/
WORKDIR /app

RUN pip install .

CMD uwsgi --http 0.0.0.0:6300 --module drakcore.app:app --processes 4
