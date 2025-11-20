FROM python:3.12

COPY ./drakrun /app/drakrun
COPY ./setup.py ./requirements.txt ./pyproject.toml ./MANIFEST.in /app/

WORKDIR /app/
RUN pip install .
CMD ["flask", "--app", "drakrun.web.app:app", "run", "--with-threads", "--host", "0.0.0.0", "--port", "8080"]
