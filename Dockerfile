FROM python:3.12
ENV APP_HOME /app
WORKDIR $APP_HOME
COPY . .
RUN pip install -r requirements.txt
EXPOSE 3000
ENTRYPOINT ["python", "main.py"]