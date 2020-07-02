# образ далеам из последней версии
FROM golang:latest
# создали дерикторию для образа
#RUN mkdir /app
# переходим
WORKDIR /app
COPY . .
RUN go get github.com/githubnemo/CompileDaemon
RUN go get -v go.mongodb.org/mongo-driver/mongo@v1.0.3
RUN go get golang.org/x/crypto/bcrypt
RUN go build -o main .
ENTRYPOINT CompileDaemon --build="go build /app/main.go" --command=./main
