dep ensure
protoc -I ./udsver_v1 udsver.proto --go_out=plugins=grpc:udsver_v1
go build nodeagent.go
if [ -e nodeagent ]; then
  mkdir ./bin
  mv nodeagent ./bin
fi
