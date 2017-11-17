dep ensure
protoc -I ./protos/mgmtintf_v1 mgmtintf.proto --go_out=plugins=grpc:protos/mgmtintf_v1
go build flexvoldriver.go
