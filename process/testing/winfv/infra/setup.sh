kubectl create ns demo

kubectl apply -f porter.yaml
kubectl apply -f nginx.yaml
kubectl apply -f client.yaml
kubectl apply -f ingress.yaml
kubectl apply -f egress.yaml
