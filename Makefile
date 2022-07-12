install:
	kubectl create -f ./operator/manifests/servicefunctionchain_crd.yaml
	kubectl create -f ./operator/manifests/servicefunctionchain_lb_crd.yaml

uninstall:
	kubectl delete -f ./operator/manifests/servicefunctionchain_crd.yaml
	kubectl delete -f ./operator/manifests/servicefunctionchain_lb_crd.yaml

docker-build-only:
	docker build -t fmonaco96/sfc-k8s:latest .

docker-build-and-load:
	docker build -t fmonaco96/sfc-k8s:latest .
	kind load docker-image fmonaco96/sfc-k8s:latest

deploy: docker-build-and-load
	kubectl create -f ./operator/manifests/rbac.yaml; kubectl create -f ./operator/manifests/daemonset.yaml

undeploy: 
	kubectl delete -f ./operator/manifests/daemonset.yaml; kubectl delete -f ./operator/manifests/rbac.yaml