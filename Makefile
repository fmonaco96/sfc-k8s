IMG ?= "fmonaco96/sfc-k8s:latest"

install:
	kubectl create -f ./operator/manifests/servicefunctionchain_crd.yaml
	kubectl create -f ./operator/manifests/servicefunctionchain_lb_crd.yaml

uninstall:
	kubectl delete -f ./operator/manifests/servicefunctionchain_crd.yaml
	kubectl delete -f ./operator/manifests/servicefunctionchain_lb_crd.yaml

docker-build-only:
	docker build -t $(IMG) .

docker-build-and-load:
	docker build -t $(IMG) .
	kind load docker-image $(IMG)

docker-image-pull:
	docker-image pull $(IMG)

docker-image-push:
	docker-image push $(IMG)

docker-image-load:
	kind load docker-image $(IMG)

deploy: docker-image-load
	kubectl create -f ./operator/manifests/rbac.yaml; kubectl create -f ./operator/manifests/daemonset.yaml

undeploy: 
	kubectl delete -f ./operator/manifests/daemonset.yaml; kubectl delete -f ./operator/manifests/rbac.yaml

example-create-sfc:
	kubectl create -f ./examples/crds/sfc/service-function-chain-sample.yaml

example-delete-sfc:
	kubectl delete -f  ./examples/crds/sfc/service-function-chain-sample.yaml