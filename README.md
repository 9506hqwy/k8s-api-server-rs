# Kubernetes Extension API Server for Rust

## Sample Exntesion API Server

Build container image.

```sh
buildah bud -t <Extension API Server Image Path> -f sample-api-server/Dockerfile .
```

Push container image.

```sh
podman push <Extension API Server Image Path>
```

Create namespace.

```sh
kubectl create namespace sample-system
```

Deploy extension API server to target namespace.

```sh
cat | kubectl apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sample-api-server
  namespace: sample-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: sample-api-server-auth-delegator
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:auth-delegator
subjects:
- kind: ServiceAccount
  name: sample-api-server
  namespace: sample-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: sample-api-server-config-reader
  namespace: kube-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: extension-apiserver-authentication-reader
subjects:
- kind: ServiceAccount
  name: sample-api-server
  namespace: sample-system
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sample-api-server
  namespace: sample-system
spec:
  selector:
    matchLabels:
      app: sample-api-server
  template:
    metadata:
      labels:
        app: sample-api-server
    spec:
      serviceAccountName: sample-api-server
      containers:
      - name: sample-api-server
        image: <Extension API Server Image Path>
        env:
        - name: RUST_LOG
          value: info
        ports:
        - containerPort: 3000
          protocol: TCP
---
apiVersion: v1
kind: Service
metadata:
  labels:
    component: apiserver
    provider: sample-api-server
  name: sample-api-server
  namespace: sample-system
spec:
  ports:
  - name: https
    port: 3000
    protocol: TCP
  selector:
    app: sample-api-server
  type: ClusterIP
---
apiVersion: apiregistration.k8s.io/v1
kind: APIService
metadata:
  name: v1alpha1.sample-api-server
spec:
  groupPriorityMinimum: 3000
  versionPriority: 10
  group: sample-api-server
  insecureSkipTLSVerify: true
  service:
    name: sample-api-server
    namespace: sample-system
    port: 3000
  version: v1alpha1
EOF
```
