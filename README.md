# Kubernetes Extension API Server for Rust

## Sample Exntesion API Server

Build container image.

```sh
buildah bud --format=docker -t <Extension API Server Image Path> -f sample-api-server/Dockerfile .
```

Push container image.

```sh
podman push <Extension API Server Image Path>
```

Create namespace.

```sh
kubectl create namespace sample-system
```

Copy configmap `extension-apiserver-authentication` to target namespace.

```sh
kubectl -n kube-system get configmap extension-apiserver-authentication -o yaml | \
    sed -e 's/kube-system/sample-system/' | \
    kubectl apply -f -
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
        - name: SSL_CERT_FILE
          value: /opt/certs/client-ca-file.pem
        - name: ALLOWED_NAMES
          valueFrom:
            configMapKeyRef:
              key: requestheader-allowed-names
              name: extension-apiserver-authentication
        - name: GROUP_HEADERS
          valueFrom:
            configMapKeyRef:
              key: requestheader-group-headers
              name: extension-apiserver-authentication
        - name: USERNAME_HEADERS
          valueFrom:
            configMapKeyRef:
              key: requestheader-username-headers
              name: extension-apiserver-authentication
        ports:
        - containerPort: 3000
          protocol: TCP
        volumeMounts:
        - name: client-ca-file
          mountPath: /opt/certs
      volumes:
      - name: client-ca-file
        configMap:
          name: extension-apiserver-authentication
          items:
          - key: requestheader-client-ca-file
            path: client-ca-file.pem
            mode: 0444
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
