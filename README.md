# k6u
k6u (k**8s IPv6**Updater) is a Kubernetes operator for assisting with
`CiliumNetworkPolicy` management when using dual-stack networking under the
mercy of an internet service provider who refuses to give you a static IPv6
prefix.

# How?
Deploy the operator to your cluster as a DaemonSet:
```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  labels:
    app.kubernetes.io/name: k6u
  name: k6u
  namespace: kube-system
spec:
  revisionHistoryLimit: 10
  selector:
    matchLabels:
      app.kubernetes.io/name: k6u
  template:
    metadata:
      labels:
        app.kubernetes.io/name: k6u
    spec:
      containers:
      - env:
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              apiVersion: v1
              fieldPath: spec.nodeName
        - name: POD_NAMESPACE
          valueFrom:
            fieldRef:
              apiVersion: v1
              fieldPath: metadata.namespace
        - name: POD_NAME
          valueFrom:
            fieldRef:
              apiVersion: v1
              fieldPath: metadata.name
        - name: RUST_LOG
          value: info
        - name: UPDATE_INTERVAL
          value: "10"
        image: registry.fuwafuwatime.moe/concord/k6u:latest
        imagePullPolicy: Always
        name: k6u
        resources:
          limits:
            cpu: 8m
            memory: 16Mi
          requests:
            cpu: 4m
            memory: 8Mi
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop:
            - ALL
          readOnlyRootFilesystem: true
          runAsGroup: 1000
          runAsNonRoot: true
          runAsUser: 1000
          seccompProfile:
            type: RuntimeDefault
      dnsPolicy: ClusterFirst
      hostNetwork: true
      restartPolicy: Always
      schedulerName: default-scheduler
      securityContext: {}
      serviceAccount: k6u
      serviceAccountName: k6u
      terminationGracePeriodSeconds: 30
  updateStrategy:
    rollingUpdate:
      maxSurge: 0
      maxUnavailable: 1
    type: RollingUpdate
```

When it starts, it will automatically deploy the CRDs. Then, create a
corresponding `IP6UpdateConfig`:

```yaml
apiVersion: apps.fuwafuwatime.moe/v1
kind: IP6UpdateConfig
metadata:
  name: ip6-update-config
spec:
  delegatedPrefixLength: 60
  ciliumCIDRGroups:
  - ciliumCIDRGroupName: ip6-local-lan
    prefixIds:
    - 0
    - 1
    - 2
```

Set your `spec.delegatedPrefixLength` to the size of your delegated prefix.
Then, add a mapping to your `spec.ciliumCIDRGroups` with a `ciliumCIDRGroupName`
that matches the name of a `CiliumCIDRGroup` you'd like to update, and
`prefixIds` to the prefix IDs you'd like to add to that CIDR group. Note that
the entire `CiliumCIDRGroup`'s `externalCIDRs` will be overwritten.

Finally, for each node in your cluster where the DaemonSet runs, create a
corresponding `IP6UpdateNodeConfig`:

```yaml
apiVersion: apps.fuwafuwatime.moe/v1
kind: IP6UpdateNodeConfig
metadata:
  name: ip6-update-node1
spec:
  nodeSelector:
    kubernetes.io/hostname: node1.example.com
  interface: eth0
```

Set the `spec.nodeSelector` to match the node this applies to, and set the
`spec.interface` to match the name of a network interface to monitor for the
IPv6 prefix.

After that, you should see your `CiliumCIDRGroup` update automatically.

# License

See [LICENSE.md](LICENSE.md).
