# Chart Migration

## Overview

If you are not migrating to k3s yet, you should at least migrate your charts to the latest versions in order to ensure you can apply any updates that are provided.

## Prerequisites
1. If you are running from your local machine, ensure you have helm installed.  
    - [Install Guide](https://helm.sh/docs/intro/install/)
2. If you are running directly on the microk8s control node you can use the `microk8s helm` command.

## Migration Process

### Set Values for single cluster

It is recommended that you keep your own values file to ensure pulling changes from the repo doesn't overwrite anything for future chart deployments.
**At minimum you need to create this values file for the import process**
```yaml
# ~/chutes/override-values.yaml
multiCluster: false
```

If you had previously updated the values directly in the chart directories you can either do so in the new chart directories, i.e.`charts/chutes-miner/values.yaml` and `charts/chutes-miner-gpu/values.yaml` or you can use this override values file with your custom values.

### Update K8s resources to be managed by helm

If you previously deployed using static manifests, you need to import the resources so helm can manage them.  You can use the helper script `charts/helm-import-resources.sh` or `charts/microk8s-helm-import-resources.sh` to import them.

**NOTE** For the prupose of running this script, even if you updated the default values in the charts directly create an override values file with the content from the section above since the script expects an override file.

Import resources:
```bash
cd charts
# If running on your local machine
./helm-import-resources.sh ~/path/to/override-values.yaml
# If running on the microk8s control node
./microk8s-helm-import-resources.sh ~/path/to/override-values.yaml
cd ..
```

### Update gepetto

Build Gepetto into the miner image. Migration removes the retired source
ConfigMap so stale cluster state cannot override image code.

**NOTE** Ensure you have the correct context set if you have multiple contexts in your kubeconfig.  Helm will use whatever the current context is when it runs.  Optionally you can set the context directly using the `--kube-context` flag for helm.  See `helm --help` for details.

Deploy `chutes-miner` charts for control node components
```bash
# If running from a machine that has kubectl and helm
helm upgrade --install chutes charts/chutes-miner -f ~/chutes/values.yaml --namespace chutes
# If running from microk8s control node
microk8s helm upgrade --install chutes charts/chutes-miner -f ~/chutes/values.yaml --namespace chutes
```

Deploy `chutes-miner-gpu` charts for control node components
```bash
# If running from a machine that has kubectl and helm
helm upgrade --install chutes-gpu charts/chutes-miner-gpu -f ~/chutes/values.yaml --namespace chutes
# If running from microk8s control node
microk8s helm upgrade --install chutes-gpu charts/chutes-miner-gpu -f ~/chutes/values.yaml  --namespace chutes
```