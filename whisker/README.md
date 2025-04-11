# Tigera OSS-UI

## Set node version

Run `nvm use ${version in .nvmrc}`

## Install dependencies

Run `yarn`

## Start a development server

Run `yarn start`

Go to `http://localhost:3000` using chrome with disabled web security

To proxy to cluster backend run `kubectl -n calico-system port-forward pod/$(kubectl get pods -l k8s-app=whisker -n calico-system -o jsonpath='{.items[0].metadata.name}') 3002:3002`

## Build

Run `yarn build`

## Testing

Run `yarn test` or `yarn test:cov` to update coverage

## Formatting

Run `yarn format` or `yarn format:fix` to fix formatting issues

## Linting

Run `yarn lint` or `yarn lint:fix` to fix linting issues

## Pre commit

Run `yarn verify` to run all of the previous commands and avoid CI failures

# VS Code settings

```settings.json
{
    // Enable aliased imports with intellisense
    "typescript.preferences.importModuleSpecifier": "shortest",
}
```
