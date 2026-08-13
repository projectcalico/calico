# Tigera OSS-UI

## Set node version

Run `nvm use` or `nvm install`

## Install dependencies

Run `yarn`

## Start a development server

Run `yarn start`

Go to `http://localhost:3000` using chrome with disabled web security

Port forward to cluster `kubectl port-forward -n calico-system service/whisker 8081:8081`

## Build

Run `yarn build`
Run `yarn build:local` to build with a config that works locally when serving.

## Testing

Run `yarn test` or `yarn test:cov` to update coverage

## Formatting

Run `yarn format` or `yarn format:fix` to fix formatting issues

## Linting

Run `yarn lint` or `yarn lint:fix` to fix linting issues

## Pre commit

Run `yarn verify` to run all of the previous commands and avoid CI failures

Run `yarn patch` or `yarn minor`

# VS Code settings

```settings.json
{
    // Enable aliased imports with intellisense
    "typescript.preferences.importModuleSpecifier": "shortest",
}
```
