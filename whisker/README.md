# Tigera OSS-UI

## Set node version

Run `nvm use ${version in .nvmrc}`

## Install dependencies

Run `yarn`

## Start a development server

Run `yarn start`

Go to `http://localhost:3000`

## Build

Run `yarn build`

## Testing

Run `yarn test` or `yarn test:cov` to update coverage

## Formatting

Run `yarn format` or `yarn format:fix` to fix formatting issues

## Linting

Run `yarn lint` or `yarn lint:fix` to fix linting issues

# VS Code settings

```settings.json
{
    // Enable aliased imports with intellisense
    "typescript.preferences.importModuleSpecifier": "shortest",
}
```
