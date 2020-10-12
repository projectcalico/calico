# Generating API reference docs

The api.html doc in this directory is generated using https://github.com/tmjd/gen-crd-api-reference-docs/tree/kb_v2.

To generate a new file, you must follow the instructions in that repository to clone the project.

Then, run the following.

1. Import the desired version of the tigera/operator.

   ```
   go mod edit -replace github.com/tigera/operator=github.com/tigera/operator@<version>
   go mod download
   ```

1. Build the binary

   ```
   go build
   ```

1. Run it, passing the location of the APIs

   ```
   ./gen-crd-api-reference-docs -config ./example-config.json -api-dir github.com/tigera/operator/api -out-file api.html
   ```

Then, there are a few bits of cleanup you'll need to do

1. Copy the generated `api.html` into this directory, renaming it to `_api.html`.
