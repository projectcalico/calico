# Generating API reference docs

The api.html doc in this directory is generated using https://github.com/caseydavenport/gen-crd-api-reference-docs.

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
   ./gen-crd-api-reference-docs -config ./example-config.json -api-dir github.com/tigera/operator/pkg/apis/operator/v1 -out-file api.html
   ```

Then, there are a few bits of cleanup you'll need to do

1. Copy the generated `api.html` into this directory.

1. Add the layout section and introduction text to the top of the document so it renders properly in our docs.
