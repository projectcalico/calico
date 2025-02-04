# Script Name: build_and_test.sh
# Description: This script automates the process of cleaning, building resources required for running functional tests for the Calico Felix project.
# It ensures that all commands are executed from the correct directory relative to the script's location.
#
# Steps:
# 1. Navigate to the directory where the script is located.
# 2. Move one level up to the project root.
# 3. Run `make clean` to remove any previous build artifacts.
# 4. Navigate to the `felix` directory.
# 5. Run `make build` to compile the project.
# 6. Execute functional tests with `make fv` with `--dry-run` flag.
#
# Usage:
# Run this script from any location, and it will automatically adjust the working directory.
cd "$(dirname "$0")"
cd ..
make clean
cd felix
make build
make fv GINKGO_FOCUS="EMPTY"