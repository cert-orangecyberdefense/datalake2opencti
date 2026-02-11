# CERT Orange Cyberdefense connectors for OpenCTI

This repository is a fork of the official [OpenCTI connectors repository](https://github.com/OpenCTI-Platform/connectors).

- For general documentation about OpenCTI connectors, please refer to the official repository: https://github.com/OpenCTI-Platform/connectors.

- For specific documentation about our connectors, click on the links in the sections below.

## Connectors

We maintain code provide support for the following two connectors:
- The first one, [orange-cyberdefense-v3](https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/orange-cyberdefense-v3) (external-import), allows you to import Datalake and World Watch threat intelligence into OpenCTI.
- The second one, [orange-cyberdefense-enrichment-v3](https://github.com/OpenCTI-Platform/connectors/tree/master/internal-enrichment/orange-cyberdefense-enrichment-v3) (internal-enrichment), allows you to enrich OpenCTI observables with Datalake threat intelligence.

You may use one or both depending on your use case. Click on the links above to learn how to install it.

## How is this repository organized

- The branch `main` contains this documentation and GitHub action workflows.
- The branches `external-import-develop` and `internal-enrichment-develop` must be used for development.
- The branches `external-import-release` and `internal-enrichment-release` must be used for production-ready code. They must also be used as source branches when creating pull requests to the parent repository.

### For maintainers: How to build and deploy a beta image

_We always recommend people to use the official OpenCTI connector images, but in some cases it might be useful to build public "beta" images without waiting for the pull request to be merged on the OpenCTI side. This can be done using Github Action workflows._

1. Check that the required Github secrets and variables exists and have the right values.
2. Go to the Actions page on this GitHub repository. Click on the workflow you wish to run.
3. Please use tags such as `<current-opencti-version>-beta` when running the workflows.
4. Go to the relevant Docker Hub pages, and look for the newly created image: [datalake2opencti-external-import](https://hub.docker.com/r/ocddev/datalake2opencti-external-import) or [datalake2opencti-internal-enrichment](https://hub.docker.com/r/ocddev/datalake2opencti-internal-enrichment)