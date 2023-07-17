#!/bin/sh

go install go.uber.org/mock/mockgen@latest

# Always create mock files into a "mocks" subfolder to be ignored in test coverage.
# See codecov.yml for more info 

mockgen -destination=pkg/register/mocks/client.go -package=mocks github.com/rancher/elemental-operator/pkg/register Client
mockgen -destination=pkg/install/mocks/installer.go -package=mocks github.com/rancher/elemental-operator/pkg/install Installer
