/*
Copyright © 2022 - 2024 SUSE LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/rancher/elemental-operator/pkg/elementalcli"
	"github.com/rancher/elemental-operator/pkg/install"
	"github.com/rancher/elemental-operator/pkg/log"
	"github.com/spf13/cobra"
	"github.com/twpayne/go-vfs"
)

var (
	ErrRebooting           = errors.New("Machine needs reboot after upgrade")
	ErrAlreadyShuttingDown = errors.New("System is already shutting down")
)

func newUpgradeCommand() *cobra.Command {
	var hostDir string
	var cloudConfigPath string
	var recovery bool
	var recoveryOnly bool
	var debug bool
	var system string
	var correlationID string

	cmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrades the machine",
		RunE: func(_ *cobra.Command, _ []string) error {
			// If the system is shutting down, return an error so we can try again on next reboot.
			alreadyShuttingDown, err := isSystemShuttingDown()
			if err != nil {
				return fmt.Errorf("determining if system is running: %w", err)
			}
			if alreadyShuttingDown {
				return ErrAlreadyShuttingDown
			}

			// If system is not shutting down we can proceed.
			upgradeConfig := elementalcli.UpgradeConfig{
				Debug:        debug,
				Recovery:     recovery,
				RecoveryOnly: recoveryOnly,
				System:       system,
				Bootloader:   true,
			}
			upgradeContext := install.UpgradeContext{
				Config:          upgradeConfig,
				HostDir:         hostDir,
				CloudConfigPath: cloudConfigPath,
				CorrelationID:   correlationID,
			}

			log.Infof("Upgrade context: %+v", upgradeContext)

			installer := install.NewInstaller(vfs.OSFS, nil, nil)

			needsReboot, err := installer.UpgradeElemental(upgradeContext)
			// If the upgrade could not be applied or verified,
			// then this command will fail but the machine will not reboot.
			if err != nil {
				return fmt.Errorf("upgrading machine: %w", err)
			}
			// If the machine needs a reboot after an upgrade has been applied,
			// so that consumers can try again after reboot to validate the upgrade has been applied successfully.
			if needsReboot {
				log.Infof("Rebooting machine after %s upgrade", correlationID)
				reboot()
				return ErrRebooting
			}
			// Upgrade has been applied successfully, nothing to do.
			log.Infof("Upgrade %s applied successfully", correlationID)
			return nil
		},
	}

	cmd.Flags().StringVar(&hostDir, "host-dir", "/host", "The machine root directory where to apply the upgrade")
	cmd.Flags().StringVar(&cloudConfigPath, "cloud-config", "/run/data/cloud-config", "The path of a cloud-config file to install on the machine during upgrade")
	cmd.Flags().StringVar(&system, "system", "dir:/", "The system image uri or filesystem location to upgrade to")
	cmd.Flags().StringVar(&correlationID, "correlation-id", "", "A correlationID to label the upgrade snapshot with")
	cmd.Flags().BoolVar(&recovery, "recovery", false, "Upgrades the recovery partition together with the system")
	cmd.Flags().BoolVar(&recoveryOnly, "recovery-only", false, "Upgrades the recovery partition only")
	cmd.Flags().BoolVar(&debug, "debug", true, "Prints debug logs when performing upgrade")
	return cmd
}

func isSystemShuttingDown() (bool, error) {
	cmd := exec.Command("nsenter")
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	cmd.Args = []string{"-i", "-m", "-t", "1", "--", "systemctl is-system-running"}
	output, err := cmd.Output()
	if err != nil {
		return false, fmt.Errorf("running: systemctl is-system-running: %w", err)
	}
	if string(output) == "stopping" {
		return true, nil
	}
	return false, nil
}

func reboot() {
	cmd := exec.Command("nsenter")
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Args = []string{"-i", "-m", "-t", "1", "--", "reboot"}
	if err := cmd.Run(); err != nil {
		log.Errorf("Could not reboot: %s", err)
	}
}
