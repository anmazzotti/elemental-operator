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

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Channel struct {
	DefaultName   string `json:"defaultName,omitempty"`
	BaseOS        string `json:"baseOS,omitempty"`
	BaseOSVersion string `json:"baseOSVersion,omitempty"`
	// +optional
	Flavor      string `json:"flavor,omitempty"`
	URI         string `json:"uri,omitempty"`
	Description string `json:"description,omitempty"`
}

type MetadataSpec struct {
	Annotations map[string]string `json:"annotations,omitempty"`
	AppVersion  string            `json:"appVersion,omitempty"`
	Channels    []Channel         `json:"channels,omitempty"`
}

type MetadataStatus struct{}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

type Metadata struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   MetadataSpec   `json:"spec,omitempty"`
	Status MetadataStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

type MetadataList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Metadata `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Metadata{}, &MetadataList{})
}
