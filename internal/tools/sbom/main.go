// Command sbom writes an SPDX 2.3 JSON document for a Go binary.
// It reads the module list that the Go linker embeds in the binary.
//
// Usage: go run ./internal/tools/sbom [-version v1.2.3] BINARY > BINARY.spdx.json
package main

import (
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"
)

type checksum struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"checksumValue"`
}

type extRef struct {
	Category string `json:"referenceCategory"`
	Type     string `json:"referenceType"`
	Locator  string `json:"referenceLocator"`
}

type pkg struct {
	Name             string     `json:"name"`
	ID               string     `json:"SPDXID"`
	Version          string     `json:"versionInfo,omitempty"`
	Download         string     `json:"downloadLocation"`
	FilesAnalyzed    bool       `json:"filesAnalyzed"`
	Checksums        []checksum `json:"checksums,omitempty"`
	LicenseConcluded string     `json:"licenseConcluded"`
	LicenseDeclared  string     `json:"licenseDeclared"`
	Copyright        string     `json:"copyrightText"`
	ExternalRefs     []extRef   `json:"externalRefs,omitempty"`
}

type relationship struct {
	Element string `json:"spdxElementId"`
	Type    string `json:"relationshipType"`
	Related string `json:"relatedSpdxElement"`
}

type creationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type document struct {
	SPDXVersion   string         `json:"spdxVersion"`
	DataLicense   string         `json:"dataLicense"`
	ID            string         `json:"SPDXID"`
	Name          string         `json:"name"`
	Namespace     string         `json:"documentNamespace"`
	CreationInfo  creationInfo   `json:"creationInfo"`
	Packages      []pkg          `json:"packages"`
	Relationships []relationship `json:"relationships"`
}

const noAssertion = "NOASSERTION"

// build maps Go build info to an SPDX document. sum is the SHA-256 of the binary.
func build(bi *debug.BuildInfo, binName, version, sum string, created time.Time) document {
	main := mkPkg(bi.Path, version, "SPDXRef-Package-main")
	main.Checksums = []checksum{{Algorithm: "SHA256", Value: sum}}
	main.Name = binName
	doc := document{
		SPDXVersion: "SPDX-2.3",
		DataLicense: "CC0-1.0",
		ID:          "SPDXRef-DOCUMENT",
		Name:        binName,
		Namespace:   "https://spdx.org/spdxdocs/" + binName + "-" + sum,
		CreationInfo: creationInfo{
			Created:  created.UTC().Format("2006-01-02T15:04:05Z"),
			Creators: []string{"Tool: tripline-sbom"},
		},
		Packages:      []pkg{main},
		Relationships: []relationship{{"SPDXRef-DOCUMENT", "DESCRIBES", main.ID}},
	}
	for i, d := range bi.Deps {
		if d.Replace != nil {
			d = d.Replace
		}
		p := mkPkg(d.Path, d.Version, fmt.Sprintf("SPDXRef-Package-dep-%d", i))
		doc.Packages = append(doc.Packages, p)
		doc.Relationships = append(doc.Relationships, relationship{main.ID, "DEPENDS_ON", p.ID})
	}
	return doc
}

func mkPkg(path, version, id string) pkg {
	if version == "(devel)" {
		version = ""
	}
	p := pkg{
		Name:             path,
		ID:               id,
		Version:          version,
		Download:         noAssertion,
		LicenseConcluded: noAssertion,
		LicenseDeclared:  noAssertion,
		Copyright:        noAssertion,
	}
	purl := "pkg:golang/" + path
	if version != "" {
		purl += "@" + version
	}
	p.ExternalRefs = []extRef{{"PACKAGE-MANAGER", "purl", purl}}
	return p
}

func main() {
	version := flag.String("version", "", "version of the main package")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: sbom [-version v] BINARY")
		os.Exit(2)
	}
	if err := run(flag.Arg(0), *version); err != nil {
		fmt.Fprintln(os.Stderr, "sbom:", err)
		os.Exit(1)
	}
}

func run(path, version string) error {
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	h := sha256.Sum256(data)
	name := strings.TrimSuffix(filepath.Base(path), ".exe")
	doc := build(bi, name, version, hex.EncodeToString(h[:]), time.Now())
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
