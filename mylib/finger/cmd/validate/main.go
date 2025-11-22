package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/invopop/jsonschema"
	"github.com/killmonday/fscanx/mylib/finger/alias"
	"github.com/killmonday/fscanx/mylib/finger/fingers"
	"gopkg.in/yaml.v3"
)

func main() {
	var (
		engine = flag.String("engine", "fingers", "Engine type to validate (fingers, alias)")
		schema = flag.Bool("schema", false, "Output JSON schema for the specified engine")
		help   = flag.Bool("help", false, "Show help information")
	)

	flag.Parse()

	if *help {
		showHelp()
		return
	}

	// Handle schema output
	if *schema {
		if err := outputSchemaForEngine(*engine); err != nil {
			fmt.Printf("Error generating schema: %s\n", err.Error())
			os.Exit(1)
		}
		return
	}

	if len(flag.Args()) == 0 {
		showHelp()
		return
	}

	target := flag.Args()[0]

	// Validate files
	err := filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Check for supported file extensions
		ext := filepath.Ext(path)
		if ext != ".yaml" && ext != ".yml" && ext != ".json" {
			return nil
		}

		fmt.Printf("Validating: %s\n", path)

		// Read file content
		content, err := ioutil.ReadFile(path)
		if err != nil {
			fmt.Printf("❌ %s - Failed to read file: %s\n", path, err.Error())
			return nil
		}

		// Convert to JSON for validation
		var data interface{}
		if ext == ".json" {
			err = json.Unmarshal(content, &data)
		} else {
			err = yaml.Unmarshal(content, &data)
		}

		if err != nil {
			fmt.Printf("❌ %s - Failed to parse file: %s\n", path, err.Error())
			return nil
		}

		// Convert to JSON bytes for schema validation
		jsonData, err := json.Marshal(data)
		if err != nil {
			fmt.Printf("❌ %s - Failed to convert to JSON: %s\n", path, err.Error())
			return nil
		}

		// Validate against schema based on engine type
		var validCount, totalCount int
		var results []ValidationResult

		switch *engine {
		case "fingers":
			validCount, totalCount, results = validateFingersSchema(jsonData)
		case "alias":
			validCount, totalCount, results = validateAliasSchema(jsonData)
		default:
			fmt.Printf("❌ Unsupported engine type: %s\n", *engine)
			return nil
		}

		// Print detailed results
		fmt.Printf("📁 %s (%d items)\n", path, totalCount)

		for _, result := range results {
			if result.Valid {
				fmt.Printf("  ✅ %s - Valid\n", result.Name)
			} else {
				fmt.Printf("  ❌ %s - %s\n", result.Name, result.Error)
			}
		}

		// Print summary
		if validCount == totalCount && totalCount > 0 {
			fmt.Printf("  📊 Summary: All %d items valid\n\n", totalCount)
		} else if validCount > 0 {
			fmt.Printf("  📊 Summary: %d/%d items valid\n\n", validCount, totalCount)
		} else {
			fmt.Printf("  📊 Summary: No valid items\n\n")
		}
		return nil
	})

	if err != nil {
		fmt.Printf("Error during validation: %s\n", err.Error())
		os.Exit(1)
	}
}

func showHelp() {
	fmt.Println("Fingers Fingerprint Library Validator")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  validate <path_or_file> [options]")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -engine string")
	fmt.Println("        Engine type to validate (fingers, alias) (default \"fingers\")")
	fmt.Println("  -schema")
	fmt.Println("        Output JSON schema for the specified engine")
	fmt.Println("  -help")
	fmt.Println("        Show this help information")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  # Validate fingers fingerprint files")
	fmt.Println("  validate fingerprints/ -engine fingers")
	fmt.Println()
	fmt.Println("  # Validate alias files")
	fmt.Println("  validate aliases/ -engine alias")
	fmt.Println()
	fmt.Println("  # Output JSON schema for fingers")
	fmt.Println("  validate -schema -engine fingers")
	fmt.Println()
	fmt.Println("  # Output JSON schema for alias")
	fmt.Println("  validate -schema -engine alias")
}

type ValidationResult struct {
	Name  string
	Valid bool
	Error string
}

// Validate fingers fingerprints
func validateFingersSchema(jsonData []byte) (validCount, totalCount int, results []ValidationResult) {
	// First try as single fingerprint
	var singleFinger fingers.Finger
	if err := json.Unmarshal(jsonData, &singleFinger); err == nil {
		// Single fingerprint case
		totalCount = 1
		result := ValidationResult{
			Name:  singleFinger.Name,
			Valid: true,
		}

		if singleFinger.Name == "" {
			result.Name = "<unnamed>"
			result.Valid = false
			result.Error = "name is required"
		} else if len(singleFinger.Rules) == 0 {
			result.Valid = false
			result.Error = "must have at least one rule"
		}

		if result.Valid {
			validCount = 1
		}
		results = append(results, result)
		return
	}

	// Try as array of fingerprints
	var fingerArray []fingers.Finger
	if err := json.Unmarshal(jsonData, &fingerArray); err == nil {
		// Array of fingerprints case
		totalCount = len(fingerArray)
		for i, finger := range fingerArray {
			result := ValidationResult{
				Name:  finger.Name,
				Valid: true,
			}

			if finger.Name == "" {
				result.Name = fmt.Sprintf("<unnamed-%d>", i)
				result.Valid = false
				result.Error = "name is required"
			} else if len(finger.Rules) == 0 {
				result.Valid = false
				result.Error = "must have at least one rule"
			}

			if result.Valid {
				validCount++
			}
			results = append(results, result)
		}
		return
	}

	// If neither single nor array format works
	results = append(results, ValidationResult{
		Name:  "<invalid>",
		Valid: false,
		Error: "data doesn't match fingers fingerprint format",
	})
	totalCount = 1
	return
}

// Validate alias entries
func validateAliasSchema(jsonData []byte) (validCount, totalCount int, results []ValidationResult) {
	// First try as single alias
	var singleAlias alias.Alias
	if err := json.Unmarshal(jsonData, &singleAlias); err == nil {
		// Single alias case
		totalCount = 1
		result := ValidationResult{
			Name:  singleAlias.Name,
			Valid: true,
		}

		if singleAlias.Name == "" {
			result.Name = "<unnamed>"
			result.Valid = false
			result.Error = "name is required"
		} else if len(singleAlias.AliasMap) == 0 {
			result.Valid = false
			result.Error = "must have at least one alias mapping"
		} else if singleAlias.Priority < 0 || singleAlias.Priority > 5 {
			result.Valid = false
			result.Error = "priority must be between 0 and 5"
		}

		if result.Valid {
			validCount = 1
		}
		results = append(results, result)
		return
	}

	// Try as array of aliases
	var aliasArray []alias.Alias
	if err := json.Unmarshal(jsonData, &aliasArray); err == nil {
		// Array of aliases case
		totalCount = len(aliasArray)
		for i, a := range aliasArray {
			result := ValidationResult{
				Name:  a.Name,
				Valid: true,
			}

			if a.Name == "" {
				result.Name = fmt.Sprintf("<unnamed-%d>", i)
				result.Valid = false
				result.Error = "name is required"
			} else if len(a.AliasMap) == 0 {
				result.Valid = false
				result.Error = "must have at least one alias mapping"
			} else if a.Priority < 0 || a.Priority > 5 {
				result.Valid = false
				result.Error = "priority must be between 0 and 5"
			}

			if result.Valid {
				validCount++
			}
			results = append(results, result)
		}
		return
	}

	// If neither single nor array format works
	results = append(results, ValidationResult{
		Name:  "<invalid>",
		Valid: false,
		Error: "data doesn't match alias format",
	})
	totalCount = 1
	return
}

func outputSchemaForEngine(engineType string) error {
	reflector := jsonschema.Reflector{
		AllowAdditionalProperties: false,
		DoNotReference:            true,
	}

	var schema *jsonschema.Schema

	switch engineType {
	case "fingers":
		schema = reflector.Reflect(&fingers.Finger{})
		schema.Title = "Fingers Fingerprint Schema"
		schema.Description = "JSON Schema for validating Fingers fingerprint library format"

		// Add examples
		schema.Examples = []interface{}{
			map[string]interface{}{
				"name":         "nginx",
				"vendor":       "nginx",
				"product":      "nginx",
				"protocol":     "http",
				"link":         "https://nginx.org",
				"default_port": []string{"80", "443"},
				"focus":        false,
				"rule": []map[string]interface{}{
					{
						"regexps": map[string]interface{}{
							"header": []string{"Server: nginx"},
							"regexp": []string{"nginx/([\\d\\.]+)"},
						},
						"version": "\\1",
						"level":   0,
					},
				},
				"tag":   []string{"web", "server"},
				"opsec": false,
			},
		}

	case "alias":
		schema = reflector.Reflect(&alias.Alias{})
		schema.Title = "Alias Schema"
		schema.Description = "JSON Schema for validating alias mapping format"

		// Add examples
		schema.Examples = []interface{}{
			map[string]interface{}{
				"name":     "nginx",
				"vendor":   "nginx",
				"product":  "nginx",
				"label":    "web,server,proxy",
				"priority": 1,
				"target":   []string{"https://nginx.org", "192.168.1.100:80"},
				"alias": map[string]interface{}{
					"wappalyzer": []string{"Nginx"},
					"ehole":      []string{"nginx"},
					"fingers":    []string{"nginx"},
				},
				"block": []string{},
			},
		}

	default:
		return fmt.Errorf("unsupported engine type: %s", engineType)
	}

	schemaJSON, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return err
	}

	fmt.Println(string(schemaJSON))
	return nil
}
