package visual

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v2"
)

func PrettyJSON(data map[string]interface{}) error {
	// Marshal the data to JSON with indentation
	prettyJSON, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		return err
	}

	// Construct the top and bottom lines
	lineLength := len(string(prettyJSON)) + 4
	topLine := fmt.Sprintf("|%s|", strings.Repeat("=", lineLength-2))
	bottomLine := fmt.Sprintf("|%s|", strings.Repeat("=", lineLength-2))

	// Print the output with the top and bottom lines
	fmt.Println(topLine)
	fmt.Println("|    JSON Output:    |")
	fmt.Println(bottomLine)
	fmt.Println(string(prettyJSON))
	fmt.Println(bottomLine)

	return nil
}

func PrettyYAML(data map[string]interface{}) error {
	prettyYaml, err := yaml.Marshal(data)
	if err != nil {
		return err
	}

	// Construct the top and bottom lines
	lineLength := len(string(prettyYaml)) + 4
	topLine := fmt.Sprintf("|%s|", strings.Repeat("=", lineLength-2))
	bottomLine := fmt.Sprintf("|%s|", strings.Repeat("=", lineLength-2))

	fmt.Println(topLine)
	fmt.Println("|    YAML Output:    |")
	fmt.Println(bottomLine)
	fmt.Println(string(prettyYaml))
	fmt.Println(bottomLine)

	return nil
}
