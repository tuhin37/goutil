package main

import "github.com/tuhin37/goutil/visual"

func main() {
	data := map[string]interface{}{
		"key1": "value1",
		"key2": 2,
		"key3": []string{"item1", "item2", "item3"},
	}

	visual.PrettyJSON(data)
	visual.PrettyYAML(data)
}
