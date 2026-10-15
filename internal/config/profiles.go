package config

import "fmt"

// ApplyProfile changes recon budgets only. Ports and Nuclei always require opt in.
func ApplyProfile(c *Config, name string) error {
	switch name {
	case "standard", "custom":
		return nil
	case "quick":
		for _, tool := range []string{"amass", "gospider", "hakrawler", "paramspider"} {
			v := c.Tools[tool]
			v.Enabled = false
			c.Tools[tool] = v
		}
		for name, v := range c.Tools {
			if v.Timeout > 180 {
				v.Timeout = 180
			}
			v.TotalTimeout = 300
			c.Tools[name] = v
		}
	case "deep":
		for name, v := range c.Tools {
			v.TotalTimeout = 3600
			c.Tools[name] = v
		}
	default:
		return fmt.Errorf("unknown profile %q; use quick, standard, deep or custom", name)
	}
	return nil
}
