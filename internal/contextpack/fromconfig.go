package contextpack

import (
	"strings"

	"github.com/andrewaeva/llmscan/internal/config"
)

// FromConfig resolves the runtime ContextPack config from a top-level
// llmscan config. Precedence: level preset → AutoContextBudget →
// per-field overrides from cfg.Scan.Context.
func FromConfig(c config.Config) Config {
	base := presetConfig(strings.ToLower(c.Scan.Context.Level))
	if b := c.AutoContextBudget(""); b > 0 {
		base.BudgetTokens = b
	}
	cc := c.Scan.Context
	base.CalleesHops = overridePositiveInt(base.CalleesHops, cc.CalleesHops)
	base.CalleesMax = overridePositiveInt(base.CalleesMax, cc.CalleesMax)
	base.CallersHops = overridePositiveInt(base.CallersHops, cc.CallersHops)
	base.CallersMax = overridePositiveInt(base.CallersMax, cc.CallersMax)
	base.IncludeTypes = overrideOptionalBool(base.IncludeTypes, cc.IncludeTypes)
	base.TypesMax = overridePositiveInt(base.TypesMax, cc.TypesMax)
	base.IncludeSanitizers = overrideOptionalBool(base.IncludeSanitizers, cc.IncludeSanitizers)
	base.SanitizersMax = overridePositiveInt(base.SanitizersMax, cc.SanitizersMax)
	base.IncludeSiblings = overrideOptionalBool(base.IncludeSiblings, cc.IncludeSiblings)
	base.SiblingsMax = overridePositiveInt(base.SiblingsMax, cc.SiblingsMax)
	base.RAGTopK = overridePositiveInt(base.RAGTopK, cc.RAGTopK)
	base.IncludeConsts = overrideOptionalBool(base.IncludeConsts, cc.IncludeConsts)
	base.ConstsMax = overridePositiveInt(base.ConstsMax, cc.ConstsMax)
	base.SqueezeHeadLines = overridePositiveInt(base.SqueezeHeadLines, cc.SqueezeHeadLines)
	base.SqueezeTailLines = overridePositiveInt(base.SqueezeTailLines, cc.SqueezeTailLines)
	base.OverflowRatio = overridePositiveFloat(base.OverflowRatio, cc.OverflowRatio)
	return base
}

func presetConfig(level string) Config {
	switch level {
	case "minimal":
		return MinimalConfig()
	case "aggressive":
		return AggressiveConfig()
	case "extreme":
		return ExtremeConfig()
	default:
		return DefaultConfig()
	}
}

func overridePositiveInt(current, candidate int) int {
	if candidate > 0 {
		return candidate
	}
	return current
}

func overridePositiveFloat(current, candidate float64) float64 {
	if candidate > 0 {
		return candidate
	}
	return current
}

func overrideOptionalBool(current bool, candidate *bool) bool {
	if candidate != nil {
		return *candidate
	}
	return current
}
