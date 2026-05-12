package contextpack

import (
	"strings"

	"github.com/andrewaeva/llmscan/internal/config"
)

// FromConfig resolves the runtime ContextPack config from a top-level
// llmscan config. Precedence: level preset → AutoContextBudget →
// per-field overrides from cfg.Scan.Context.
func FromConfig(c config.Config) Config {
	var base Config
	switch strings.ToLower(c.Scan.Context.Level) {
	case "minimal":
		base = MinimalConfig()
	case "aggressive":
		base = AggressiveConfig()
	case "extreme":
		base = ExtremeConfig()
	default:
		base = DefaultConfig()
	}
	if b := c.AutoContextBudget(""); b > 0 {
		base.BudgetTokens = b
	}
	cc := c.Scan.Context
	if cc.CalleesHops > 0 {
		base.CalleesHops = cc.CalleesHops
	}
	if cc.CalleesMax > 0 {
		base.CalleesMax = cc.CalleesMax
	}
	if cc.CallersHops > 0 {
		base.CallersHops = cc.CallersHops
	}
	if cc.CallersMax > 0 {
		base.CallersMax = cc.CallersMax
	}
	if cc.IncludeTypes != nil {
		base.IncludeTypes = *cc.IncludeTypes
	}
	if cc.TypesMax > 0 {
		base.TypesMax = cc.TypesMax
	}
	if cc.IncludeSanitizers != nil {
		base.IncludeSanitizers = *cc.IncludeSanitizers
	}
	if cc.SanitizersMax > 0 {
		base.SanitizersMax = cc.SanitizersMax
	}
	if cc.IncludeSiblings != nil {
		base.IncludeSiblings = *cc.IncludeSiblings
	}
	if cc.SiblingsMax > 0 {
		base.SiblingsMax = cc.SiblingsMax
	}
	if cc.RAGTopK > 0 {
		base.RAGTopK = cc.RAGTopK
	}
	if cc.IncludeConsts != nil {
		base.IncludeConsts = *cc.IncludeConsts
	}
	if cc.ConstsMax > 0 {
		base.ConstsMax = cc.ConstsMax
	}
	if cc.SqueezeHeadLines > 0 {
		base.SqueezeHeadLines = cc.SqueezeHeadLines
	}
	if cc.SqueezeTailLines > 0 {
		base.SqueezeTailLines = cc.SqueezeTailLines
	}
	if cc.OverflowRatio > 0 {
		base.OverflowRatio = cc.OverflowRatio
	}
	return base
}
