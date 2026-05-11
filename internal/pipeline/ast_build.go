package pipeline

import (
	"context"
	"sync"

	myast "github.com/andrewaeva/llmscan/internal/ast"
	"github.com/andrewaeva/llmscan/internal/skills"
	"github.com/andrewaeva/llmscan/internal/types"
)

// parseASTs concurrently parses files into per-language ASTs.
func (e *Engine) parseASTs(ctx context.Context, files []types.FileTarget) (map[string]*myast.FileAST, []*myast.FileAST) {
	out := make(map[string]*myast.FileAST, len(files))
	var mu sync.Mutex
	var wg sync.WaitGroup
	conc := e.Cfg.Scan.Concurrency
	if conc <= 0 {
		conc = 4
	}
	sem := make(chan struct{}, conc)
	for _, f := range files {
		if myast.Detect(f.Path) == myast.LangUnknown {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(f types.FileTarget) {
			defer wg.Done()
			defer func() { <-sem }()
			a, err := myast.Parse(ctx, f.Path, []byte(f.Content))
			if err != nil {
				e.logf("ast %s: %v", f.Path, err)
				return
			}
			mu.Lock()
			out[f.Path] = a
			mu.Unlock()
		}(f)
	}
	wg.Wait()
	list := make([]*myast.FileAST, 0, len(out))
	for _, a := range out {
		list = append(list, a)
	}
	return out, list
}

// loadSkills loads all enabled skills from configured directories.
func (e *Engine) loadSkills() map[string]*skills.Skill {
	out := map[string]*skills.Skill{}
	for _, dir := range e.Cfg.Skills.Dirs {
		s, errs := skills.LoadDir(dir)
		for _, err := range errs {
			e.logf("skill: %v", err)
		}
		for _, sk := range s {
			out[sk.Name] = sk
		}
	}
	return out
}
