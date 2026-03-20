Chrome headless POC or GTFO
Research CVEs to understand what code path has the issue before adding tests
Focus on the the proper low-level AST data-flow fix with conditional taint analysis instead of just the simplest correct fix
Never take shortcuts, hard code patterns or use workarounds/hacks
Everything must be fully scope-qualified and type tracked
Never make assumptions everything is deterministic via native javascript calls or runtime variables emulation
Don't be lazy always focus on making it better regardless of complexity
Depth limits are not allowed