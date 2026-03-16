Fix the engine instead of dumbing down tests
Focus on the proper fix
Make architectural changes when the current system is wrong
Never hard code patterns do everything at a low AST level
Never take shortcuts
Do complex interproductual analysis thats the whole point of the project
We do extremely deep interprocedural tracing
Do proper conditional taint analysis
if we can't prove through actual data flow that taint reaches a sink, we don't report it.