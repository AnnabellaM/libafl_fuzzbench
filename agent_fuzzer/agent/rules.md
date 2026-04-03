| Rule | Criterion |                                                                                    
|------|-----------|                                                                                    
| **NEG-1** | Blocked block body contains only a `return` statement |                                   
| **NEG-2** | Blocked block body contains only an error handler (`opt_error`, `fprintf`+`exit`, `abort`, `assert`, etc.)|                                                                                      
| **NEG-3** | Blocked block body contains only cleanup (`free`, `close`, `destroy`, etc.)
| **NEG-4** | Branch or context is annotated `deprecated`, `legacy`, or `obsolete` |   