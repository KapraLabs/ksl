
error[E0277]: `?` couldn't convert the error to `ksl_errors::KslError`
   --> src\ksl_dep_audit.rs:442:31
    |
442 |     resolver.resolve(&package)?;
    |              -----------------^ the trait `std::convert::From<std::string::String>` is not implemented for `ksl_errors::KslError`
    |              |
    |              this can't be annotated with `?` because it has type `Result<_, std::string::String>`
    |
    = note: the question mark operation (`?`) implicitly performs a conversion on the error value using the `From` trait
    = help: the trait `std::ops::FromResidual<std::result::Result<std::convert::Infallible, E>>` is implemented for `std::result::Result<T, F>`
    = note: required for `std::result::Result<std::string::String, ksl_errors::KslError>` to implement `std::ops::FromResidual<std::result::Result<std::convert::Infallible, std::string::String>>`

error[E0034]: multiple applicable items in scope
   --> src\ksl_runtime_monitor.rs:246:31
    |
246 |         let mut vm = KapraVM::new();
    |                               ^^^ multiple `new` found
    |
note: candidate #1 is defined in an impl for the type `kapra_vm::KapraVM`
   --> src\kapra_vm.rs:199:5
    |
199 |     pub fn new(bytecode: KapraBytecode, runtime: Option<Arc<AsyncRuntime>>, gas_limit: Option<u64>) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
note: candidate #2 is defined in an impl for the type `kapra_vm::KapraVM`
   --> src\ksl_kapra_validator.rs:163:5
    |
163 | /     pub fn new(
164 | |         is_embedded: bool,
165 | |         consensus_runtime: Arc<ConsensusRuntime>,
166 | |         async_runtime: Arc<AsyncRuntime>,
167 | |         contract_compiler: Arc<ContractCompiler>,
168 | |     ) -> Self {
    | |_____________^

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_runtime_monitor.rs:283:25
    |
283 |           _ => return Err(KslError::type_error(
    |  _________________________^^^^^^^^^^^^^^^^^^^^-
284 | |             format!("Unknown project type for file: {}", file),
285 | |             pos,
286 | |         )),
    | |_________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
283 -         _ => return Err(KslError::type_error(
284 -             format!("Unknown project type for file: {}", file),
285 -             pos,
286 -         )),
283 +         _ => return Err(KslError::type_error(format!("Unknown project type for file: {}", file), pos, /* std::string::String */)),
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_migrate.rs:75:26
    |
75  |               .map_err(|e| KslError::type_error(
    |  __________________________^^^^^^^^^^^^^^^^^^^^-
76  | |                 format!("Failed to read file {}: {}", self.config.input_file.display(), e),
77  | |                 pos,
78  | |             ))?;
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
75  -             .map_err(|e| KslError::type_error(
76  -                 format!("Failed to read file {}: {}", self.config.input_file.display(), e),
77  -                 pos,
78  -             ))?;
75  +             .map_err(|e| KslError::type_error(format!("Failed to read file {}: {}", self.config.input_file.display(), e), pos, /* std::string::String */))?;
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_migrate.rs:81:26
    |
81  |               .map_err(|e| KslError::type_error(
    |  __________________________^^^^^^^^^^^^^^^^^^^^-
82  | |                 format!("Parse error at position {}: {}", e.position, e.message),
83  | |                 pos,
84  | |             ))?;
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
81  -             .map_err(|e| KslError::type_error(
82  -                 format!("Parse error at position {}: {}", e.position, e.message),
83  -                 pos,
84  -             ))?;
81  +             .map_err(|e| KslError::type_error(format!("Parse error at position {}: {}", e.position, e.message), pos, /* std::string::String */))?;
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_migrate.rs:91:29
    |
91  |               _ => return Err(KslError::type_error(
    |  _____________________________^^^^^^^^^^^^^^^^^^^^-
92  | |                 format!("Unsupported target version: {}", self.config.target_version),
93  | |                 pos,
94  | |             )),
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
91  -             _ => return Err(KslError::type_error(
92  -                 format!("Unsupported target version: {}", self.config.target_version),
93  -                 pos,
94  -             )),
91  +             _ => return Err(KslError::type_error(format!("Unsupported target version: {}", self.config.target_version), pos, /* std::string::String */)),
    |

error[E0308]: mismatched types
   --> src\ksl_migrate.rs:98:15
    |
98  |         check(&ast)
    |         ----- ^^^^ expected `&[AstNode]`, found `&Vec<AstNode>`
    |         |
    |         arguments to this function are incorrect
    |
    = note: expected reference `&[ksl_ast::AstNode]`
               found reference `&std::vec::Vec<ksl_macros::AstNode>`
note: function defined here
   --> src\ksl_checker.rs:651:8
    |
651 | pub fn check(nodes: &[AstNode]) -> Result<(), Vec<TypeError>> {
    |        ^^^^^ -----------------

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_migrate.rs:99:31
    |
99  |               .map_err(|errors| KslError::type_error(
    |  _______________________________^^^^^^^^^^^^^^^^^^^^-
100 | |                 errors.into_iter()
101 | |                     .map(|e| format!("Type error at position {}: {}", e.position, e.message))
102 | |                     .collect::<Vec<_>>()
103 | |                     .join("\n"),
104 | |                 pos,
105 | |             ))?;
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
99  ~             .map_err(|errors| KslError::type_error(errors.into_iter()
100 +                     .map(|e| format!("Type error at position {}: {}", e.position, e.message))
101 +                     .collect::<Vec<_>>()
102 ~                     .join("\n"), pos, /* std::string::String */))?;
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_migrate.rs:113:26
    |
113 |               .map_err(|e| KslError::type_error(
    |  __________________________^^^^^^^^^^^^^^^^^^^^-
114 | |                 format!("Failed to create output file {}: {}", output_path.display(), e),
115 | |                 pos,
116 | |             ))?
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
113 -             .map_err(|e| KslError::type_error(
114 -                 format!("Failed to create output file {}: {}", output_path.display(), e),
115 -                 pos,
116 -             ))?
113 +             .map_err(|e| KslError::type_error(format!("Failed to create output file {}: {}", output_path.display(), e), pos, /* std::string::String */))?
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_migrate.rs:118:26
    |
118 |               .map_err(|e| KslError::type_error(
    |  __________________________^^^^^^^^^^^^^^^^^^^^-
119 | |                 format!("Failed to write output file {}: {}", output_path.display(), e),
120 | |                 pos,
121 | |             ))?;
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
118 -             .map_err(|e| KslError::type_error(
119 -                 format!("Failed to write output file {}: {}", output_path.display(), e),
120 -                 pos,
121 -             ))?;
118 +             .map_err(|e| KslError::type_error(format!("Failed to write output file {}: {}", output_path.display(), e), pos, /* std::string::String */))?;
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_migrate.rs:127:30
    |
127 |                   .map_err(|e| KslError::type_error(
    |  ______________________________^^^^^^^^^^^^^^^^^^^^-
128 | |                     format!("Failed to create report file {}: {}", report_path.display(), e),
129 | |                     pos,
130 | |                 ))?
    | |_________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
127 -                 .map_err(|e| KslError::type_error(
128 -                     format!("Failed to create report file {}: {}", report_path.display(), e),
129 -                     pos,
130 -                 ))?
127 +                 .map_err(|e| KslError::type_error(format!("Failed to create report file {}: {}", report_path.display(), e), pos, /* std::string::String */))?
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_migrate.rs:132:30
    |
132 |                   .map_err(|e| KslError::type_error(
    |  ______________________________^^^^^^^^^^^^^^^^^^^^-
133 | |                     format!("Failed to write report file {}: {}", report_path.display(), e),
134 | |                     pos,
135 | |                 ))?;
    | |_________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
132 -                 .map_err(|e| KslError::type_error(
133 -                     format!("Failed to write report file {}: {}", report_path.display(), e),
134 -                     pos,
135 -                 ))?;
132 +                 .map_err(|e| KslError::type_error(format!("Failed to write report file {}: {}", report_path.display(), e), pos, /* std::string::String */))?;
    |

error[E0599]: the method `clone` exists for struct `Vec<MigrationChange>`, but its trait bounds were not satisfied
   --> src\ksl_migrate.rs:140:25
    |
35  | struct MigrationChange {
    | ---------------------- doesn't satisfy `ksl_migrate::MigrationChange: std::clone::Clone`
...
140 |         Ok(self.changes.clone())
    |                         ^^^^^
    |
   ::: C:\Users\ecomm\.rustup\toolchains\stable-x86_64-pc-windows-msvc\lib/rustlib/src/rust\library\alloc\src\vec\mod.rs:397:1
    |
397 | pub struct Vec<T, #[unstable(feature = "allocator_api", issue = "32838")] A: Allocator = Global> {
    | ------------------------------------------------------------------------------------------------ doesn't satisfy `_: Clone`
    |
    = note: the following trait bounds were not satisfied:
            `ksl_migrate::MigrationChange: std::clone::Clone`
            which is required by `std::vec::Vec<ksl_migrate::MigrationChange>: std::clone::Clone`
help: consider annotating `ksl_migrate::MigrationChange` with `#[derive(Clone)]`
    |
35  + #[derive(Clone)]
36  | struct MigrationChange {
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_migrate.rs:203:38
    |
203 |                           .map_err(|e| KslError::type_error(
    |  ______________________________________^^^^^^^^^^^^^^^^^^^^-
204 | |                             format!("AST transformation failed: {}", e),
205 | |                             pos,
206 | |                         ))?;
    | |_________________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
203 -                         .map_err(|e| KslError::type_error(
204 -                             format!("AST transformation failed: {}", e),
205 -                             pos,
206 -                         ))?;
203 +                         .map_err(|e| KslError::type_error(format!("AST transformation failed: {}", e), pos, /* std::string::String */))?;
    |

error[E0599]: no method named `contains` found for struct `std::boxed::Box<ksl_parser::TypeAnnotation>` in the current scope
   --> src\ksl_migrate.rs:216:32
    |
216 |                     if element.contains('[') {
    |                                ^^^^^^^^ method not found in `Box<TypeAnnotation>`
    |
    = help: items from traits can only be used if the trait is implemented and in scope
    = note: the following traits define an item `contains`, perhaps you need to implement one of them:
            candidate #1: `bitflags::traits::Flags`
            candidate #2: `clap_lex::ext::OsStrExt`
            candidate #3: `ipnet::ipnet::Contains`
            candidate #4: `itertools::Itertools`
            candidate #5: `itertools::Itertools`
            candidate #6: `option_ext::OptionExt`
            candidate #7: `std::ops::RangeBounds`

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_migrate.rs:287:38
    |
287 |                           .map_err(|e| KslError::type_error(
    |  ______________________________________^^^^^^^^^^^^^^^^^^^^-
288 | |                             format!("AST transformation failed: {}", e),
289 | |                             pos,
290 | |                         ))?;
    | |_________________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
287 -                         .map_err(|e| KslError::type_error(
288 -                             format!("AST transformation failed: {}", e),
289 -                             pos,
290 -                         ))?;
287 +                         .map_err(|e| KslError::type_error(format!("AST transformation failed: {}", e), pos, /* std::string::String */))?;
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_template.rs:238:28
    |
238 |               .ok_or_else(|| KslError::type_error(
    |  ____________________________^^^^^^^^^^^^^^^^^^^^-
239 | |                 format!("Template {} not found", template_name),
240 | |                 pos,
241 | |             ))?;
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
238 -             .ok_or_else(|| KslError::type_error(
239 -                 format!("Template {} not found", template_name),
240 -                 pos,
241 -             ))?;
238 +             .ok_or_else(|| KslError::type_error(format!("Template {} not found", template_name), pos, /* std::string::String */))?;
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_template.rs:245:26
    |
245 |               .map_err(|e| KslError::type_error(
    |  __________________________^^^^^^^^^^^^^^^^^^^^-
246 | |                 format!("Invalid template {}: {}", template_name, e.message),
247 | |                 SourcePosition::new(e.position, e.position),
248 | |             ))?;
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
245 -             .map_err(|e| KslError::type_error(
246 -                 format!("Invalid template {}: {}", template_name, e.message),
247 -                 SourcePosition::new(e.position, e.position),
248 -             ))?;
245 +             .map_err(|e| KslError::type_error(format!("Invalid template {}: {}", template_name, e.message), SourcePosition::new(e.position, e.position), /* std::string::String */))?;
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_template.rs:258:30
    |
258 |                   .map_err(|e| KslError::type_error(
    |  ______________________________^^^^^^^^^^^^^^^^^^^^-
259 | |                     format!("Failed to write temporary file {}: {}", temp_file.display(), e),
260 | |                     pos,
261 | |                 ))?;
    | |_________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
258 -                 .map_err(|e| KslError::type_error(
259 -                     format!("Failed to write temporary file {}: {}", temp_file.display(), e),
260 -                     pos,
261 -                 ))?;
258 +                 .map_err(|e| KslError::type_error(format!("Failed to write temporary file {}: {}", temp_file.display(), e), pos, /* std::string::String */))?;
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_template.rs:263:30
    |
263 |                   .map_err(|e| KslError::type_error(
    |  ______________________________^^^^^^^^^^^^^^^^^^^^-
264 | |                     format!("Documentation generation failed: {}", e),
265 | |                     pos,
266 | |                 ))?;
    | |_________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
263 -                 .map_err(|e| KslError::type_error(
264 -                     format!("Documentation generation failed: {}", e),
265 -                     pos,
266 -                 ))?;
263 +                 .map_err(|e| KslError::type_error(format!("Documentation generation failed: {}", e), pos, /* std::string::String */))?;
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_template.rs:268:30
    |
268 |                   .map_err(|e| KslError::type_error(
    |  ______________________________^^^^^^^^^^^^^^^^^^^^-
269 | |                     format!("Failed to clean up temporary file {}: {}", temp_file.display(), e),
270 | |                     pos,
271 | |                 ))?;
    | |_________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
268 -                 .map_err(|e| KslError::type_error(
269 -                     format!("Failed to clean up temporary file {}: {}", temp_file.display(), e),
270 -                     pos,
271 -                 ))?;
268 +                 .map_err(|e| KslError::type_error(format!("Failed to clean up temporary file {}: {}", temp_file.display(), e), pos, /* std::string::String */))?;
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_template.rs:277:30
    |
277 |                   .map_err(|e| KslError::type_error(
    |  ______________________________^^^^^^^^^^^^^^^^^^^^-
278 | |                     format!("Failed to write output {}: {}", output_path.display(), e),
279 | |                     pos,
280 | |                 ))?;
    | |_________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
277 -                 .map_err(|e| KslError::type_error(
278 -                     format!("Failed to write output {}: {}", output_path.display(), e),
279 -                     pos,
280 -                 ))?;
277 +                 .map_err(|e| KslError::type_error(format!("Failed to write output {}: {}", output_path.display(), e), pos, /* std::string::String */))?;
    |

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_project.rs:194:34
    |
194 | ...   return Err(KslError::new(ErrorType::ValidationError, "Project name must be non-empty and contain only al...
    |                            ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::Paint;
    |

error[E0599]: no variant or associated item named `ValidationError` found for enum `ksl_errors::ErrorType` in the current scope
   --> src\ksl_project.rs:194:49
    |
194 | ...ror::new(ErrorType::ValidationError, "Project name must be non-empty and contain only alphanumeric characte...
    |                        ^^^^^^^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `ValidationError` not found for this enum

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_project.rs:200:34
    |
200 |             return Err(KslError::new(ErrorType::FileError, format!("Directory '{}' already exists", name)));
    |                                  ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::Paint;
    |

error[E0599]: no variant or associated item named `FileError` found for enum `ksl_errors::ErrorType` in the current scope
   --> src\ksl_project.rs:200:49
    |
200 |             return Err(KslError::new(ErrorType::FileError, format!("Directory '{}' already exists", name)));
    |                                                 ^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `FileError` not found for this enum

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_project.rs:205:38
    |
205 | ...   .ok_or_else(|| KslError::new(ErrorType::TemplateError, format!("Template '{}' not found", template_name)...
    |                                ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::Paint;
    |

error[E0599]: no variant or associated item named `TemplateError` found for enum `ksl_errors::ErrorType` in the current scope
   --> src\ksl_project.rs:205:53
    |
205 | ...rror::new(ErrorType::TemplateError, format!("Template '{}' not found", template_name)))?;
    |                         ^^^^^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `TemplateError` not found for this enum

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_project.rs:209:36
    |
209 | ...   .map_err(|e| KslError::new(ErrorType::FileError, format!("Failed to create project directory: {}", e)))?;
    |                              ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::Paint;
    |

error[E0599]: no variant or associated item named `FileError` found for enum `ksl_errors::ErrorType` in the current scope
   --> src\ksl_project.rs:209:51
    |
209 | ...   .map_err(|e| KslError::new(ErrorType::FileError, format!("Failed to create project directory: {}", e)))?;
    |                                             ^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `FileError` not found for this enum

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_project.rs:214:36
    |
214 |             .map_err(|e| KslError::new(ErrorType::FileError, format!("Failed to create src directory: {}", e)))?;
    |                                    ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::Paint;
    |

error[E0599]: no variant or associated item named `FileError` found for enum `ksl_errors::ErrorType` in the current scope
   --> src\ksl_project.rs:214:51
    |
214 |             .map_err(|e| KslError::new(ErrorType::FileError, format!("Failed to create src directory: {}", e)))?;
    |                                                   ^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `FileError` not found for this enum

error[E0599]: no method named `save_project_config` found for struct `tokio::sync::MutexGuard<'_, ksl_config::ConfigManager>` in the current scope
   --> src\ksl_project.rs:227:16
    |
227 |         config.save_project_config(&project_config)
    |                ^^^^^^^^^^^^^^^^^^^ method not found in `MutexGuard<'_, ConfigManager>`

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_project.rs:229:36
    |
229 |             .map_err(|e| KslError::new(ErrorType::ConfigError, e.to_string()))?;
    |                                    ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::Paint;
    |

error[E0599]: no variant or associated item named `ConfigError` found for enum `ksl_errors::ErrorType` in the current scope
   --> src\ksl_project.rs:229:51
    |
229 |             .map_err(|e| KslError::new(ErrorType::ConfigError, e.to_string()))?;
    |                                                   ^^^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `ConfigError` not found for this enum

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_project.rs:236:36
    |
236 | ...   .map_err(|e| KslError::new(ErrorType::FileError, format!("Failed to create ksl_package.toml: {}", e)))?;
    |                              ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::Paint;
    |

error[E0599]: no variant or associated item named `FileError` found for enum `ksl_errors::ErrorType` in the current scope
   --> src\ksl_project.rs:236:51
    |
236 | ...   .map_err(|e| KslError::new(ErrorType::FileError, format!("Failed to create ksl_package.toml: {}", e)))?;
    |                                             ^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `FileError` not found for this enum

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_project.rs:238:36
    |
238 | ...   .map_err(|e| KslError::new(ErrorType::FileError, format!("Failed to write ksl_package.toml: {}", e)))?;
    |                              ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::Paint;
    |

error[E0599]: no variant or associated item named `FileError` found for enum `ksl_errors::ErrorType` in the current scope
   --> src\ksl_project.rs:238:51
    |
238 | ...   .map_err(|e| KslError::new(ErrorType::FileError, format!("Failed to write ksl_package.toml: {}", e)))?;
    |                                             ^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `FileError` not found for this enum

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_project.rs:243:36
    |
243 |             .map_err(|e| KslError::new(ErrorType::FileError, format!("Failed to create src/main.ksl: {}", e)))?;
    |                                    ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::Paint;
    |

error[E0599]: no variant or associated item named `FileError` found for enum `ksl_errors::ErrorType` in the current scope
   --> src\ksl_project.rs:243:51
    |
243 |             .map_err(|e| KslError::new(ErrorType::FileError, format!("Failed to create src/main.ksl: {}", e)))?;
    |                                                   ^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `FileError` not found for this enum

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_project.rs:245:36
    |
245 |             .map_err(|e| KslError::new(ErrorType::FileError, format!("Failed to write src/main.ksl: {}", e)))?;
    |                                    ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::Paint;
    |

error[E0599]: no variant or associated item named `FileError` found for enum `ksl_errors::ErrorType` in the current scope
   --> src\ksl_project.rs:245:51
    |
245 |             .map_err(|e| KslError::new(ErrorType::FileError, format!("Failed to write src/main.ksl: {}", e)))?;
    |                                                   ^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `FileError` not found for this enum

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_project.rs:252:36
    |
252 |             .map_err(|e| KslError::new(ErrorType::AsyncError, e.to_string()))?;
    |                                    ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::Paint;
    |

error[E0599]: no variant or associated item named `AsyncError` found for enum `ksl_errors::ErrorType` in the current scope
   --> src\ksl_project.rs:252:51
    |
252 |             .map_err(|e| KslError::new(ErrorType::AsyncError, e.to_string()))?;
    |                                                   ^^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `AsyncError` not found for this enum

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_transpiler.rs:90:26
    |
90  |               .map_err(|e| KslError::type_error(
    |  __________________________^^^^^^^^^^^^^^^^^^^^-
91  | |                 format!("Failed to read file {}: {}", self.config.input_file.display(), e),
92  | |                 pos,
93  | |             ))?;
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
90  -             .map_err(|e| KslError::type_error(
91  -                 format!("Failed to read file {}: {}", self.config.input_file.display(), e),
92  -                 pos,
93  -             ))?;
90  +             .map_err(|e| KslError::type_error(format!("Failed to read file {}: {}", self.config.input_file.display(), e), pos, /* std::string::String */))?;
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_transpiler.rs:95:26
    |
95  |               .map_err(|e| KslError::type_error(
    |  __________________________^^^^^^^^^^^^^^^^^^^^-
96  | |                 format!("Parse error at position {}: {}", e.position, e.message),
97  | |                 pos,
98  | |             ))?;
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
95  -             .map_err(|e| KslError::type_error(
96  -                 format!("Parse error at position {}: {}", e.position, e.message),
97  -                 pos,
98  -             ))?;
95  +             .map_err(|e| KslError::type_error(format!("Parse error at position {}: {}", e.position, e.message), pos, /* std::string::String */))?;
    |

error[E0599]: no variant or associated item named `Rust` found for enum `ksl_compiler::CompileTarget` in the current scope
   --> src\ksl_transpiler.rs:107:57
    |
107 |                 TranspileTarget::Rust => CompileTarget::Rust,
    |                                                         ^^^^ variant or associated item not found in `CompileTarget`
    |
   ::: src\ksl_compiler.rs:47:1
    |
47  | pub enum CompileTarget {
    | ---------------------- variant or associated item `Rust` not found for this enum

error[E0599]: no variant or associated item named `Python` found for enum `ksl_compiler::CompileTarget` in the current scope
   --> src\ksl_transpiler.rs:108:59
    |
108 |                 TranspileTarget::Python => CompileTarget::Python,
    |                                                           ^^^^^^ variant or associated item not found in `CompileTarget`
    |
   ::: src\ksl_compiler.rs:47:1
    |
47  | pub enum CompileTarget {
    | ---------------------- variant or associated item `Python` not found for this enum

error[E0599]: no variant or associated item named `JavaScript` found for enum `ksl_compiler::CompileTarget` in the current scope
   --> src\ksl_transpiler.rs:109:63
    |
109 |                 TranspileTarget::JavaScript => CompileTarget::JavaScript,
    |                                                               ^^^^^^^^^^ variant or associated item not found in `CompileTarget`
    |
   ::: src\ksl_compiler.rs:47:1
    |
47  | pub enum CompileTarget {
    | ---------------------- variant or associated item `JavaScript` not found for this enum

error[E0599]: no variant or associated item named `TypeScript` found for enum `ksl_compiler::CompileTarget` in the current scope
   --> src\ksl_transpiler.rs:110:63
    |
110 |                 TranspileTarget::TypeScript => CompileTarget::TypeScript,
    |                                                               ^^^^^^^^^^ variant or associated item not found in `CompileTarget`
    |
   ::: src\ksl_compiler.rs:47:1
    |
47  | pub enum CompileTarget {
    | ---------------------- variant or associated item `TypeScript` not found for this enum

error[E0061]: this function takes 7 arguments but 2 arguments were supplied
   --> src\ksl_transpiler.rs:114:24
    |
114 |         let bytecode = compile(&ast, &compile_config)?;
    |                        ^^^^^^^----------------------- multiple arguments are missing
    |
note: expected `&[AstNode]`, found `&Vec<AstNode>`
   --> src\ksl_transpiler.rs:114:32
    |
114 |         let bytecode = compile(&ast, &compile_config)?;
    |                                ^^^^
    = note: expected reference `&[ksl_ast::AstNode]`
               found reference `&std::vec::Vec<ksl_macros::AstNode>`
note: function defined here
   --> src\ksl_compiler.rs:803:8
    |
803 | pub fn compile(
    |        ^^^^^^^
804 |     ast: &[AstNode],
    |     ---------------
805 |     module_name: &str,
806 |     target: CompileTarget,
    |     ---------------------
807 |     output_path: &str,
    |     -----------------
808 |     metrics: &PerformanceMetrics,
    |     ----------------------------
809 |     enable_debug: bool,
    |     ------------------
810 |     hot_reload_config: Option<HotReloadConfig>,
    |     ------------------------------------------
help: provide the arguments
    |
114 -         let bytecode = compile(&ast, &compile_config)?;
114 +         let bytecode = compile(/* &[ksl_ast::AstNode] */, &compile_config, /* ksl_compiler::CompileTarget */, /* &str */, /* &ksl_analyzer::PerformanceMetrics */, /* bool */, /* std::option::Option<ksl_macros::HotReloadConfig> */)?;
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_transpiler.rs:126:26
    |
126 |               .map_err(|e| KslError::type_error(
    |  __________________________^^^^^^^^^^^^^^^^^^^^-
127 | |                 format!("Failed to write output file {}: {}", self.config.output_file.display(), e),
128 | |                 pos,
129 | |             ))?;
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
126 -             .map_err(|e| KslError::type_error(
127 -                 format!("Failed to write output file {}: {}", self.config.output_file.display(), e),
128 -                 pos,
129 -             ))?;
126 +             .map_err(|e| KslError::type_error(format!("Failed to write output file {}: {}", self.config.output_file.display(), e), pos, /* std::string::String */))?;
    |

error[E0277]: the `?` operator can only be used in a closure that returns `Result` or `Option` (or another type that implements `std::ops::FromResidual`)
   --> src\ksl_transpiler.rs:155:90
    |
155 |                         .map(|(name, typ)| format!("{}: {}", name, self.type_to_rust(typ)?))
    |                              -------------                                               ^ cannot use the `?` operator in a closure that returns `std::string::String`
    |                              |
    |                              this function should return `Result` or `Option` to accept `?`
    |
    = help: the trait `std::ops::FromResidual<std::result::Result<std::convert::Infallible, ksl_errors::KslError>>` is not implemented for `std::string::String`

error[E0599]: no method named `transpile_rust_body_async` found for reference `&ksl_transpiler::Transpiler` in the current scope
   --> src\ksl_transpiler.rs:161:41
    |
161 |                     code.push_str(&self.transpile_rust_body_async(body).await?);
    |                                         ^^^^^^^^^^^^^^^^^^^^^^^^^
    |
help: there is a method `transpile_async` with a similar name, but with different arguments
   --> src\ksl_transpiler.rs:85:5
    |
85  |     pub async fn transpile_async(&self) -> AsyncResult<()> {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

error[E0277]: the size for values of type `str` cannot be known at compilation time
   --> src\ksl_transpiler.rs:161:36
    |
161 |                     code.push_str(&self.transpile_rust_body_async(body).await?);
    |                                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ doesn't have a size known at compile-time
    |
    = help: the trait `std::marker::Sized` is not implemented for `str`
    = note: all local variables must have a statically known size
    = help: unsized locals are gated as an unstable feature

error[E0277]: the size for values of type `str` cannot be known at compilation time
   --> src\ksl_transpiler.rs:161:78
    |
161 |                     code.push_str(&self.transpile_rust_body_async(body).await?);
    |                                                                              ^ doesn't have a size known at compile-time
    |
    = help: the trait `std::marker::Sized` is not implemented for `str`
note: required by a bound in `std::ops::ControlFlow::Break`
   --> C:\Users\ecomm\.rustup\toolchains\stable-x86_64-pc-windows-msvc\lib/rustlib/src/rust\library\core\src\ops\control_flow.rs:86:25
    |
86  | pub enum ControlFlow<B, C = ()> {
    |                         ^^^^^^ required by this bound in `ControlFlow::Break`
...
94  |     Break(B),
    |     ----- required by a bound in this variant

error[E0277]: the size for values of type `str` cannot be known at compilation time
   --> src\ksl_transpiler.rs:161:36
    |
161 |                     code.push_str(&self.transpile_rust_body_async(body).await?);
    |                                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ doesn't have a size known at compile-time
    |
    = help: the trait `std::marker::Sized` is not implemented for `str`
note: required by a bound in `std::ops::ControlFlow::Continue`
   --> C:\Users\ecomm\.rustup\toolchains\stable-x86_64-pc-windows-msvc\lib/rustlib/src/rust\library\core\src\ops\control_flow.rs:86:25
    |
86  | pub enum ControlFlow<B, C = ()> {
    |                         ^^^^^^ required by this bound in `ControlFlow::Continue`
...
90  |     Continue(C),
    |     -------- required by a bound in this variant

error[E0277]: the `?` operator can only be used in a closure that returns `Result` or `Option` (or another type that implements `std::ops::FromResidual`)
   --> src\ksl_transpiler.rs:189:92
    |
189 |                         .map(|(name, typ)| format!("{}: {}", name, self.type_to_python(typ)?))
    |                              -------------                                                 ^ cannot use the `?` operator in a closure that returns `std::string::String`
    |                              |
    |                              this function should return `Result` or `Option` to accept `?`
    |
    = help: the trait `std::ops::FromResidual<std::result::Result<std::convert::Infallible, ksl_errors::KslError>>` is not implemented for `std::string::String`

error[E0599]: no method named `transpile_python_body_async` found for reference `&ksl_transpiler::Transpiler` in the current scope
   --> src\ksl_transpiler.rs:195:41
    |
195 |                     code.push_str(&self.transpile_python_body_async(body).await?);
    |                                         ^^^^^^^^^^^^^^^^^^^^^^^^^^^
    |
help: there is a method `transpile_async` with a similar name, but with different arguments
   --> src\ksl_transpiler.rs:85:5
    |
85  |     pub async fn transpile_async(&self) -> AsyncResult<()> {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

error[E0277]: the size for values of type `str` cannot be known at compilation time
   --> src\ksl_transpiler.rs:195:36
    |
195 |                     code.push_str(&self.transpile_python_body_async(body).await?);
    |                                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ doesn't have a size known at compile-time
    |
    = help: the trait `std::marker::Sized` is not implemented for `str`
    = note: all local variables must have a statically known size
    = help: unsized locals are gated as an unstable feature

error[E0277]: the size for values of type `str` cannot be known at compilation time
   --> src\ksl_transpiler.rs:195:80
    |
195 |                     code.push_str(&self.transpile_python_body_async(body).await?);
    |                                                                                ^ doesn't have a size known at compile-time
    |
    = help: the trait `std::marker::Sized` is not implemented for `str`
note: required by a bound in `std::ops::ControlFlow::Break`
   --> C:\Users\ecomm\.rustup\toolchains\stable-x86_64-pc-windows-msvc\lib/rustlib/src/rust\library\core\src\ops\control_flow.rs:86:25
    |
86  | pub enum ControlFlow<B, C = ()> {
    |                         ^^^^^^ required by this bound in `ControlFlow::Break`
...
94  |     Break(B),
    |     ----- required by a bound in this variant

error[E0277]: the size for values of type `str` cannot be known at compilation time
   --> src\ksl_transpiler.rs:195:36
    |
195 |                     code.push_str(&self.transpile_python_body_async(body).await?);
    |                                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ doesn't have a size known at compile-time
    |
    = help: the trait `std::marker::Sized` is not implemented for `str`
note: required by a bound in `std::ops::ControlFlow::Continue`
   --> C:\Users\ecomm\.rustup\toolchains\stable-x86_64-pc-windows-msvc\lib/rustlib/src/rust\library\core\src\ops\control_flow.rs:86:25
    |
86  | pub enum ControlFlow<B, C = ()> {
    |                         ^^^^^^ required by this bound in `ControlFlow::Continue`
...
90  |     Continue(C),
    |     -------- required by a bound in this variant

error[E0599]: no method named `transpile_js_body_async` found for reference `&ksl_transpiler::Transpiler` in the current scope
   --> src\ksl_transpiler.rs:227:41
    |
227 |                     code.push_str(&self.transpile_js_body_async(body).await?);
    |                                         ^^^^^^^^^^^^^^^^^^^^^^^
    |
help: there is a method `transpile_async` with a similar name, but with different arguments
   --> src\ksl_transpiler.rs:85:5
    |
85  |     pub async fn transpile_async(&self) -> AsyncResult<()> {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

error[E0277]: the size for values of type `str` cannot be known at compilation time
   --> src\ksl_transpiler.rs:227:36
    |
227 |                     code.push_str(&self.transpile_js_body_async(body).await?);
    |                                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ doesn't have a size known at compile-time
    |
    = help: the trait `std::marker::Sized` is not implemented for `str`
    = note: all local variables must have a statically known size
    = help: unsized locals are gated as an unstable feature

error[E0277]: the size for values of type `str` cannot be known at compilation time
   --> src\ksl_transpiler.rs:227:76
    |
227 |                     code.push_str(&self.transpile_js_body_async(body).await?);
    |                                                                            ^ doesn't have a size known at compile-time
    |
    = help: the trait `std::marker::Sized` is not implemented for `str`
note: required by a bound in `std::ops::ControlFlow::Break`
   --> C:\Users\ecomm\.rustup\toolchains\stable-x86_64-pc-windows-msvc\lib/rustlib/src/rust\library\core\src\ops\control_flow.rs:86:25
    |
86  | pub enum ControlFlow<B, C = ()> {
    |                         ^^^^^^ required by this bound in `ControlFlow::Break`
...
94  |     Break(B),
    |     ----- required by a bound in this variant

error[E0277]: the size for values of type `str` cannot be known at compilation time
   --> src\ksl_transpiler.rs:227:36
    |
227 |                     code.push_str(&self.transpile_js_body_async(body).await?);
    |                                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ doesn't have a size known at compile-time
    |
    = help: the trait `std::marker::Sized` is not implemented for `str`
note: required by a bound in `std::ops::ControlFlow::Continue`
   --> C:\Users\ecomm\.rustup\toolchains\stable-x86_64-pc-windows-msvc\lib/rustlib/src/rust\library\core\src\ops\control_flow.rs:86:25
    |
86  | pub enum ControlFlow<B, C = ()> {
    |                         ^^^^^^ required by this bound in `ControlFlow::Continue`
...
90  |     Continue(C),
    |     -------- required by a bound in this variant

error[E0277]: the `?` operator can only be used in a closure that returns `Result` or `Option` (or another type that implements `std::ops::FromResidual`)
   --> src\ksl_transpiler.rs:253:88
    |
253 |                         .map(|(name, typ)| format!("{}: {}", name, self.type_to_ts(typ)?))
    |                              -------------                                             ^ cannot use the `?` operator in a closure that returns `std::string::String`
    |                              |
    |                              this function should return `Result` or `Option` to accept `?`
    |
    = help: the trait `std::ops::FromResidual<std::result::Result<std::convert::Infallible, ksl_errors::KslError>>` is not implemented for `std::string::String`

error[E0599]: no method named `transpile_ts_body_async` found for reference `&ksl_transpiler::Transpiler` in the current scope
   --> src\ksl_transpiler.rs:259:41
    |
259 |                     code.push_str(&self.transpile_ts_body_async(body).await?);
    |                                         ^^^^^^^^^^^^^^^^^^^^^^^
    |
help: there is a method `transpile_async` with a similar name, but with different arguments
   --> src\ksl_transpiler.rs:85:5
    |
85  |     pub async fn transpile_async(&self) -> AsyncResult<()> {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

error[E0277]: the size for values of type `str` cannot be known at compilation time
   --> src\ksl_transpiler.rs:259:36
    |
259 |                     code.push_str(&self.transpile_ts_body_async(body).await?);
    |                                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ doesn't have a size known at compile-time
    |
    = help: the trait `std::marker::Sized` is not implemented for `str`
    = note: all local variables must have a statically known size
    = help: unsized locals are gated as an unstable feature

error[E0277]: the size for values of type `str` cannot be known at compilation time
   --> src\ksl_transpiler.rs:259:76
    |
259 |                     code.push_str(&self.transpile_ts_body_async(body).await?);
    |                                                                            ^ doesn't have a size known at compile-time
    |
    = help: the trait `std::marker::Sized` is not implemented for `str`
note: required by a bound in `std::ops::ControlFlow::Break`
   --> C:\Users\ecomm\.rustup\toolchains\stable-x86_64-pc-windows-msvc\lib/rustlib/src/rust\library\core\src\ops\control_flow.rs:86:25
    |
86  | pub enum ControlFlow<B, C = ()> {
    |                         ^^^^^^ required by this bound in `ControlFlow::Break`
...
94  |     Break(B),
    |     ----- required by a bound in this variant

error[E0277]: the size for values of type `str` cannot be known at compilation time
   --> src\ksl_transpiler.rs:259:36
    |
259 |                     code.push_str(&self.transpile_ts_body_async(body).await?);
    |                                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ doesn't have a size known at compile-time
    |
    = help: the trait `std::marker::Sized` is not implemented for `str`
note: required by a bound in `std::ops::ControlFlow::Continue`
   --> C:\Users\ecomm\.rustup\toolchains\stable-x86_64-pc-windows-msvc\lib/rustlib/src/rust\library\core\src\ops\control_flow.rs:86:25
    |
86  | pub enum ControlFlow<B, C = ()> {
    |                         ^^^^^^ required by this bound in `ControlFlow::Continue`
...
90  |     Continue(C),
    |     -------- required by a bound in this variant

error[E0599]: no method named `get_type_info` found for struct `std::sync::Arc<ksl_types::TypeSystem>` in the current scope
   --> src\ksl_testgen.rs:129:43
    |
129 |         let type_info = state.type_system.get_type_info(return_type)
    |                                           ^^^^^^^^^^^^^
    |
help: there is a method `type_id` with a similar name, but with different arguments
   --> C:\Users\ecomm\.rustup\toolchains\stable-x86_64-pc-windows-msvc\lib/rustlib/src/rust\library\core\src\any.rs:134:5
    |
134 |     fn type_id(&self) -> TypeId;
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^

error[E0599]: no function or associated item named `new_with_profiling` found for struct `kapra_vm::KapraVM` in the current scope
   --> src\ksl_profile.rs:264:31
    |
264 |         let mut vm = KapraVM::new_with_profiling(self.bytecode.clone());
    |                               ^^^^^^^^^^^^^^^^^^ function or associated item not found in `KapraVM`
    |
   ::: src\kapra_vm.rs:120:1
    |
120 | pub struct KapraVM {
    | ------------------ function or associated item `new_with_profiling` not found for this struct
    |
help: there is an associated function `new_with_async` with a similar name
    |
264 -         let mut vm = KapraVM::new_with_profiling(self.bytecode.clone());
264 +         let mut vm = KapraVM::new_with_async(self.bytecode.clone());
    |

error[E0599]: no method named `clone` found for struct `ksl_bytecode::KapraBytecode` in the current scope
   --> src\ksl_profile.rs:264:64
    |
264 |         let mut vm = KapraVM::new_with_profiling(self.bytecode.clone());
    |                                                                ^^^^^ method not found in `KapraBytecode`
    |
   ::: src\ksl_bytecode.rs:720:1
    |
720 | pub struct KapraBytecode {
    | ------------------------ method `clone` not found for this struct
    |
    = help: items from traits can only be used if the trait is implemented and in scope
    = note: the following trait defines an item `clone`, perhaps you need to implement it:
            candidate #1: `std::clone::Clone`

error[E0599]: no method named `get_metrics` found for struct `std::sync::Arc<ksl_metrics::MetricsCollector>` in the current scope
   --> src\ksl_profile.rs:271:46
    |
271 |         let metrics = self.metrics_collector.get_metrics();
    |                                              ^^^^^^^^^^^
    |
help: there is a method `get_async_metrics` with a similar name
    |
271 -         let metrics = self.metrics_collector.get_metrics();
271 +         let metrics = self.metrics_collector.get_async_metrics();
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_profile.rs:318:26
    |
318 |               .map_err(|e| KslError::type_error(
    |  __________________________^^^^^^^^^^^^^^^^^^^^-
319 | |                 format!("Parse error at position {}: {}", e.position, e.message),
320 | |                 pos,
321 | |             ))?;
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
318 -             .map_err(|e| KslError::type_error(
319 -                 format!("Parse error at position {}: {}", e.position, e.message),
320 -                 pos,
321 -             ))?;
318 +             .map_err(|e| KslError::type_error(format!("Parse error at position {}: {}", e.position, e.message), pos, /* std::string::String */))?;
    |

error[E0599]: no method named `expect` found for struct `std::sync::Arc<ksl_metrics::MetricsCollector>` in the current scope
   --> src\ksl_profile.rs:324:32
    |
324 |         self.metrics_collector.expect("Failed to initialize metrics collector").start_collection();
    |                                ^^^^^^ method not found in `Arc<MetricsCollector>`

error[E0599]: no method named `run_async` found for mutable reference `&mut kapra_vm::KapraVM` in the current scope
   --> src\ksl_profile.rs:327:12
    |
327 |         vm.run_async().await
    |            ^^^^^^^^^
    |
help: there is a method `run_with_async` with a similar name, but with different arguments
   --> src\kapra_vm.rs:845:5
    |
845 |     pub async fn run_with_async(&mut self, runtime: &AsyncRuntime) -> Result<(), RuntimeError> {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_profile.rs:328:26
    |
328 |               .map_err(|e| KslError::type_error(
    |  __________________________^^^^^^^^^^^^^^^^^^^^-
329 | |                 format!("Execution error: {}", e),
330 | |                 pos,
331 | |             ))?;
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
328 -             .map_err(|e| KslError::type_error(
329 -                 format!("Execution error: {}", e),
330 -                 pos,
331 -             ))?;
328 +             .map_err(|e| KslError::type_error(format!("Execution error: {}", e), pos, /* std::string::String */))?;
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_security.rs:85:26
    |
85  |               .map_err(|e| KslError::type_error(
    |  __________________________^^^^^^^^^^^^^^^^^^^^-
86  | |                 format!("Failed to read file {}: {}", self.config.input_file.display(), e),
87  | |                 pos,
88  | |             ))?;
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
85  -             .map_err(|e| KslError::type_error(
86  -                 format!("Failed to read file {}: {}", self.config.input_file.display(), e),
87  -                 pos,
88  -             ))?;
85  +             .map_err(|e| KslError::type_error(format!("Failed to read file {}: {}", self.config.input_file.display(), e), pos, /* std::string::String */))?;
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_security.rs:90:26
    |
90  |               .map_err(|e| KslError::type_error(
    |  __________________________^^^^^^^^^^^^^^^^^^^^-
91  | |                 format!("Parse error at position {}: {}", e.position, e.message),
92  | |                 pos,
93  | |             ))?;
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
90  -             .map_err(|e| KslError::type_error(
91  -                 format!("Parse error at position {}: {}", e.position, e.message),
92  -                 pos,
93  -             ))?;
90  +             .map_err(|e| KslError::type_error(format!("Parse error at position {}: {}", e.position, e.message), pos, /* std::string::String */))?;
    |

error[E0599]: no method named `clone` found for struct `ksl_sandbox::SandboxPolicy` in the current scope
  --> src\ksl_security.rs:96:67
   |
96 |         let mut sandbox = Sandbox::new(self.config.sandbox_policy.clone());
   |                                                                   ^^^^^ method not found in `SandboxPolicy`
   |
  ::: src\ksl_sandbox.rs:57:1
   |
57 | pub struct SandboxPolicy {
   | ------------------------ method `clone` not found for this struct
   |
   = help: items from traits can only be used if the trait is implemented and in scope
   = note: the following trait defines an item `clone`, perhaps you need to implement it:
           candidate #1: `std::clone::Clone`

error[E0061]: this function takes 0 arguments but 1 argument was supplied
   --> src\ksl_security.rs:96:27
    |
96  |         let mut sandbox = Sandbox::new(self.config.sandbox_policy.clone());
    |                           ^^^^^^^^^^^^ ---------------------------------- unexpected argument
    |
note: associated function defined here
   --> src\ksl_sandbox.rs:220:12
    |
220 |     pub fn new() -> Self {
    |            ^^^
help: remove the extra argument
    |
96  -         let mut sandbox = Sandbox::new(self.config.sandbox_policy.clone());
96  +         let mut sandbox = Sandbox::new();
    |

error[E0599]: no method named `run_sandbox_async` found for struct `ksl_sandbox::Sandbox` in the current scope
  --> src\ksl_security.rs:97:17
   |
97 |         sandbox.run_sandbox_async(&self.config.input_file).await
   |                 ^^^^^^^^^^^^^^^^^
   |
  ::: src\ksl_sandbox.rs:92:1
   |
92 | pub struct Sandbox {
   | ------------------ method `run_sandbox_async` not found for this struct
   |
help: there is a method `run_sandbox` with a similar name
   |
97 -         sandbox.run_sandbox_async(&self.config.input_file).await
97 +         sandbox.run_sandbox(&self.config.input_file).await
   |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_security.rs:98:26
    |
98  |               .map_err(|e| KslError::type_error(
    |  __________________________^^^^^^^^^^^^^^^^^^^^-
99  | |                 e.into_iter().map(|e| e.to_string()).collect::<Vec<_>>().join("\n"),
100 | |                 pos,
101 | |             ))?;
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
98  -             .map_err(|e| KslError::type_error(
99  -                 e.into_iter().map(|e| e.to_string()).collect::<Vec<_>>().join("\n"),
100 -                 pos,
101 -             ))?;
98  +             .map_err(|e| KslError::type_error(e.into_iter().map(|e| e.to_string()).collect::<Vec<_>>().join("\n"), pos, /* std::string::String */))?;
    |

error[E0425]: cannot find function `extract_capabilities` in this scope
   --> src\ksl_security.rs:105:30
    |
105 |         state.capabilities = extract_capabilities(&ast);
    |                              ^^^^^^^^^^^^^^^^^^^^ not found in this scope

error[E0061]: this function takes 2 arguments but 1 argument was supplied
   --> src\ksl_security.rs:112:9
    |
112 |         verify(&ast)
    |         ^^^^^^------ argument #2 of type `bool` is missing
    |
note: function defined here
   --> src\ksl_verifier.rs:640:14
    |
640 | pub async fn verify(ast: &[AstNode], enable_async: bool) -> Result<(), Vec<VerError>> {
    |              ^^^^^^                  ------------------
help: provide the argument
    |
112 -         verify(&ast)
112 +         verify(&ast, /* bool */)
    |

error[E0599]: no method named `map_err` found for opaque type `impl Future<Output = Result<(), Vec<KslError>>>` in the current scope
   --> src\ksl_security.rs:113:14
    |
112 | /         verify(&ast)
113 | |             .map_err(|e| KslError::type_error(
    | |             -^^^^^^^ method not found in `impl Future<Output = Result<(), Vec<KslError>>>`
    | |_____________|
    |
    |
   ::: C:\Users\ecomm\.cargo\registry\src\index.crates.io-1949cf8c6b5b557f\futures-util-0.3.31\src\future\try_future\mod.rs:308:8
    |
308 |       fn map_err<E, F>(self, f: F) -> MapErr<Self, F>
    |          ------- the method is available for `impl futures::Future<Output = std::result::Result<(), std::vec::Vec<ksl_errors::KslError>>>` here
    |
    = help: items from traits can only be used if the trait is in scope
help: consider `await`ing on the `Future` and calling the method on its `Output`
    |
113 |             .await.map_err(|e| KslError::type_error(
    |              ++++++
help: trait `TryFutureExt` which provides `map_err` is implemented but not in scope; perhaps you want to import it
    |
6   + use futures::TryFutureExt;
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_security.rs:113:26
    |
113 |               .map_err(|e| KslError::type_error(
    |  __________________________^^^^^^^^^^^^^^^^^^^^-
114 | |                 format!("Verification failed: {}", e),
115 | |                 pos,
116 | |             ))?;
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
113 -             .map_err(|e| KslError::type_error(
114 -                 format!("Verification failed: {}", e),
115 -                 pos,
116 -             ))?;
113 +             .map_err(|e| KslError::type_error(format!("Verification failed: {}", e), pos, /* std::string::String */))?;
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_security.rs:122:30
    |
122 |                   .map_err(|e| KslError::type_error(
    |  ______________________________^^^^^^^^^^^^^^^^^^^^-
123 | |                     format!("Failed to create report file {}: {}", report_path.display(), e),
124 | |                     pos,
125 | |                 ))?
    | |_________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
122 -                 .map_err(|e| KslError::type_error(
123 -                     format!("Failed to create report file {}: {}", report_path.display(), e),
124 -                     pos,
125 -                 ))?
122 +                 .map_err(|e| KslError::type_error(format!("Failed to create report file {}: {}", report_path.display(), e), pos, /* std::string::String */))?
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_security.rs:127:30
    |
127 |                   .map_err(|e| KslError::type_error(
    |  ______________________________^^^^^^^^^^^^^^^^^^^^-
128 | |                     format!("Failed to write report file {}: {}", report_path.display(), e),
129 | |                     pos,
130 | |                 ))?;
    | |_________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
127 -                 .map_err(|e| KslError::type_error(
128 -                     format!("Failed to write report file {}: {}", report_path.display(), e),
129 -                     pos,
130 -                 ))?;
127 +                 .map_err(|e| KslError::type_error(format!("Failed to write report file {}: {}", report_path.display(), e), pos, /* std::string::String */))?;
    |

error[E0614]: type `ksl_macros::AstNode` cannot be dereferenced
   --> src\ksl_security.rs:215:79
    |
215 |                 if let AstNode::Expr { kind: ExprKind::Ident(array_name) } = &**array {
    |                                                                               ^^^^^^^

error[E0614]: type `ksl_macros::AstNode` cannot be dereferenced
   --> src\ksl_security.rs:218:83
    |
218 |                     if let AstNode::Expr { kind: ExprKind::Number(index_val) } = &**index {
    |                                                                                   ^^^^^^^

error[E0599]: no method named `detect_external_calls` found for reference `&ksl_security::SecurityAnalyzer` in the current scope
   --> src\ksl_security.rs:242:18
    |
242 |             self.detect_external_calls(body, &mut has_external_call);
    |                  ^^^^^^^^^^^^^^^^^^^^^ method not found in `&SecurityAnalyzer`

error[E0433]: failed to resolve: use of undeclared type `SubCommand`
   --> src\ksl_scaffold.rs:953:9
    |
953 |         SubCommand::with_name("scaffold")
    |         ^^^^^^^^^^ use of undeclared type `SubCommand`

error[E0308]: mismatched types
   --> src\ksl_kapra_crypto.rs:975:26
    |
975 |             entry_point: "main",
    |                          ^^^^^^ expected `Option<&str>`, found `&str`
    |
    = note:   expected enum `std::option::Option<&str>`
            found reference `&'static str`
help: try wrapping the expression in `Some`
    |
975 |             entry_point: Some("main"),
    |                          +++++      +

error[E0433]: failed to resolve: use of undeclared type `SubCommand`
   --> src\ksl_updater.rs:704:9
    |
704 |         SubCommand::with_name("updater")
    |         ^^^^^^^^^^
    |         |
    |         use of undeclared type `SubCommand`
    |         help: a struct with a similar name exists: `Command`

error[E0433]: failed to resolve: use of undeclared type `SubCommand`
   --> src\ksl_updater.rs:707:17
    |
707 |                 SubCommand::with_name("apply")
    |                 ^^^^^^^^^^
    |                 |
    |                 use of undeclared type `SubCommand`
    |                 help: a struct with a similar name exists: `Command`

error[E0433]: failed to resolve: use of undeclared type `SubCommand`
   --> src\ksl_updater.rs:721:17
    |
721 |                 SubCommand::with_name("fetch")
    |                 ^^^^^^^^^^
    |                 |
    |                 use of undeclared type `SubCommand`
    |                 help: a struct with a similar name exists: `Command`

error[E0433]: failed to resolve: use of undeclared type `SubCommand`
   --> src\ksl_updater.rs:732:17
    |
732 |                 SubCommand::with_name("sign")
    |                 ^^^^^^^^^^
    |                 |
    |                 use of undeclared type `SubCommand`
    |                 help: a struct with a similar name exists: `Command`

error[E0433]: failed to resolve: use of undeclared type `License`
  --> src\ksl_template.rs:91:30
   |
91 |                     license: License::MIT,
   |                              ^^^^^^^ use of undeclared type `License`
   |
help: there is an enum variant `crate::AuditIssue::License`; try using the variant's enum
   |
91 -                     license: License::MIT,
91 +                     license: crate::AuditIssue::MIT,
   |

error[E0433]: failed to resolve: use of undeclared type `License`
   --> src\ksl_template.rs:127:30
    |
127 |                     license: License::Apache2,
    |                              ^^^^^^^ use of undeclared type `License`
    |
help: there is an enum variant `crate::AuditIssue::License`; try using the variant's enum
    |
127 -                     license: License::Apache2,
127 +                     license: crate::AuditIssue::Apache2,
    |

error[E0433]: failed to resolve: use of undeclared type `License`
   --> src\ksl_template.rs:166:30
    |
166 |                     license: License::BSD3,
    |                              ^^^^^^^ use of undeclared type `License`
    |
help: there is an enum variant `crate::AuditIssue::License`; try using the variant's enum
    |
166 -                     license: License::BSD3,
166 +                     license: crate::AuditIssue::BSD3,
    |

error[E0433]: failed to resolve: use of undeclared type `License`
   --> src\ksl_template.rs:202:30
    |
202 |                     license: License::MIT,
    |                              ^^^^^^^ use of undeclared type `License`
    |
help: there is an enum variant `crate::AuditIssue::License`; try using the variant's enum
    |
202 -                     license: License::MIT,
202 +                     license: crate::AuditIssue::MIT,
    |

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
   --> src\ksl_ir.rs:480:28
    |
480 |               bytecode_hash: FixedArray([0; 32]),
    |                              ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
    |
   ::: src\ksl_kapra_crypto.rs:44:1
    |
44  | / pub struct FixedArray<const N: usize> {
45  | |     data: [u8; N],
46  | | }
    | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
   --> src\kapra_vm.rs:222:29
    |
222 |               gas_charged_to: FixedArray([0; 32]),
    |                               ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
    |
   ::: src\ksl_kapra_crypto.rs:44:1
    |
44  | / pub struct FixedArray<const N: usize> {
45  | |     data: [u8; N],
46  | | }
    | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
   --> src\kapra_vm.rs:225:25
    |
225 |                   sender: FixedArray([0; 32]),
    |                           ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
    |
   ::: src\ksl_kapra_crypto.rs:44:1
    |
44  | / pub struct FixedArray<const N: usize> {
45  | |     data: [u8; N],
46  | | }
    | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
   --> src\kapra_vm.rs:575:36
    |
575 |                           delegatee: FixedArray(delegatee),
    |                                      ^^^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
    |
   ::: src\ksl_kapra_crypto.rs:44:1
    |
44  | / pub struct FixedArray<const N: usize> {
45  | |     data: [u8; N],
46  | | }
    | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:1280:27
     |
1280 |           let contract_id = FixedArray(hasher.finalize().into());
     |                             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:1438:9
     |
1438 |           FixedArray(hasher.finalize().into())
     |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0425]: cannot find function `run_jit` in this scope
   --> src\ksl_cli.rs:283:9
    |
283 |         run_jit(bytecode, async_support, debug)
    |         ^^^^^^^ not found in this scope

error[E0425]: cannot find function `find_shard_operations` in this scope
   --> src\ksl_optimizer.rs:136:40
    |
136 |                     if let Some(ops) = find_shard_operations(&body, pattern) {
    |                                        ^^^^^^^^^^^^^^^^^^^^^ not found in this scope

error[E0425]: cannot find function `vectorize_shard_ops` in this scope
   --> src\ksl_optimizer.rs:138:49
    |
138 |                         if let Ok(vectorized) = vectorize_shard_ops(ops, self.vector_width) {
    |                                                 ^^^^^^^^^^^^^^^^^^^ not found in this scope

error[E0425]: cannot find function `replace_with_vector_ops` in this scope
   --> src\ksl_optimizer.rs:139:29
    |
139 | ...                   replace_with_vector_ops(&mut body, vectorized);
    |                       ^^^^^^^^^^^^^^^^^^^^^^^ not found in this scope

error[E0425]: cannot find function `build_line_map` in this scope
   --> src\ksl_profile.rs:242:24
    |
242 |         let line_map = build_line_map(&ast, &bytecode);
    |                        ^^^^^^^^^^^^^^ not found in this scope

Some errors have detailed explanations: E0026, E0034, E0061, E0063, E0106, E0119, E0191, E0252, E0255...
For more information about an error, try `rustc --explain E0026`.
warning: `KSL` (lib) generated 632 warnings
error: could not compile `KSL` (lib) due to 1454 previous errors; 632 warnings emitted
warning: build failed, waiting for other jobs to finish...
error[E0428]: the name `tests` is defined multiple times
   --> src\ksl_kapra_consensus.rs:949:1
    |
752 | mod tests {
    | --------- previous definition of the module `tests` here
...
949 | mod tests {
    | ^^^^^^^^^ `tests` redefined here
    |
    = note: `tests` must be defined only once in the type namespace of this module

error[E0428]: the name `tests` is defined multiple times
   --> src\ksl_bench.rs:472:1
    |
284 | mod tests {
    | --------- previous definition of the module `tests` here
...
472 | mod tests {
    | ^^^^^^^^^ `tests` redefined here
    |
    = note: `tests` must be defined only once in the type namespace of this module

error: invalid format string: expected `}`, found `x`
   --> src\ksl_package.rs:325:57
    |
325 |         writeln!(module, "fn add(x: u32, y: u32): u32 { x + y; }").unwrap();
    |                                                       - ^ expected `}` in format string
    |                                                       |
    |                                                       because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `x`
   --> src\ksl_package.rs:355:63
    |
355 |         writeln!(module, "async fn add(x: u32, y: u32): u32 { x + y; }").unwrap();
    |                                                             - ^ expected `}` in format string
    |                                                             |
    |                                                             because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `x`
   --> src\ksl_package.rs:384:57
    |
384 |         writeln!(module, "fn add(x: u32, y: u32): u32 { x + y; }").unwrap();
    |                                                       - ^ expected `}` in format string
    |                                                       |
    |                                                       because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `x`
   --> src\ksl_package.rs:412:63
    |
412 |         writeln!(module, "async fn add(x: u32, y: u32): u32 { x + y; }").unwrap();
    |                                                             - ^ expected `}` in format string
    |                                                             |
    |                                                             because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_analyzer.rs:582:29
    |
582 |             "fn compute() { let x: u32 = 42; let y: u32 = x + x; }"
    |                           - ^ expected `}` in format string
    |                           |
    |                           because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_analyzer.rs:597:38
    |
597 |             "async fn fetch_data() { let data = await http.get(\"https://example.com\"); }"
    |                                    - ^ expected `}` in format string
    |                                    |
    |                                    because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: async functions cannot be used for tests
   --> src\ksl_wasm.rs:642:5
    |
642 |       async fn test_wasm_generation_with_abi() {
    |       ^----
    |       |
    |  _____`async` because of this
    | |
643 | |         let bytecode = KapraBytecode {
644 | |             instructions: vec![
645 | |                 KapraInstruction {
...   |
681 | |         assert!(found_version);
682 | |     }
    | |_____^

error: invalid format string: expected `}`, found `l`
   --> src\ksl_linter.rs:363:31
    |
363 |             "fn CamelCase() { let NotSnakeCase: u32 = 42; }"
    |                             - ^ expected `}` in format string
    |                             |
    |                             because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_linter.rs:379:26
    |
379 |             "fn test() { let unused: u32 = 42; let used: u32 = 43; let x = used + 1; }"
    |                        - ^ expected `}` in format string
    |                        |
    |                        because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_linter.rs:394:26
    |
394 |             "fn test() { let data: result<string, error> = http.get(\"url\"); }"
    |                        - ^ expected `}` in format string
    |                        |
    |                        because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_linter.rs:409:26
    |
409 |             "fn test() { let x = await http.get(\"url\"); }"
    |                        - ^ expected `}` in format string
    |                        |
    |                        because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_linter.rs:424:32
    |
424 |             "async fn test() { let x = await http.get(\"url\"); }"
    |                              - ^ expected `}` in format string
    |                              |
    |                              because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_linter.rs:438:32
    |
438 |             "async fn test() { let x = await http.get(\"url\"); }"
    |                              - ^ expected `}` in format string
    |                              |
    |                              because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_module.rs:285:58
    |
285 |             "mod utils;\nimport utils::add;\nfn main() { let x = add(1, 2); }"
    |                                                        - ^ expected `}` in format string
    |                                                        |
    |                                                        because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `x`
   --> src\ksl_module.rs:291:44
    |
291 |             "fn add(x: u32, y: u32): u32 { x + y; }"
    |                                          - ^ expected `}` in format string
    |                                          |
    |                                          because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_module.rs:309:76
    |
309 | ...   "async mod network;\nimport network::fetch;\nasync fn main() { let data = await fetch(\"https://example....
    |                                                                    - ^ expected `}` in format string
    |                                                                    |
    |                                                                    because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `/`
   --> src\ksl_module.rs:315:52
    |
315 |             "async fn fetch(url: string): string { /* implementation */ }"
    |                                                  - ^ expected `}` in format string
    |                                                  |
    |                                                  because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_module.rs:334:58
    |
334 |             "mod utils;\nimport utils::add;\nfn main() { let x = add(1, 2); }"
    |                                                        - ^ expected `}` in format string
    |                                                        |
    |                                                        because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `x`
   --> src\ksl_module.rs:340:44
    |
340 |             "fn add(x: u32, y: u32): u32 { x + y; }"
    |                                          - ^ expected `}` in format string
    |                                          |
    |                                          because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_module.rs:357:59
    |
357 |             "import std::crypto::bls_verify;\nfn main() { let valid = bls_verify(...); }"
    |                                                         - ^ expected `}` in format string
    |                                                         |
    |                                                         because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_contract.rs:883:37
    |
883 |             "#[verify]\nfn main() { let hash: array<u8, 32> = sha3(\"data\"); }"
    |                                   - ^ expected `}` in format string
    |                                   |
    |                                   because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_contract.rs:899:37
    |
899 |             "#[verify]\nfn main() { loop { } }"
    |                                   - ^ expected `}` in format string
    |                                   |
    |                                   because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_contract.rs:914:37
    |
914 |             "#[verify]\nfn main() { let now: u64 = time.now(); }"
    |                                   - ^ expected `}` in format string
    |                                   |
    |                                   because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_contract.rs:942:37
    |
942 |             "#[verify]\nfn main() { let x: u64 = 42; }"
    |                                   - ^ expected `}` in format string
    |                                   |
    |                                   because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_contract.rs:970:37
    |
970 |             "#[verify]\nfn main() { let x: u64 = 42; }"
    |                                   - ^ expected `}` in format string
    |                                   |
    |                                   because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `s`
    --> src\ksl_hot_reload.rs:1642:46
     |
1642 |         writeln!(file, "fn main() {{ async { sleep(1); } }}").unwrap();
     |                                            - ^ expected `}` in format string
     |                                            |
     |                                            because of this opening brace
     |
     = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `s`
    --> src\ksl_hot_reload.rs:1666:46
     |
1666 |         writeln!(file, "fn main() {{ async { sleep(1); print(\"Updated\"); } }}").unwrap();
     |                                            - ^ expected `}` in format string
     |                                            |
     |                                            because of this opening brace
     |
     = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_simulator.rs:473:17
    |
472 |             "fn main() {
    |                        - because of this opening brace
473 |                 let tx = blockchain.new_tx();
    |                 ^ expected `}` in format string
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_simulator.rs:500:17
    |
499 |             "fn main() {
    |                        - because of this opening brace
500 |                 let reading = device.sensor();
    |                 ^ expected `}` in format string
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_simulator.rs:526:17
    |
525 |             "fn main() {
    |                        - because of this opening brace
526 |                 let response = http.get(\"https://example.com\");
    |                 ^ expected `}` in format string
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_simulator.rs:557:17
    |
556 |             "fn main() {
    |                        - because of this opening brace
557 |                 let response = http.get(\"https://example.com\");
    |                 ^ expected `}` in format string
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `f`
   --> src\ksl_simulator.rs:588:17
    |
587 |             "fn main() {
    |                        - because of this opening brace
588 |                 for i in 0..20 {
    |                 ^ expected `}` in format string
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_simulator.rs:620:17
    |
619 |             "fn main() {
    |                        - because of this opening brace
620 |                 let response = http.get(\"https://example.com\");
    |                 ^ expected `}` in format string
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: 1 positional argument in format string, but no arguments were given
   --> src\ksl_simulator.rs:645:24
    |
645 |             "fn main() { }"
    |                        ^^^

error: invalid format string: expected `}`, found `l`
   --> src\ksl_cli.rs:587:32
    |
587 |             "async fn main() { let data = await http.get(\"https://example.com\"); }"
    |                              - ^ expected `}` in format string
    |                              |
    |                              because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_coverage.rs:404:39
    |
404 |             "#[test]\nfn test_add() { let x: u32 = 42; assert(x + x == 84); }"
    |                                     - ^ expected `}` in format string
    |                                     |
    |                                     because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_coverage.rs:418:40
    |
418 |             "#[test]\nfn test_cond() { let x: u32 = 42; if x > 0 { x; } else { 0; } }"
    |                                      - ^ expected `}` in format string
    |                                      |
    |                                      because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_coverage.rs:432:42
    |
432 |             "#[test]\nfn test_simple() { let x: u32 = 42; }"
    |                                        - ^ expected `}` in format string
    |                                        |
    |                                        because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_debug.rs:408:26
    |
408 |             "fn main() { let x: u32 = 42; let y: u32 = x + x; }"
    |                        - ^ expected `}` in format string
    |                        |
    |                        because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_debug.rs:422:26
    |
422 |             "fn main() { let x: u32 = 42; let y: u32 = x + x; }"
    |                        - ^ expected `}` in format string
    |                        |
    |                        because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_debug.rs:438:26
    |
438 |             "fn main() { let x: u32 = 42; }"
    |                        - ^ expected `}` in format string
    |                        |
    |                        because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error[E0428]: the name `test_abi_validation` is defined multiple times
    --> src\ksl_genesis.rs:1207:11
     |
1129 |     fn test_abi_validation() {
     |     ------------------------ previous definition of the value `test_abi_validation` here
...
1207 |     async fn test_abi_validation() {
     |           ^^^^^^^^^^^^^^^^^^^^^^^^ `test_abi_validation` redefined here
     |
     = note: `test_abi_validation` must be defined only once in the value namespace of this module

error: invalid format string: expected `}`, found `l`
   --> src\ksl_test.rs:734:30
    |
734 |             "fn test_add() { let x: u32 = 42; assert(x == 42); }"
    |                            - ^ expected `}` in format string
    |                            |
    |                            because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_test.rs:757:30
    |
757 |             "fn test_add() { let x: u32 = 42; assert(x == 43); }"
    |                            - ^ expected `}` in format string
    |                            |
    |                            because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_test.rs:806:38
    |
806 |             "async fn test_async() { let x: u32 = 42; assert(x == 42); }"
    |                                    - ^ expected `}` in format string
    |                                    |
    |                                    because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_test.rs:853:35
    |
853 |             "fn test_snapshot() { let x: u32 = 42; assert(x == 42); }"
    |                                 - ^ expected `}` in format string
    |                                 |
    |                                 because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_test.rs:878:30
    |
878 |             "fn test_gas() { let x: u32 = 42; assert(x == 42); }"
    |                            - ^ expected `}` in format string
    |                            |
    |                            because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_test.rs:957:30
    |
957 |             "fn test_add() { let x: u32 = 42; assert(x == 42); }"
    |                            - ^ expected `}` in format string
    |                            |
    |                            because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_aot.rs:507:26
    |
507 |             "fn main() { let x: u32 = 42; let y: u32 = x + x; }"
    |                        - ^ expected `}` in format string
    |                        |
    |                        because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_sandbox.rs:396:26
    |
396 |             "fn main() { let x: u32 = 42; let y: u32 = x + x; }"
    |                        - ^ expected `}` in format string
    |                        |
    |                        because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_sandbox.rs:408:26
    |
408 |             "fn main() { let data: result<string, error> = http.get(\"url\"); }"
    |                        - ^ expected `}` in format string
    |                        |
    |                        because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_sandbox.rs:422:42
    |
422 |             "#[allow(http)]\nfn main() { let data: result<string, error> = http.get(\"url\"); }"
    |                                        - ^ expected `}` in format string
    |                                        |
    |                                        because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `f`
   --> src\ksl_sandbox.rs:435:17
    |
434 |             "#[allow(http)]\nfn main() {
    |                                        - because of this opening brace
435 |                 for i in 0..20 {
    |                 ^ expected `}` in format string
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_sandbox.rs:460:17
    |
459 |             "#[allow(http)]\nfn main() {
    |                                        - because of this opening brace
460 |                 let _ = http.get(\"https://example.com\");
    |                 ^ expected `}` in format string
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_sandbox.rs:482:17
    |
481 |             "fn main() {
    |                        - because of this opening brace
482 |                 let mut i: u64 = 0;
    |                 ^ expected `}` in format string
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_sandbox.rs:506:17
    |
505 |             "fn main() {
    |                        - because of this opening brace
506 |                 let mut v: vec<u8> = vec![];
    |                 ^ expected `}` in format string
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_bench.rs:294:41
    |
294 |             "#[bench]\nfn bench_add() { let x: u32 = 42; let y: u32 = x + x; }"
    |                                       - ^ expected `}` in format string
    |                                       |
    |                                       because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_bench.rs:311:25
    |
311 |             "fn add() { let x: u32 = 42; let y: u32 = x + x; }"
    |                       - ^ expected `}` in format string
    |                       |
    |                       because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error: invalid format string: expected `}`, found `l`
   --> src\ksl_ci.rs:908:30
    |
908 |             "fn test_add() { let x: u32 = 42; assert(x == 42); }"
    |                            - ^ expected `}` in format string
    |                            |
    |                            because of this opening brace
    |
    = note: if you intended to print `{`, you can escape it using `{{`

error[E0432]: unresolved imports `ed25519_dalek::Keypair`, `ed25519_dalek::PublicKey`
  --> src\ksl_stdlib_crypto.rs:14:5
   |
14 |     Keypair as EdKeypair,
   |     ^^^^^^^^^^^^^^^^^^^^ no `Keypair` in the root
15 |     PublicKey as EdPublicKey,
   |     ^^^^^^^^^^^^^^^^^^^^^^^^ no `PublicKey` in the root
   |
   = help: consider importing one of these items instead:
           blst::min_pk::PublicKey
           blst::min_sig::PublicKey
           pqcrypto::kem::hqc128::PublicKey
           pqcrypto::kem::hqc192::PublicKey
           pqcrypto::kem::hqc256::PublicKey
           pqcrypto::kem::mceliece348864::PublicKey
           pqcrypto::kem::mceliece348864f::PublicKey
           pqcrypto::kem::mceliece460896::PublicKey
           pqcrypto::kem::mceliece460896f::PublicKey
           pqcrypto::kem::mceliece6688128::PublicKey
           pqcrypto::kem::mceliece6688128f::PublicKey
           pqcrypto::kem::mceliece6960119::PublicKey
           pqcrypto::kem::mceliece6960119f::PublicKey
           pqcrypto::kem::mceliece8192128::PublicKey
           pqcrypto::kem::mceliece8192128f::PublicKey
           pqcrypto::kem::mlkem1024::PublicKey
           pqcrypto::kem::mlkem512::PublicKey
           pqcrypto::kem::mlkem768::PublicKey
           pqcrypto::sign::falcon1024::PublicKey
           pqcrypto::sign::falcon512::PublicKey
           pqcrypto::sign::falconpadded1024::PublicKey
           pqcrypto::sign::falconpadded512::PublicKey
           pqcrypto::sign::mldsa44::PublicKey
           pqcrypto::sign::mldsa65::PublicKey
           pqcrypto::sign::mldsa87::PublicKey
           pqcrypto::sign::sphincssha2128fsimple::PublicKey
           pqcrypto::sign::sphincssha2128ssimple::PublicKey
           pqcrypto::sign::sphincssha2192fsimple::PublicKey
           pqcrypto::sign::sphincssha2192ssimple::PublicKey
           pqcrypto::sign::sphincssha2256fsimple::PublicKey
           pqcrypto::sign::sphincssha2256ssimple::PublicKey
           pqcrypto::sign::sphincsshake128fsimple::PublicKey
           pqcrypto::sign::sphincsshake128ssimple::PublicKey
           pqcrypto::sign::sphincsshake192fsimple::PublicKey
           pqcrypto::sign::sphincsshake192ssimple::PublicKey
           pqcrypto::sign::sphincsshake256fsimple::PublicKey
           pqcrypto::sign::sphincsshake256ssimple::PublicKey
           pqcrypto_dilithium::dilithium2::PublicKey
           pqcrypto_dilithium::dilithium3::PublicKey
           pqcrypto_dilithium::dilithium5::PublicKey
           pqcrypto_traits::kem::PublicKey
           pqcrypto_traits::sign::PublicKey

error[E0432]: unresolved imports `pqcrypto::dilithium`, `pqcrypto::dilithium`
  --> src\ksl_validator_keys.rs:15:15
   |
15 | use pqcrypto::dilithium::{self, DilithiumKeypair, DilithiumPublicKey, DilithiumSecretKey};
   |               ^^^^^^^^^   ^^^^ no `dilithium` in the root
   |               |
   |               could not find `dilithium` in `pqcrypto`
   |
   = note: unresolved item `crate::ksl_kapra_crypto::tests::dilithium` exists but is inaccessible

error[E0432]: unresolved imports `blst::blst_sk`, `blst::blst_pk`, `blst::blst_signature`
  --> src\ksl_validator_keys.rs:16:12
   |
16 | use blst::{blst_sk, blst_pk, blst_signature};
   |            ^^^^^^^  ^^^^^^^  ^^^^^^^^^^^^^^ no `blst_signature` in the root
   |            |        |
   |            |        no `blst_pk` in the root
   |            no `blst_sk` in the root
   |
   = note: unresolved item `crate::ksl_kapra_crypto::tests::blst_sk` exists but is inaccessible
   = note: unresolved item `crate::ksl_kapra_crypto::tests::blst_pk` exists but is inaccessible
   = note: unresolved item `crate::ksl_kapra_crypto::tests::blst_signature` exists but is inaccessible
help: a similar name exists in the module
   |
16 - use blst::{blst_sk, blst_pk, blst_signature};
16 + use blst::{blst_fr, blst_pk, blst_signature};
   |
help: a similar name exists in the module
   |
16 - use blst::{blst_sk, blst_pk, blst_signature};
16 + use blst::{blst_sk, blst_p1, blst_signature};
   |

error[E0432]: unresolved imports `ed25519_dalek::Keypair`, `ed25519_dalek::PublicKey`
  --> src\ksl_validator_keys.rs:24:21
   |
24 | use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
   |                     ^^^^^^^  ^^^^^^^^^ no `PublicKey` in the root
   |                     |
   |                     no `Keypair` in the root
   |
   = note: unresolved item `crate::ksl_kapra_crypto::tests::Keypair` exists but is inaccessible
   = help: consider importing one of these items instead:
           blst::min_pk::PublicKey
           blst::min_sig::PublicKey
           pqcrypto::kem::hqc128::PublicKey
           pqcrypto::kem::hqc192::PublicKey
           pqcrypto::kem::hqc256::PublicKey
           pqcrypto::kem::mceliece348864::PublicKey
           pqcrypto::kem::mceliece348864f::PublicKey
           pqcrypto::kem::mceliece460896::PublicKey
           pqcrypto::kem::mceliece460896f::PublicKey
           pqcrypto::kem::mceliece6688128::PublicKey
           pqcrypto::kem::mceliece6688128f::PublicKey
           pqcrypto::kem::mceliece6960119::PublicKey
           pqcrypto::kem::mceliece6960119f::PublicKey
           pqcrypto::kem::mceliece8192128::PublicKey
           pqcrypto::kem::mceliece8192128f::PublicKey
           pqcrypto::kem::mlkem1024::PublicKey
           pqcrypto::kem::mlkem512::PublicKey
           pqcrypto::kem::mlkem768::PublicKey
           pqcrypto::sign::falcon1024::PublicKey
           pqcrypto::sign::falcon512::PublicKey
           pqcrypto::sign::falconpadded1024::PublicKey
           pqcrypto::sign::falconpadded512::PublicKey
           pqcrypto::sign::mldsa44::PublicKey
           pqcrypto::sign::mldsa65::PublicKey
           pqcrypto::sign::mldsa87::PublicKey
           pqcrypto::sign::sphincssha2128fsimple::PublicKey
           pqcrypto::sign::sphincssha2128ssimple::PublicKey
           pqcrypto::sign::sphincssha2192fsimple::PublicKey
           pqcrypto::sign::sphincssha2192ssimple::PublicKey
           pqcrypto::sign::sphincssha2256fsimple::PublicKey
           pqcrypto::sign::sphincssha2256ssimple::PublicKey
           pqcrypto::sign::sphincsshake128fsimple::PublicKey
           pqcrypto::sign::sphincsshake128ssimple::PublicKey
           pqcrypto::sign::sphincsshake192fsimple::PublicKey
           pqcrypto::sign::sphincsshake192ssimple::PublicKey
           pqcrypto::sign::sphincsshake256fsimple::PublicKey
           pqcrypto::sign::sphincsshake256ssimple::PublicKey
           pqcrypto_dilithium::dilithium2::PublicKey
           pqcrypto_dilithium::dilithium3::PublicKey
           pqcrypto_dilithium::dilithium5::PublicKey
           pqcrypto_traits::kem::PublicKey
           pqcrypto_traits::sign::PublicKey

error[E0432]: unresolved imports `bincode::serialize`, `bincode::deserialize`
  --> src\ksl_contract.rs:78:15
   |
78 | use bincode::{serialize, deserialize};
   |               ^^^^^^^^^  ^^^^^^^^^^^ no `deserialize` in the root
   |               |
   |               no `serialize` in the root
   |
   = note: unresolved item `crate::kapra_vm::tests::serialize` exists but is inaccessible
   = note: unresolved item `crate::kapra_vm::tests::deserialize` exists but is inaccessible

error[E0432]: unresolved imports `ed25519_dalek::Keypair`, `ed25519_dalek::PublicKey`
  --> src\ksl_hot_reload.rs:26:21
   |
26 | use ed25519_dalek::{Keypair, PublicKey, Signature, Verifier};
   |                     ^^^^^^^  ^^^^^^^^^ no `PublicKey` in the root
   |                     |
   |                     no `Keypair` in the root
   |
   = note: unresolved item `crate::ksl_validator_keys::tests::Keypair` exists but is inaccessible
   = help: consider importing one of these items instead:
           blst::min_pk::PublicKey
           blst::min_sig::PublicKey
           pqcrypto::kem::hqc128::PublicKey
           pqcrypto::kem::hqc192::PublicKey
           pqcrypto::kem::hqc256::PublicKey
           pqcrypto::kem::mceliece348864::PublicKey
           pqcrypto::kem::mceliece348864f::PublicKey
           pqcrypto::kem::mceliece460896::PublicKey
           pqcrypto::kem::mceliece460896f::PublicKey
           pqcrypto::kem::mceliece6688128::PublicKey
           pqcrypto::kem::mceliece6688128f::PublicKey
           pqcrypto::kem::mceliece6960119::PublicKey
           pqcrypto::kem::mceliece6960119f::PublicKey
           pqcrypto::kem::mceliece8192128::PublicKey
           pqcrypto::kem::mceliece8192128f::PublicKey
           pqcrypto::kem::mlkem1024::PublicKey
           pqcrypto::kem::mlkem512::PublicKey
           pqcrypto::kem::mlkem768::PublicKey
           pqcrypto::sign::falcon1024::PublicKey
           pqcrypto::sign::falcon512::PublicKey
           pqcrypto::sign::falconpadded1024::PublicKey
           pqcrypto::sign::falconpadded512::PublicKey
           pqcrypto::sign::mldsa44::PublicKey
           pqcrypto::sign::mldsa65::PublicKey
           pqcrypto::sign::mldsa87::PublicKey
           pqcrypto::sign::sphincssha2128fsimple::PublicKey
           pqcrypto::sign::sphincssha2128ssimple::PublicKey
           pqcrypto::sign::sphincssha2192fsimple::PublicKey
           pqcrypto::sign::sphincssha2192ssimple::PublicKey
           pqcrypto::sign::sphincssha2256fsimple::PublicKey
           pqcrypto::sign::sphincssha2256ssimple::PublicKey
           pqcrypto::sign::sphincsshake128fsimple::PublicKey
           pqcrypto::sign::sphincsshake128ssimple::PublicKey
           pqcrypto::sign::sphincsshake192fsimple::PublicKey
           pqcrypto::sign::sphincsshake192ssimple::PublicKey
           pqcrypto::sign::sphincsshake256fsimple::PublicKey
           pqcrypto::sign::sphincsshake256ssimple::PublicKey
           pqcrypto_dilithium::dilithium2::PublicKey
           pqcrypto_dilithium::dilithium3::PublicKey
           pqcrypto_dilithium::dilithium5::PublicKey
           pqcrypto_traits::kem::PublicKey
           pqcrypto_traits::sign::PublicKey

error[E0432]: unresolved imports `opentelemetry::metrics::Unit`, `opentelemetry::metrics::ValueRecorder`
  --> src\ksl_metrics.rs:14:42
   |
14 |     metrics::{Counter, Histogram, Meter, Unit, ValueRecorder},
   |                                          ^^^^  ^^^^^^^^^^^^^ no `ValueRecorder` in `metrics`
   |                                          |
   |                                          no `Unit` in `metrics`
   |
   = help: consider importing one of these variants instead:
           crate::TokenType::Unit
           crate::ksl_macros::Type::Unit
           serde::de::Unexpected::Unit
           syn::Fields::Unit

error[E0432]: unresolved imports `clap::App`, `clap::SubCommand`
  --> src\ksl_genesis.rs:13:12
   |
13 | use clap::{App, Arg, SubCommand};
   |            ^^^       ^^^^^^^^^^
   |            |         |
   |            |         no `SubCommand` in the root
   |            |         help: a similar name exists in the module (notice the capitalization): `Subcommand`
   |            no `App` in the root
   |
   = help: consider importing this variant instead:
           z3::AstKind::App
   = note: unresolved item `crate::ksl_cli::tests::SubCommand` exists but is inaccessible

error[E0432]: unresolved imports `sysinfo::SystemExt`, `sysinfo::ProcessExt`
  --> src\ksl_ci.rs:36:23
   |
36 | use sysinfo::{System, SystemExt, ProcessExt};
   |                       ^^^^^^^^^  ^^^^^^^^^^ no `ProcessExt` in the root
   |                       |
   |                       no `SystemExt` in the root
   |
   = note: unresolved item `crate::ksl_benchmark::tests::SystemExt` exists but is inaccessible
   = note: unresolved item `crate::ksl_benchmark::tests::ProcessExt` exists but is inaccessible
help: a similar name exists in the module
   |
36 - use sysinfo::{System, SystemExt, ProcessExt};
36 + use sysinfo::{System, System, ProcessExt};
   |
help: a similar name exists in the module
   |
36 - use sysinfo::{System, SystemExt, ProcessExt};
36 + use sysinfo::{System, SystemExt, Process};
   |

error[E0432]: unresolved import `crate::ksl_async::AsyncResult`
  --> src\ksl_contract.rs:54:38
   |
54 | use crate::ksl_async::{AsyncRuntime, AsyncResult};
   |                                      ^^^^^^^^^^^ no `AsyncResult` in `ksl_async`
   |
   = note: unresolved item `crate::ksl_kapra_zkp::tests::AsyncResult` exists but is inaccessible

error[E0432]: unresolved import `crate::ksl_async::AsyncResult`
  --> src\ksl_contract_verifier.rs:53:38
   |
53 | use crate::ksl_async::{AsyncRuntime, AsyncResult};
   |                                      ^^^^^^^^^^^ no `AsyncResult` in `ksl_async`
   |
   = note: unresolved item `crate::ksl_contract::tests::AsyncResult` exists but is inaccessible

error[E0432]: unresolved import `crate::ksl_async::AsyncResult`
  --> src\ksl_deploy.rs:16:38
   |
16 | use crate::ksl_async::{AsyncRuntime, AsyncResult};
   |                                      ^^^^^^^^^^^ no `AsyncResult` in `ksl_async`
   |
   = note: unresolved item `crate::ksl_contract_verifier::tests::AsyncResult` exists but is inaccessible

error[E0432]: unresolved import `crate::ksl_async::AsyncResult`
  --> src\ksl_repl_server.rs:12:38
   |
12 | use crate::ksl_async::{AsyncRuntime, AsyncResult};
   |                                      ^^^^^^^^^^^ no `AsyncResult` in `ksl_async`
   |
   = note: unresolved item `crate::ksl_deploy::tests::AsyncResult` exists but is inaccessible

error[E0432]: unresolved import `crate::ksl_analyzer::AnalysisResult`
 --> src\ksl_refactor.rs:8:37
  |
8 | use crate::ksl_analyzer::{Analyzer, AnalysisResult};
  |                                     ^^^^^^^^^^^^^^ no `AnalysisResult` in `ksl_analyzer`
  |
  = note: unresolved item `crate::ksl_lsp::tests::AnalysisResult` exists but is inaccessible

error[E0432]: unresolved imports `crate::ksl_async::AsyncType`, `crate::ksl_async::AsyncContext`
  --> src\ksl_typegen.rs:11:24
   |
11 | use crate::ksl_async::{AsyncType, AsyncContext};
   |                        ^^^^^^^^^  ^^^^^^^^^^^^
   |                        |          |
   |                        |          no `AsyncContext` in `ksl_async`
   |                        |          help: a similar name exists in the module: `AsyncConfig`
   |                        no `AsyncType` in `ksl_async`
   |
   = note: unresolved item `crate::ksl_refactor::tests::AsyncContext` exists but is inaccessible

error[E0432]: unresolved import `crate::ksl_contract::Contract`
 --> src\ksl_web3.rs:4:27
  |
4 | use crate::ksl_contract::{Contract, ContractState, ContractEvent};
  |                           ^^^^^^^^
  |                           |
  |                           no `Contract` in `ksl_contract`
  |                           help: a similar name exists in the module: `ContractId`
  |
  = help: consider importing one of these variants instead:
          crate::FuzzDomain::Contract
          crate::TypeMetadata::Contract
          crate::ksl_web3::Type::Contract

error[E0432]: unresolved imports `crate::ksl_async::AsyncContext`, `crate::ksl_async::AsyncCommand`
 --> src\ksl_web3.rs:6:24
  |
6 | use crate::ksl_async::{AsyncContext, AsyncCommand};
  |                        ^^^^^^^^^^^^  ^^^^^^^^^^^^ no `AsyncCommand` in `ksl_async`
  |                        |
  |                        no `AsyncContext` in `ksl_async`
  |                        help: a similar name exists in the module: `AsyncConfig`
  |
  = note: unresolved item `crate::ksl_typegen::tests::AsyncContext` exists but is inaccessible
  = note: unresolved item `crate::ksl_refactor::tests::AsyncCommand` exists but is inaccessible

error[E0432]: unresolved imports `crate::ksl_async::AsyncCommand`, `crate::ksl_async::AsyncContext`
 --> src\ksl_vscode.rs:9:24
  |
9 | use crate::ksl_async::{AsyncCommand, AsyncContext};
  |                        ^^^^^^^^^^^^  ^^^^^^^^^^^^
  |                        |             |
  |                        |             no `AsyncContext` in `ksl_async`
  |                        |             help: a similar name exists in the module: `AsyncConfig`
  |                        no `AsyncCommand` in `ksl_async`
  |
  = note: unresolved item `crate::ksl_web3::tests::AsyncCommand` exists but is inaccessible
  = note: unresolved item `crate::ksl_web3::tests::AsyncContext` exists but is inaccessible

error[E0432]: unresolved imports `crate::ksl_kapra_crypto::sign_dilithium`, `crate::ksl_kapra_crypto::verify_dilithium`, `crate::ksl_kapra_crypto::KeyPair`
   --> src\ksl_kapra_consensus.rs:901:31
    |
901 | use crate::ksl_kapra_crypto::{sign_dilithium, verify_dilithium, KeyPair};
    |                               ^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^  ^^^^^^^ no `KeyPair` in `ksl_kapra_crypto`
    |                               |               |
    |                               |               no `verify_dilithium` in `ksl_kapra_crypto`
    |                               no `sign_dilithium` in `ksl_kapra_crypto`
    |
    = note: unresolved item `crate::ksl_contract::tests::KeyPair` exists but is inaccessible

error[E0432]: unresolved import `crate::ksl_async::AsyncResult`
   --> src\ksl_kapra_consensus.rs:902:38
    |
902 | use crate::ksl_async::{AsyncRuntime, AsyncResult};
    |                                      ^^^^^^^^^^^ no `AsyncResult` in `ksl_async`
    |
    = note: unresolved item `crate::ksl_repl_server::tests::AsyncResult` exists but is inaccessible

error[E0432]: unresolved import `crate::ksl_async::AsyncResult`
 --> src\ksl_kapra_shard.rs:9:38
  |
9 | use crate::ksl_async::{AsyncRuntime, AsyncResult};
  |                                      ^^^^^^^^^^^ no `AsyncResult` in `ksl_async`
  |
  = note: unresolved item `crate::ksl_kapra_consensus::tests::AsyncResult` exists but is inaccessible

error[E0432]: unresolved import `crate::ksl_async::AsyncResult`
 --> src\ksl_kapra_validator.rs:9:38
  |
9 | use crate::ksl_async::{AsyncRuntime, AsyncResult};
  |                                      ^^^^^^^^^^^ no `AsyncResult` in `ksl_async`
  |
  = note: unresolved item `crate::ksl_kapra_shard::tests::AsyncResult` exists but is inaccessible

error[E0432]: unresolved import `crate::ksl_async::AsyncResult`
 --> src\ksl_package_version.rs:7:38
  |
7 | use crate::ksl_async::{AsyncRuntime, AsyncResult};
  |                                      ^^^^^^^^^^^ no `AsyncResult` in `ksl_async`
  |
  = note: unresolved item `crate::ksl_kapra_validator::tests::AsyncResult` exists but is inaccessible

error[E0432]: unresolved import `crate::ksl_module::ModuleFormat`
  --> src\ksl_bundler.rs:13:25
   |
13 | use crate::ksl_module::{ModuleFormat, ModuleSystem};
   |                         ^^^^^^^^^^^^ no `ModuleFormat` in `ksl_module`
   |
   = note: unresolved item `crate::ksl_deploy::tests::ModuleFormat` exists but is inaccessible

error[E0432]: unresolved import `crate::ksl_async::AsyncResult`
  --> src\ksl_bundler.rs:14:38
   |
14 | use crate::ksl_async::{AsyncRuntime, AsyncResult};
   |                                      ^^^^^^^^^^^ no `AsyncResult` in `ksl_async`
   |
   = note: unresolved item `crate::ksl_package_version::tests::AsyncResult` exists but is inaccessible

error[E0432]: unresolved imports `crate::ksl_async::AsyncContext`, `crate::ksl_async::AsyncCommand`
 --> src\ksl_dev_tools.rs:5:24
  |
5 | use crate::ksl_async::{AsyncContext, AsyncCommand};
  |                        ^^^^^^^^^^^^  ^^^^^^^^^^^^ no `AsyncCommand` in `ksl_async`
  |                        |
  |                        no `AsyncContext` in `ksl_async`
  |                        help: a similar name exists in the module: `AsyncConfig`
  |
  = note: unresolved item `crate::ksl_vscode::tests::AsyncContext` exists but is inaccessible
  = note: unresolved item `crate::ksl_vscode::tests::AsyncCommand` exists but is inaccessible

error[E0432]: unresolved import `crate::ksl_ast_transform::AstTransformer`
 --> src\ksl_doc_lsp.rs:7:41
  |
7 | use crate::ksl_ast_transform::{AstNode, AstTransformer};
  |                                         ^^^^^^^^^^^^^^ no `AstTransformer` in `ksl_ast_transform`
  |
  = note: unresolved item `crate::ksl_macros::tests::AstTransformer` exists but is inaccessible

error[E0432]: unresolved import `crate::ksl_async::AsyncResult`
 --> src\ksl_doc_lsp.rs:8:38
  |
8 | use crate::ksl_async::{AsyncRuntime, AsyncResult};
  |                                      ^^^^^^^^^^^ no `AsyncResult` in `ksl_async`
  |
  = note: unresolved item `crate::ksl_bundler::tests::AsyncResult` exists but is inaccessible

error[E0432]: unresolved import `crate::ksl_validator_keys::ValidatorKeys`
  --> src\ksl_fuzzer.rs:15:33
   |
15 | use crate::ksl_validator_keys::{ValidatorKeys, Signature};
   |                                 ^^^^^^^^^^^^^
   |                                 |
   |                                 no `ValidatorKeys` in `ksl_validator_keys`
   |                                 help: a similar name exists in the module: `ValidatorKeyPair`
   |
   = note: unresolved item `crate::ksl_benchmark::tests::ValidatorKeys` exists but is inaccessible

error[E0432]: unresolved import `crate::ksl_sandbox::run_sandbox_async`
 --> src\ksl_interpreter.rs:9:50
  |
9 | use crate::ksl_sandbox::{Sandbox, SandboxPolicy, run_sandbox_async};
  |                                                  ^^^^^^^^^^^^^^^^^ no `run_sandbox_async` in `ksl_sandbox`
  |
  = note: unresolved item `crate::ksl_deploy::tests::run_sandbox_async` exists but is inaccessible

error[E0432]: unresolved import `crate::ksl_async::AsyncResult`
  --> src\ksl_interpreter.rs:10:38
   |
10 | use crate::ksl_async::{AsyncRuntime, AsyncResult};
   |                                      ^^^^^^^^^^^ no `AsyncResult` in `ksl_async`
   |
   = note: unresolved item `crate::ksl_doc_lsp::tests::AsyncResult` exists but is inaccessible

error[E0432]: unresolved imports `crate::ksl_contract::Contract`, `crate::ksl_contract::AbiSchema`
  --> src\ksl_genesis.rs:10:27
   |
10 | use crate::ksl_contract::{Contract, ContractAbi, AbiSchema};
   |                           ^^^^^^^^               ^^^^^^^^^ no `AbiSchema` in `ksl_contract`
   |                           |
   |                           no `Contract` in `ksl_contract`
   |                           help: a similar name exists in the module: `ContractId`
   |
   = help: consider importing one of these variants instead:
           crate::FuzzDomain::Contract
           crate::TypeMetadata::Contract
           crate::ksl_web3::Type::Contract

error[E0432]: unresolved imports `crate::ksl_package::Package`, `crate::ksl_package::PackageConfig`
  --> src\ksl_genesis.rs:11:26
   |
11 | use crate::ksl_package::{Package, PackageConfig};
   |                          ^^^^^^^  ^^^^^^^^^^^^^
   |                          |        |
   |                          |        no `PackageConfig` in `ksl_package`
   |                          |        help: a similar name exists in the module: `PackageInfo`
   |                          no `Package` in `ksl_package`
   |
   = help: consider importing one of these structs instead:
           crate::Package
           crate::ksl_community::Package
           crate::ksl_dep_audit::Package
   = note: unresolved item `crate::ksl_scaffold::tests::PackageConfig` exists but is inaccessible

error[E0432]: unresolved import `crate::ksl_validator_keys::ValidatorKeys`
  --> src\ksl_test.rs:38:33
   |
38 | use crate::ksl_validator_keys::{ValidatorKeys, Signature};
   |                                 ^^^^^^^^^^^^^
   |                                 |
   |                                 no `ValidatorKeys` in `ksl_validator_keys`
   |                                 help: a similar name exists in the module: `ValidatorKeyPair`
   |
   = note: unresolved item `crate::ksl_fuzzer::tests::ValidatorKeys` exists but is inaccessible

error[E0432]: unresolved imports `crate::ksl_async::AsyncContext`, `crate::ksl_async::AsyncCommand`
  --> src\ksl_bench.rs:13:24
   |
13 | use crate::ksl_async::{AsyncContext, AsyncCommand};
   |                        ^^^^^^^^^^^^  ^^^^^^^^^^^^ no `AsyncCommand` in `ksl_async`
   |                        |
   |                        no `AsyncContext` in `ksl_async`
   |                        help: a similar name exists in the module: `AsyncConfig`
   |
   = note: unresolved item `crate::ksl_dev_tools::tests::AsyncContext` exists but is inaccessible
   = note: unresolved item `crate::ksl_dev_tools::tests::AsyncCommand` exists but is inaccessible

error[E0432]: unresolved import `crate::ksl_async::AsyncResult`
 --> src\ksl_package_publish.rs:7:38
  |
7 | use crate::ksl_async::{AsyncRuntime, AsyncResult};
  |                                      ^^^^^^^^^^^ no `AsyncResult` in `ksl_async`
  |
  = note: unresolved item `crate::ksl_interpreter::tests::AsyncResult` exists but is inaccessible

error[E0432]: unresolved import `crate::ksl_validator_keys::ValidatorKeys`
  --> src\ksl_package_publish.rs:20:33
   |
20 | use crate::ksl_validator_keys::{ValidatorKeys, Signature};
   |                                 ^^^^^^^^^^^^^
   |                                 |
   |                                 no `ValidatorKeys` in `ksl_validator_keys`
   |                                 help: a similar name exists in the module: `ValidatorKeyPair`
   |
   = note: unresolved item `crate::ksl_test::tests::ValidatorKeys` exists but is inaccessible

error[E0432]: unresolved imports `crate::ksl_package::PackageLoader`, `crate::ksl_package::PackageConfig`
  --> src\ksl_package_publish.rs:23:26
   |
23 | use crate::ksl_package::{PackageLoader, PackageConfig};
   |                          ^^^^^^^^^^^^^  ^^^^^^^^^^^^^
   |                          |              |
   |                          |              no `PackageConfig` in `ksl_package`
   |                          |              help: a similar name exists in the module: `PackageInfo`
   |                          no `PackageLoader` in `ksl_package`
   |
   = note: unresolved item `crate::ksl_genesis::tests::PackageConfig` exists but is inaccessible

error[E0432]: unresolved import `crate::ksl_validator_keys::ValidatorKeys`
  --> src\ksl_ci.rs:21:33
   |
21 | use crate::ksl_validator_keys::{ValidatorKeys, Signature};
   |                                 ^^^^^^^^^^^^^
   |                                 |
   |                                 no `ValidatorKeys` in `ksl_validator_keys`
   |                                 help: a similar name exists in the module: `ValidatorKeyPair`
   |
   = note: unresolved item `crate::ksl_package_publish::tests::ValidatorKeys` exists but is inaccessible

error[E0432]: unresolved import `crate::ksl_async::AsyncResult`
  --> src\ksl_kapra_scheduler.rs:11:38
   |
11 | use crate::ksl_async::{AsyncRuntime, AsyncResult};
   |                                      ^^^^^^^^^^^ no `AsyncResult` in `ksl_async`
   |
   = note: unresolved item `crate::ksl_package_publish::tests::AsyncResult` exists but is inaccessible

error[E0432]: unresolved imports `crate::ksl_async::AsyncContext`, `crate::ksl_async::AsyncCommand`
 --> src\ksl_embedded.rs:5:24
  |
5 | use crate::ksl_async::{AsyncContext, AsyncCommand};
  |                        ^^^^^^^^^^^^  ^^^^^^^^^^^^ no `AsyncCommand` in `ksl_async`
  |                        |
  |                        no `AsyncContext` in `ksl_async`
  |                        help: a similar name exists in the module: `AsyncConfig`
  |
  = note: unresolved item `crate::ksl_bench::tests::AsyncContext` exists but is inaccessible
  = note: unresolved item `crate::ksl_bench::tests::AsyncCommand` exists but is inaccessible

error[E0432]: unresolved imports `crate::ksl_stdlib_net::Networking`, `crate::ksl_stdlib_net::HttpRequest`, `crate::ksl_stdlib_net::HttpResponse`, `crate::ksl_stdlib_net::WebSocket`
 --> src\ksl_community.rs:4:29
  |
4 | use crate::ksl_stdlib_net::{Networking, HttpRequest, HttpResponse, WebSocket};
  |                             ^^^^^^^^^^  ^^^^^^^^^^^  ^^^^^^^^^^^^  ^^^^^^^^^
  |                             |           |            |             |
  |                             |           |            |             no `WebSocket` in `ksl_stdlib_net`
  |                             |           |            |             help: a similar name exists in the module: `UdpSocket`
  |                             |           |            no `HttpResponse` in `ksl_stdlib_net`
  |                             |           no `HttpRequest` in `ksl_stdlib_net`
  |                             no `Networking` in `ksl_stdlib_net`
  |
  = note: unresolved item `crate::ksl_web3::tests::Networking` exists but is inaccessible
  = help: consider importing one of these variants instead:
          crate::Type::HttpRequest
          crate::ksl_analyzer::Type::HttpRequest
  = help: consider importing one of these items instead:
          crate::HttpResponse
          crate::Type::HttpResponse
          crate::ksl_analyzer::Type::HttpResponse
  = help: consider importing this variant instead:
          crate::NetworkProtocol::WebSocket

error[E0432]: unresolved imports `crate::ksl_cli::CliCommand`, `crate::ksl_cli::CliContext`
 --> src\ksl_community.rs:5:22
  |
5 | use crate::ksl_cli::{CliCommand, CliContext};
  |                      ^^^^^^^^^^  ^^^^^^^^^^ no `CliContext` in `ksl_cli`
  |                      |
  |                      no `CliCommand` in `ksl_cli`
  |
  = note: unresolved item `crate::ksl_dev_tools::tests::CliCommand` exists but is inaccessible

error[E0432]: unresolved imports `crate::ksl_async::AsyncContext`, `crate::ksl_async::AsyncCommand`
 --> src\ksl_community.rs:6:24
  |
6 | use crate::ksl_async::{AsyncContext, AsyncCommand};
  |                        ^^^^^^^^^^^^  ^^^^^^^^^^^^ no `AsyncCommand` in `ksl_async`
  |                        |
  |                        no `AsyncContext` in `ksl_async`
  |                        help: a similar name exists in the module: `AsyncConfig`
  |
  = note: unresolved item `crate::ksl_embedded::tests::AsyncContext` exists but is inaccessible
  = note: unresolved item `crate::ksl_embedded::tests::AsyncCommand` exists but is inaccessible

error[E0432]: unresolved imports `crate::ksl_security::SecurityCheck`, `crate::ksl_security::SecurityLevel`, `crate::ksl_security::SecurityContext`
 --> src\ksl_dep_audit.rs:5:27
  |
5 | use crate::ksl_security::{SecurityCheck, SecurityLevel, SecurityContext};
  |                           ^^^^^^^^^^^^^  ^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^
  |                           |              |              |
  |                           |              |              no `SecurityContext` in `ksl_security`
  |                           |              |              help: a similar name exists in the module: `SecurityConfig`
  |                           |              no `SecurityLevel` in `ksl_security`
  |                           no `SecurityCheck` in `ksl_security`
  |
  = note: unresolved item `crate::ksl_contract::tests::SecurityCheck` exists but is inaccessible

error[E0432]: unresolved imports `crate::ksl_async::AsyncContext`, `crate::ksl_async::AsyncCommand`
 --> src\ksl_dep_audit.rs:6:24
  |
6 | use crate::ksl_async::{AsyncContext, AsyncCommand};
  |                        ^^^^^^^^^^^^  ^^^^^^^^^^^^ no `AsyncCommand` in `ksl_async`
  |                        |
  |                        no `AsyncContext` in `ksl_async`
  |                        help: a similar name exists in the module: `AsyncConfig`
  |
  = note: unresolved item `crate::ksl_community::tests::AsyncContext` exists but is inaccessible
  = note: unresolved item `crate::ksl_community::tests::AsyncCommand` exists but is inaccessible

error[E0432]: unresolved imports `crate::kapra_vm::VmState`, `crate::kapra_vm::VmError`
 --> src\ksl_runtime_monitor.rs:5:32
  |
5 | use crate::kapra_vm::{KapraVM, VmState, VmError};
  |                                ^^^^^^^  ^^^^^^^ no `VmError` in `kapra_vm`
  |                                |
  |                                no `VmState` in `kapra_vm`
  |
  = note: unresolved item `crate::ksl_embedded::tests::VmState` exists but is inaccessible
  = note: unresolved item `crate::ksl_embedded::tests::VmError` exists but is inaccessible

error[E0432]: unresolved imports `crate::ksl_async::AsyncContext`, `crate::ksl_async::AsyncCommand`
 --> src\ksl_runtime_monitor.rs:6:24
  |
6 | use crate::ksl_async::{AsyncContext, AsyncCommand};
  |                        ^^^^^^^^^^^^  ^^^^^^^^^^^^ no `AsyncCommand` in `ksl_async`
  |                        |
  |                        no `AsyncContext` in `ksl_async`
  |                        help: a similar name exists in the module: `AsyncConfig`
  |
  = note: unresolved item `crate::ksl_dep_audit::tests::AsyncContext` exists but is inaccessible
  = note: unresolved item `crate::ksl_dep_audit::tests::AsyncCommand` exists but is inaccessible

error[E0432]: unresolved imports `crate::ksl_ast_transform::AstTransformer`, `crate::ksl_ast_transform::TransformError`
 --> src\ksl_migrate.rs:6:32
  |
6 | use crate::ksl_ast_transform::{AstTransformer, TransformError};
  |                                ^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^ no `TransformError` in `ksl_ast_transform`
  |                                |
  |                                no `AstTransformer` in `ksl_ast_transform`
  |
  = note: unresolved item `crate::ksl_doc_lsp::tests::AstTransformer` exists but is inaccessible
  = note: unresolved item `crate::ksl_interpreter::tests::TransformError` exists but is inaccessible

error[E0432]: unresolved imports `crate::ksl_async::AsyncContext`, `crate::ksl_async::AsyncCommand`
  --> src\ksl_migrate.rs:10:24
   |
10 | use crate::ksl_async::{AsyncContext, AsyncCommand};
   |                        ^^^^^^^^^^^^  ^^^^^^^^^^^^ no `AsyncCommand` in `ksl_async`
   |                        |
   |                        no `AsyncContext` in `ksl_async`
   |                        help: a similar name exists in the module: `AsyncConfig`
   |
   = note: unresolved item `crate::ksl_runtime_monitor::tests::AsyncContext` exists but is inaccessible
   = note: unresolved item `crate::ksl_runtime_monitor::tests::AsyncCommand` exists but is inaccessible

error[E0432]: unresolved imports `crate::ksl_async::AsyncContext`, `crate::ksl_async::AsyncCommand`
 --> src\ksl_template.rs:9:24
  |
9 | use crate::ksl_async::{AsyncContext, AsyncCommand};
  |                        ^^^^^^^^^^^^  ^^^^^^^^^^^^ no `AsyncCommand` in `ksl_async`
  |                        |
  |                        no `AsyncContext` in `ksl_async`
  |                        help: a similar name exists in the module: `AsyncConfig`
  |
  = note: unresolved item `crate::ksl_migrate::tests::AsyncContext` exists but is inaccessible
  = note: unresolved item `crate::ksl_migrate::tests::AsyncCommand` exists but is inaccessible

error[E0432]: unresolved import `crate::ksl_config::ProjectConfig`
 --> src\ksl_project.rs:5:25
  |
5 | use crate::ksl_config::{ProjectConfig, ConfigManager};
  |                         ^^^^^^^^^^^^^ no `ProjectConfig` in `ksl_config`
  |
  = note: unresolved item `crate::ksl_template::tests::ProjectConfig` exists but is inaccessible

error[E0432]: unresolved imports `crate::ksl_async::AsyncContext`, `crate::ksl_async::AsyncCommand`
 --> src\ksl_project.rs:6:24
  |
6 | use crate::ksl_async::{AsyncContext, AsyncCommand};
  |                        ^^^^^^^^^^^^  ^^^^^^^^^^^^ no `AsyncCommand` in `ksl_async`
  |                        |
  |                        no `AsyncContext` in `ksl_async`
  |                        help: a similar name exists in the module: `AsyncConfig`
  |
  = note: unresolved item `crate::ksl_template::tests::AsyncContext` exists but is inaccessible
  = note: unresolved item `crate::ksl_template::tests::AsyncCommand` exists but is inaccessible

error[E0432]: unresolved imports `crate::ksl_ast_transform::transform`, `crate::ksl_ast_transform::TransformRule`, `crate::ksl_ast_transform::AstTransformer`
 --> src\ksl_transpiler.rs:7:32
  |
7 | use crate::ksl_ast_transform::{transform, TransformRule, AstTransformer};
  |                                ^^^^^^^^^  ^^^^^^^^^^^^^  ^^^^^^^^^^^^^^ no `AstTransformer` in `ksl_ast_transform`
  |                                |          |
  |                                |          no `TransformRule` in `ksl_ast_transform`
  |                                |          help: a similar name exists in the module: `TransformPass`
  |                                no `transform` in `ksl_ast_transform`
  |
  = note: unresolved item `crate::ksl_refactor::tests::transform` exists but is inaccessible
  = note: unresolved item `crate::ksl_migrate::tests::AstTransformer` exists but is inaccessible

error[E0432]: unresolved import `crate::ksl_async::AsyncResult`
 --> src\ksl_transpiler.rs:9:38
  |
9 | use crate::ksl_async::{AsyncRuntime, AsyncResult};
  |                                      ^^^^^^^^^^^ no `AsyncResult` in `ksl_async`
  |
  = note: unresolved item `crate::ksl_kapra_scheduler::tests::AsyncResult` exists but is inaccessible

error[E0432]: unresolved import `crate::ksl_async::AsyncResult`
 --> src\ksl_testgen.rs:9:38
  |
9 | use crate::ksl_async::{AsyncRuntime, AsyncResult};
  |                                      ^^^^^^^^^^^ no `AsyncResult` in `ksl_async`
  |
  = note: unresolved item `crate::ksl_transpiler::tests::AsyncResult` exists but is inaccessible

error[E0432]: unresolved import `crate::ksl_metrics::MetricType`
  --> src\ksl_profile.rs:11:44
   |
11 | use crate::ksl_metrics::{MetricsCollector, MetricType};
   |                                            ^^^^^^^^^^ no `MetricType` in `ksl_metrics`
   |
   = note: unresolved item `crate::ksl_bench::tests::MetricType` exists but is inaccessible

error[E0432]: unresolved import `crate::ksl_async::AsyncResult`
  --> src\ksl_profile.rs:12:38
   |
12 | use crate::ksl_async::{AsyncRuntime, AsyncResult};
   |                                      ^^^^^^^^^^^ no `AsyncResult` in `ksl_async`
   |
   = note: unresolved item `crate::ksl_testgen::tests::AsyncResult` exists but is inaccessible

error[E0432]: unresolved import `crate::ksl_sandbox::run_sandbox_async`
 --> src\ksl_security.rs:7:50
  |
7 | use crate::ksl_sandbox::{Sandbox, SandboxPolicy, run_sandbox_async};
  |                                                  ^^^^^^^^^^^^^^^^^ no `run_sandbox_async` in `ksl_sandbox`
  |
  = note: unresolved item `crate::ksl_interpreter::tests::run_sandbox_async` exists but is inaccessible

error[E0432]: unresolved import `crate::ksl_async::AsyncResult`
 --> src\ksl_security.rs:9:38
  |
9 | use crate::ksl_async::{AsyncRuntime, AsyncResult};
  |                                      ^^^^^^^^^^^ no `AsyncResult` in `ksl_async`
  |
  = note: unresolved item `crate::ksl_profile::tests::AsyncResult` exists but is inaccessible

error: cannot find macro `json` in this scope
    --> src\ksl_fuzzer.rs:1071:17
     |
1071 |                 json!({
     |                 ^^^^
     |
help: consider importing this macro
     |
1    + use serde_json::json;
     |

error: cannot find macro `json` in this scope
    --> src\ksl_fuzzer.rs:1059:17
     |
1059 |                 json!({
     |                 ^^^^
     |
help: consider importing this macro
     |
1    + use serde_json::json;
     |

error: cannot find macro `json` in this scope
    --> src\ksl_fuzzer.rs:1047:17
     |
1047 |                 json!({
     |                 ^^^^
     |
help: consider importing this macro
     |
1    + use serde_json::json;
     |

error: cannot find macro `json` in this scope
   --> src\ksl_hot_reload.rs:197:9
    |
197 |         json!({
    |         ^^^^
    |
help: consider importing this macro
    |
6   + use serde_json::json;
    |

error[E0422]: cannot find struct, variant or union type `Attribute` in this scope
   --> src\ksl_checker.rs:999:15
    |
999 |             &[Attribute { name: "async".to_string() }],
    |               ^^^^^^^^^ not found in this scope
    |
help: consider importing one of these items
    |
658 +     use crate::Attribute;
    |
658 +     use crate::Expr::Attribute;
    |
658 +     use inkwell::attributes::Attribute;
    |
658 +     use syn::Attribute;
    |

error[E0422]: cannot find struct, variant or union type `Attribute` in this scope
    --> src\ksl_checker.rs:1019:15
     |
1019 |             &[Attribute { name: "async".to_string() }],
     |               ^^^^^^^^^ not found in this scope
     |
help: consider importing one of these items
     |
658  +     use crate::Attribute;
     |
658  +     use crate::Expr::Attribute;
     |
658  +     use inkwell::attributes::Attribute;
     |
658  +     use syn::Attribute;
     |

error[E0422]: cannot find struct, variant or union type `Parameter` in this scope
   --> src\ksl_llvm.rs:789:17
    |
789 |                 Parameter {
    |                 ^^^^^^^^^ not found in this scope
    |
help: consider importing this struct through its public re-export
    |
717 +     use crate::Parameter;
    |

error[E0422]: cannot find struct, variant or union type `Parameter` in this scope
   --> src\ksl_llvm.rs:793:17
    |
793 |                 Parameter {
    |                 ^^^^^^^^^ not found in this scope
    |
help: consider importing this struct through its public re-export
    |
717 +     use crate::Parameter;
    |

error[E0422]: cannot find struct, variant or union type `Parameter` in this scope
   --> src\ksl_llvm.rs:822:17
    |
822 |                 Parameter {
    |                 ^^^^^^^^^ not found in this scope
    |
help: consider importing this struct through its public re-export
    |
717 +     use crate::Parameter;
    |

error[E0422]: cannot find struct, variant or union type `Parameter` in this scope
   --> src\ksl_llvm.rs:826:17
    |
826 |                 Parameter {
    |                 ^^^^^^^^^ not found in this scope
    |
help: consider importing this struct through its public re-export
    |
717 +     use crate::Parameter;
    |

error[E0425]: cannot find value `metadata` in this scope
   --> src\ksl_scaffold.rs:753:32
    |
753 |         if let Some(policy) = &metadata.sandbox_policy {
    |                                ^^^^^^^^ not found in this scope
    |
help: consider importing one of these functions
    |
1   + use std::fs::metadata;
    |
1   + use std::ptr::metadata;
    |
1   + use core::ptr::metadata;
    |
1   + use tokio::fs::metadata;
    |

error[E0433]: failed to resolve: could not find `Section` in `wasmparser`
   --> src\ksl_wasm.rs:665:35
    |
665 |             if let Ok(wasmparser::Section::Custom(custom)) = section {
    |                                   ^^^^^^^ could not find `Section` in `wasmparser`
    |
help: consider importing one of these items
    |
520 +     use inkwell::object_file::Section;
    |
520 +     use wasm_encoder::Section;
    |
help: if you import `Section`, refer to it directly
    |
665 -             if let Ok(wasmparser::Section::Custom(custom)) = section {
665 +             if let Ok(Section::Custom(custom)) = section {
    |

error[E0425]: cannot find value `DST` in this scope
    --> src\kapra_vm.rs:2460:46
     |
2460 |         let sig = sk.sign(message, &[], &pk, DST);
     |                                              ^^^ not found in this scope
     |
note: constant `crate::ksl_kapra_crypto::DST` exists but is inaccessible
    --> src\ksl_kapra_crypto.rs:1211:1
     |
1211 | const DST: &[u8] = b"KSL_BLS_SIG";
     | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ not accessible

error[E0433]: failed to resolve: use of undeclared type `BinaryOperator`
   --> src\ksl_ast_transform.rs:334:33
    |
334 | ...                   op: BinaryOperator::Add,
    |                           ^^^^^^^^^^^^^^ use of undeclared type `BinaryOperator`
    |
help: consider importing this enum through its public re-export
    |
320 +     use crate::BinaryOperator;
    |

error[E0422]: cannot find struct, variant or union type `MatchArm` in this scope
   --> src\ksl_ast_transform.rs:369:21
    |
369 |                     MatchArm {
    |                     ^^^^^^^^ not found in this scope
    |
help: consider importing this struct through its public re-export
    |
320 +     use crate::MatchArm;
    |

error[E0422]: cannot find struct, variant or union type `MatchArm` in this scope
   --> src\ksl_ast_transform.rs:472:29
    |
472 | ...                   MatchArm {
    |                       ^^^^^^^^ not found in this scope
    |
help: consider importing this struct through its public re-export
    |
320 +     use crate::MatchArm;
    |

error[E0433]: failed to resolve: use of undeclared type `NamedTempFile`
   --> src\ksl_contract_verifier.rs:952:29
    |
952 |         let mut temp_file = NamedTempFile::new_in(&temp_dir).unwrap();
    |                             ^^^^^^^^^^^^^ use of undeclared type `NamedTempFile`
    |
help: consider importing this struct
    |
805 +     use tempfile::NamedTempFile;
    |

error[E0433]: failed to resolve: use of undeclared type `Value`
   --> src\ksl_stdlib_net.rs:841:56
    |
841 | ...   let response = stdlib.execute("http.get", vec![Value::String("https://httpbin.org/get".to_string())]).aw...
    |                                                      ^^^^^ use of undeclared type `Value`
    |
help: consider importing one of these items
    |
803 +     use crate::Value;
    |
803 +     use crate::ksl_interpreter::Value;
    |
803 +     use crate::ksl_stdlib::Value;
    |
803 +     use crate::ksl_value::Value;
    |
      and 10 other candidates

error[E0433]: failed to resolve: use of undeclared type `Value`
   --> src\ksl_stdlib_net.rs:844:32
    |
844 |         assert!(matches!(body, Value::String(s) if s.contains("httpbin.org")));
    |                                ^^^^^ use of undeclared type `Value`
    |
help: consider importing one of these items
    |
803 +     use crate::Value;
    |
803 +     use crate::ksl_interpreter::Value;
    |
803 +     use crate::ksl_stdlib::Value;
    |
803 +     use crate::ksl_value::Value;
    |
      and 10 other candidates

error[E0433]: failed to resolve: use of undeclared type `Value`
   --> src\ksl_stdlib_net.rs:848:13
    |
848 |             Value::String("https://httpbin.org/post".to_string()),
    |             ^^^^^ use of undeclared type `Value`
    |
help: consider importing one of these items
    |
803 +     use crate::Value;
    |
803 +     use crate::ksl_interpreter::Value;
    |
803 +     use crate::ksl_stdlib::Value;
    |
803 +     use crate::ksl_value::Value;
    |
      and 10 other candidates

error[E0433]: failed to resolve: use of undeclared type `Value`
   --> src\ksl_stdlib_net.rs:849:13
    |
849 |             Value::String("test data".to_string()),
    |             ^^^^^ use of undeclared type `Value`
    |
help: consider importing one of these items
    |
803 +     use crate::Value;
    |
803 +     use crate::ksl_interpreter::Value;
    |
803 +     use crate::ksl_stdlib::Value;
    |
803 +     use crate::ksl_value::Value;
    |
      and 10 other candidates

error[E0433]: failed to resolve: use of undeclared type `Value`
   --> src\ksl_stdlib_net.rs:853:32
    |
853 |         assert!(matches!(body, Value::String(s) if s.contains("test data")));
    |                                ^^^^^ use of undeclared type `Value`
    |
help: consider importing one of these items
    |
803 +     use crate::Value;
    |
803 +     use crate::ksl_interpreter::Value;
    |
803 +     use crate::ksl_stdlib::Value;
    |
803 +     use crate::ksl_value::Value;
    |
      and 10 other candidates

error[E0433]: failed to resolve: use of undeclared type `Value`
   --> src\ksl_stdlib_net.rs:863:13
    |
863 |             Value::String("localhost".to_string()),
    |             ^^^^^ use of undeclared type `Value`
    |
help: consider importing one of these items
    |
803 +     use crate::Value;
    |
803 +     use crate::ksl_interpreter::Value;
    |
803 +     use crate::ksl_stdlib::Value;
    |
803 +     use crate::ksl_value::Value;
    |
      and 10 other candidates

error[E0433]: failed to resolve: use of undeclared type `Value`
   --> src\ksl_stdlib_net.rs:864:13
    |
864 |             Value::U32(80),
    |             ^^^^^ use of undeclared type `Value`
    |
help: consider importing one of these items
    |
803 +     use crate::Value;
    |
803 +     use crate::ksl_interpreter::Value;
    |
803 +     use crate::ksl_stdlib::Value;
    |
803 +     use crate::ksl_value::Value;
    |
      and 10 other candidates

error[E0433]: failed to resolve: use of undeclared type `Value`
   --> src\ksl_stdlib_net.rs:868:32
    |
868 |         assert!(matches!(port, Value::U32(_)));
    |                                ^^^^^ use of undeclared type `Value`
    |
help: consider importing one of these items
    |
803 +     use crate::Value;
    |
803 +     use crate::ksl_interpreter::Value;
    |
803 +     use crate::ksl_stdlib::Value;
    |
803 +     use crate::ksl_value::Value;
    |
      and 10 other candidates

error[E0433]: failed to resolve: use of undeclared type `Value`
   --> src\ksl_stdlib_net.rs:877:25
    |
877 |         let data = vec![Value::U32(1), Value::U32(2), Value::U32(3)];
    |                         ^^^^^ use of undeclared type `Value`
    |
help: consider importing one of these items
    |
803 +     use crate::Value;
    |
803 +     use crate::ksl_interpreter::Value;
    |
803 +     use crate::ksl_stdlib::Value;
    |
803 +     use crate::ksl_value::Value;
    |
      and 10 other candidates

error[E0433]: failed to resolve: use of undeclared type `Value`
   --> src\ksl_stdlib_net.rs:877:40
    |
877 |         let data = vec![Value::U32(1), Value::U32(2), Value::U32(3)];
    |                                        ^^^^^ use of undeclared type `Value`
    |
help: consider importing one of these items
    |
803 +     use crate::Value;
    |
803 +     use crate::ksl_interpreter::Value;
    |
803 +     use crate::ksl_stdlib::Value;
    |
803 +     use crate::ksl_value::Value;
    |
      and 10 other candidates

error[E0433]: failed to resolve: use of undeclared type `Value`
   --> src\ksl_stdlib_net.rs:877:55
    |
877 |         let data = vec![Value::U32(1), Value::U32(2), Value::U32(3)];
    |                                                       ^^^^^ use of undeclared type `Value`
    |
help: consider importing one of these items
    |
803 +     use crate::Value;
    |
803 +     use crate::ksl_interpreter::Value;
    |
803 +     use crate::ksl_stdlib::Value;
    |
803 +     use crate::ksl_value::Value;
    |
      and 10 other candidates

error[E0433]: failed to resolve: use of undeclared type `Value`
   --> src\ksl_stdlib_net.rs:879:13
    |
879 |             Value::String("localhost".to_string()),
    |             ^^^^^ use of undeclared type `Value`
    |
help: consider importing one of these items
    |
803 +     use crate::Value;
    |
803 +     use crate::ksl_interpreter::Value;
    |
803 +     use crate::ksl_stdlib::Value;
    |
803 +     use crate::ksl_value::Value;
    |
      and 10 other candidates

error[E0433]: failed to resolve: use of undeclared type `Value`
   --> src\ksl_stdlib_net.rs:880:13
    |
880 |             Value::U32(12345),
    |             ^^^^^ use of undeclared type `Value`
    |
help: consider importing one of these items
    |
803 +     use crate::Value;
    |
803 +     use crate::ksl_interpreter::Value;
    |
803 +     use crate::ksl_stdlib::Value;
    |
803 +     use crate::ksl_value::Value;
    |
      and 10 other candidates

error[E0433]: failed to resolve: use of undeclared type `Value`
   --> src\ksl_stdlib_net.rs:881:13
    |
881 |             Value::Array(data, 3),
    |             ^^^^^ use of undeclared type `Value`
    |
help: consider importing one of these items
    |
803 +     use crate::Value;
    |
803 +     use crate::ksl_interpreter::Value;
    |
803 +     use crate::ksl_stdlib::Value;
    |
803 +     use crate::ksl_value::Value;
    |
      and 10 other candidates

error[E0433]: failed to resolve: use of undeclared type `Value`
   --> src\ksl_stdlib_net.rs:885:38
    |
885 |         assert!(matches!(bytes_sent, Value::U32(3)));
    |                                      ^^^^^ use of undeclared type `Value`
    |
help: consider importing one of these items
    |
803 +     use crate::Value;
    |
803 +     use crate::ksl_interpreter::Value;
    |
803 +     use crate::ksl_stdlib::Value;
    |
803 +     use crate::ksl_value::Value;
    |
      and 10 other candidates

error[E0433]: failed to resolve: use of undeclared type `KapraVM`
   --> src\ksl_kapra_consensus.rs:819:22
    |
819 |         let mut vm = KapraVM::new(1000, 1000, false);
    |                      ^^^^^^^ use of undeclared type `KapraVM`
    |
help: consider importing one of these structs
    |
753 +     use crate::KapraVM;
    |
753 +     use crate::ksl_dev_tools::KapraVM;
    |
753 +     use crate::ksl_game::KapraVM;
    |
753 +     use crate::ksl_iot::KapraVM;
    |
      and 4 other candidates

error[E0433]: failed to resolve: use of undeclared type `KapraVM`
   --> src\ksl_kapra_consensus.rs:841:22
    |
841 |         let mut vm = KapraVM::new(1000, 100, false);
    |                      ^^^^^^^ use of undeclared type `KapraVM`
    |
help: consider importing one of these structs
    |
753 +     use crate::KapraVM;
    |
753 +     use crate::ksl_dev_tools::KapraVM;
    |
753 +     use crate::ksl_game::KapraVM;
    |
753 +     use crate::ksl_iot::KapraVM;
    |
      and 4 other candidates

error[E0433]: failed to resolve: use of undeclared type `Type`
   --> src\ksl_doc_lsp.rs:895:26
    |
895 |             return_type: Type::Unit,
    |                          ^^^^ use of undeclared type `Type`
    |
help: consider importing one of these items
    |
802 +     use crate::Type;
    |
802 +     use crate::ksl_analyzer::Type;
    |
802 +     use crate::ksl_dev_tools::Type;
    |
802 +     use crate::ksl_game::Type;
    |
      and 15 other candidates

error[E0422]: cannot find struct, variant or union type `ContractParameter` in this scope
    --> src\ksl_fuzzer.rs:1831:33
     |
1831 | ...                   ContractParameter {
     |                       ^^^^^^^^^^^^^^^^^ not found in this scope

error[E0422]: cannot find struct, variant or union type `ContractFunction` in this scope
    --> src\ksl_genesis.rs:1134:37
     |
1134 |         contract.abi.functions.push(ContractFunction {
     |                                     ^^^^^^^^^^^^^^^^ not found in this scope
     |
help: consider importing this struct through its public re-export
     |
1054 +     use crate::ContractFunction;
     |

error[E0422]: cannot find struct, variant or union type `ContractFunction` in this scope
    --> src\ksl_genesis.rs:1140:37
     |
1140 |         contract.abi.functions.push(ContractFunction {
     |                                     ^^^^^^^^^^^^^^^^ not found in this scope
     |
help: consider importing this struct through its public re-export
     |
1054 +     use crate::ContractFunction;
     |

error[E0422]: cannot find struct, variant or union type `ContractFunction` in this scope
    --> src\ksl_genesis.rs:1212:37
     |
1212 |         contract.abi.functions.push(ContractFunction {
     |                                     ^^^^^^^^^^^^^^^^ not found in this scope
     |
help: consider importing this struct through its public re-export
     |
1054 +     use crate::ContractFunction;
     |

error[E0422]: cannot find struct, variant or union type `ContractFunction` in this scope
    --> src\ksl_genesis.rs:1231:37
     |
1231 |         contract.abi.functions.push(ContractFunction {
     |                                     ^^^^^^^^^^^^^^^^ not found in this scope
     |
help: consider importing this struct through its public re-export
     |
1054 +     use crate::ContractFunction;
     |

error[E0425]: cannot find function `tempdir` in this scope
    --> src\ksl_genesis.rs:1266:24
     |
1266 |         let temp_dir = tempdir().unwrap();
     |                        ^^^^^^^ not found in this scope
     |
help: consider importing this function
     |
1054 +     use tempfile::tempdir;
     |

error[E0659]: `SecretKey` is ambiguous
    --> src\ksl_kapra_crypto.rs:1501:18
     |
1501 |         let sk = SecretKey::key_gen(ikm);
     |                  ^^^^^^^^^ ambiguous name
     |
     = note: ambiguous because of multiple glob imports of a name in the same module
note: `SecretKey` could refer to the type alias imported here
    --> src\ksl_kapra_crypto.rs:1473:9
     |
1473 |     use super::*;
     |         ^^^^^^^^
     = help: consider adding an explicit import of `SecretKey` to disambiguate
note: `SecretKey` could also refer to the struct imported here
    --> src\ksl_kapra_crypto.rs:1474:9
     |
1474 |     use blst::min_pk::*;
     |         ^^^^^^^^^^^^^^^
     = help: consider adding an explicit import of `SecretKey` to disambiguate

error[E0659]: `SecretKey` is ambiguous
    --> src\ksl_kapra_crypto.rs:1539:18
     |
1539 |         let sk = SecretKey::key_gen(ikm);
     |                  ^^^^^^^^^ ambiguous name
     |
     = note: ambiguous because of multiple glob imports of a name in the same module
note: `SecretKey` could refer to the type alias imported here
    --> src\ksl_kapra_crypto.rs:1473:9
     |
1473 |     use super::*;
     |         ^^^^^^^^
     = help: consider adding an explicit import of `SecretKey` to disambiguate
note: `SecretKey` could also refer to the struct imported here
    --> src\ksl_kapra_crypto.rs:1474:9
     |
1474 |     use blst::min_pk::*;
     |         ^^^^^^^^^^^^^^^
     = help: consider adding an explicit import of `SecretKey` to disambiguate

error[E0659]: `SecretKey` is ambiguous
    --> src\ksl_kapra_crypto.rs:1691:18
     |
1691 |         let sk = SecretKey::key_gen(ikm);
     |                  ^^^^^^^^^ ambiguous name
     |
     = note: ambiguous because of multiple glob imports of a name in the same module
note: `SecretKey` could refer to the type alias imported here
    --> src\ksl_kapra_crypto.rs:1473:9
     |
1473 |     use super::*;
     |         ^^^^^^^^
     = help: consider adding an explicit import of `SecretKey` to disambiguate
note: `SecretKey` could also refer to the struct imported here
    --> src\ksl_kapra_crypto.rs:1474:9
     |
1474 |     use blst::min_pk::*;
     |         ^^^^^^^^^^^^^^^
     = help: consider adding an explicit import of `SecretKey` to disambiguate

error[E0659]: `SecretKey` is ambiguous
    --> src\ksl_kapra_crypto.rs:1735:18
     |
1735 |         let sk = SecretKey::key_gen(ikm);
     |                  ^^^^^^^^^ ambiguous name
     |
     = note: ambiguous because of multiple glob imports of a name in the same module
note: `SecretKey` could refer to the type alias imported here
    --> src\ksl_kapra_crypto.rs:1473:9
     |
1473 |     use super::*;
     |         ^^^^^^^^
     = help: consider adding an explicit import of `SecretKey` to disambiguate
note: `SecretKey` could also refer to the struct imported here
    --> src\ksl_kapra_crypto.rs:1474:9
     |
1474 |     use blst::min_pk::*;
     |         ^^^^^^^^^^^^^^^
     = help: consider adding an explicit import of `SecretKey` to disambiguate

error[E0659]: `SecretKey` is ambiguous
    --> src\ksl_kapra_crypto.rs:1779:18
     |
1779 |         let sk = SecretKey::key_gen(ikm);
     |                  ^^^^^^^^^ ambiguous name
     |
     = note: ambiguous because of multiple glob imports of a name in the same module
note: `SecretKey` could refer to the type alias imported here
    --> src\ksl_kapra_crypto.rs:1473:9
     |
1473 |     use super::*;
     |         ^^^^^^^^
     = help: consider adding an explicit import of `SecretKey` to disambiguate
note: `SecretKey` could also refer to the struct imported here
    --> src\ksl_kapra_crypto.rs:1474:9
     |
1474 |     use blst::min_pk::*;
     |         ^^^^^^^^^^^^^^^
     = help: consider adding an explicit import of `SecretKey` to disambiguate

error[E0603]: enum import `Type` is private
   --> src\ksl_abi.rs:439:47
    |
439 |     use crate::ksl_ast::{Function, Parameter, Type};
    |                                               ^^^^ private enum import
    |
note: the enum import `Type` is defined here...
   --> src\ksl_ast.rs:3:24
    |
3   | use crate::ksl_types::{Type, TypeSystem, TypeConstraint}; // Use Type, TypeSystem, TypeConstraint from ksl_types
    |                        ^^^^
note: ...and refers to the enum `Type` which is defined here
   --> src\ksl_types.rs:41:1
    |
41  | pub enum Type {
    | ^^^^^^^^^^^^^ you could import this directly
help: import `Type` directly
    |
439 |     use crate::ksl_ast::{Function, Parameter, ksl_types::Type};
    |                                               +++++++++++

error[E0603]: enum import `Type` is private
   --> src\ksl_irgen.rs:300:25
    |
300 |     use crate::ksl_ast::Type;
    |                         ^^^^ private enum import
    |
note: the enum import `Type` is defined here...
   --> src\ksl_ast.rs:3:24
    |
3   | use crate::ksl_types::{Type, TypeSystem, TypeConstraint}; // Use Type, TypeSystem, TypeConstraint from ksl_types
    |                        ^^^^
note: ...and refers to the enum `Type` which is defined here
   --> src\ksl_types.rs:41:1
    |
41  | pub enum Type {
    | ^^^^^^^^^^^^^ you could import this directly
help: import `Type` directly
    |
300 -     use crate::ksl_ast::Type;
300 +     use ksl_types::Type;
    |

error[E0603]: enum import `AstNode` is private
   --> src\ksl_verifier.rs:675:29
    |
675 |     use crate::ksl_parser::{AstNode, ExprKind, TypeAnnotation};
    |                             ^^^^^^^ private enum import
    |
note: the enum import `AstNode` is defined here...
   --> src\ksl_parser.rs:5:25
    |
5   | use crate::ksl_macros::{AstNode, NetworkOpType, MacroExpander, MacroDef, HotReloadableFunction, HotReloadableF...
    |                         ^^^^^^^
note: ...and refers to the enum `AstNode` which is defined here
   --> src\ksl_macros.rs:439:1
    |
439 | pub enum AstNode {
    | ^^^^^^^^^^^^^^^^ you could import this directly
help: import `AstNode` directly
    |
675 |     use crate::ksl_parser::{ksl_macros::AstNode, ExprKind, TypeAnnotation};
    |                             ++++++++++++

error[E0603]: enum import `AstNode` is private
   --> src\ksl_test.rs:241:43
    |
241 |                 if let crate::ksl_parser::AstNode::FnDecl { name, is_async, attrs, .. } = node {
    |                                           ^^^^^^^  ------ variant `FnDecl` is not publicly re-exported
    |                                           |
    |                                           private enum import
    |
note: the enum import `AstNode` is defined here...
   --> src\ksl_parser.rs:5:25
    |
5   | use crate::ksl_macros::{AstNode, NetworkOpType, MacroExpander, MacroDef, HotReloadableFunction, HotReloadableF...
    |                         ^^^^^^^
note: ...and refers to the enum `AstNode` which is defined here
   --> src\ksl_macros.rs:439:1
    |
439 | pub enum AstNode {
    | ^^^^^^^^^^^^^^^^ you could import this directly

warning: unused imports: `TypeContext`, `TypeSystem`, and `Type`
 --> src\ksl_compiler.rs:6:50
  |
6 | use crate::ksl_types::{ExprKind, TypeAnnotation, Type, TypeContext, TypeSystem};
  |                                                  ^^^^  ^^^^^^^^^^^  ^^^^^^^^^^

warning: unused import: `compute_merkle_root`
 --> src\ksl_validator_contract.rs:2:107
  |
2 | ...s_verify, modulo_check, sha3, merkle_verify, compute_merkle_root, CrossShardProof, verify_cross_shard_proof, ...
  |                                                 ^^^^^^^^^^^^^^^^^^^

warning: unused import: `tokio::runtime::Runtime`
   --> src\ksl_package.rs:309:9
    |
309 |     use tokio::runtime::Runtime;
    |         ^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `tokio::runtime::Runtime`
   --> src\ksl_wasm.rs:522:9
    |
522 |     use tokio::runtime::Runtime;
    |         ^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `tokio::runtime::Runtime`
   --> src\ksl_async.rs:474:9
    |
474 |     use tokio::runtime::Runtime;
    |         ^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `blst::min_pk::*`
    --> src\ksl_kapra_crypto.rs:1474:9
     |
1474 |     use blst::min_pk::*;
     |         ^^^^^^^^^^^^^^^

warning: unused import: `blst::min_pk::*`
    --> src\kapra_vm.rs:1792:9
     |
1792 |     use blst::min_pk::*;
     |         ^^^^^^^^^^^^^^^

warning: unused import: `std::io::Write`
   --> src\ksl_config.rs:451:9
    |
451 |     use std::io::Write;
    |         ^^^^^^^^^^^^^^

warning: unused import: `std::io::Read`
   --> src\ksl_contract_verifier.rs:806:9
    |
806 |     use std::io::Read;
    |         ^^^^^^^^^^^^^

warning: unused import: `Read`
    --> src\ksl_hot_reload.rs:1485:19
     |
1485 |     use std::io::{Read, Write};
     |                   ^^^^

warning: unused import: `tokio::runtime::Runtime`
   --> src\ksl_stdlib_net.rs:804:9
    |
804 |     use tokio::runtime::Runtime;
    |         ^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `std::io::Read`
   --> src\ksl_refactor.rs:577:9
    |
577 |     use std::io::Read;
    |         ^^^^^^^^^^^^^

warning: unused import: `std::io::Write`
   --> src\ksl_plugins.rs:250:9
    |
250 |     use std::io::Write;
    |         ^^^^^^^^^^^^^^

warning: unused import: `tempfile::NamedTempFile`
   --> src\ksl_plugins.rs:251:9
    |
251 |     use tempfile::NamedTempFile;
    |         ^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `Expr`
 --> src\ksl_jit.rs:4:31
  |
4 | use crate::ksl_ast::{AstNode, Expr, Function, Stmt};
  |                               ^^^^

warning: unused import: `std::io::Read`
   --> src\ksl_typegen.rs:343:9
    |
343 |     use std::io::Read;
    |         ^^^^^^^^^^^^^

warning: unused import: `std::io::Read`
   --> src\ksl_vscode.rs:342:9
    |
342 |     use std::io::Read;
    |         ^^^^^^^^^^^^^

warning: unused import: `tokio::runtime::Runtime`
   --> src\ksl_stdlib_io.rs:220:9
    |
220 |     use tokio::runtime::Runtime;
    |         ^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `std::sync::mpsc`
   --> src\ksl_stdlib_io.rs:221:9
    |
221 |     use std::sync::mpsc;
    |         ^^^^^^^^^^^^^^^

warning: unused imports: `TestResult` and `run_tests`
   --> src\ksl_coverage.rs:378:21
    |
378 |     pub use super::{run_tests, TestResult};
    |                     ^^^^^^^^^  ^^^^^^^^^^

warning: unused import: `std::io::Read`
   --> src\ksl_doc_lsp.rs:803:9
    |
803 |     use std::io::Read;
    |         ^^^^^^^^^^^^^

warning: unused import: `tokio::runtime::Runtime`
   --> src\ksl_doc.rs:485:9
    |
485 |     use tokio::runtime::Runtime;
    |         ^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `Path`
  --> src\ksl_test.rs:41:17
   |
41 | use std::path::{Path, PathBuf};
   |                 ^^^^

warning: unused import: `HashSet`
  --> src\ksl_test.rs:42:33
   |
42 | use std::collections::{HashMap, HashSet};
   |                                 ^^^^^^^

warning: unused import: `tokio::sync::RwLock`
  --> src\ksl_test.rs:44:5
   |
44 | use tokio::sync::RwLock;
   |     ^^^^^^^^^^^^^^^^^^^

warning: unused imports: `RecursiveMode`, `Watcher`, and `event::Event`
  --> src\ksl_test.rs:50:34
   |
50 | use notify::{RecommendedWatcher, RecursiveMode, Watcher, event::Event};
   |                                  ^^^^^^^^^^^^^  ^^^^^^^  ^^^^^^^^^^^^

warning: unused import: `std::io::Read`
   --> src\ksl_package_publish.rs:508:9
    |
508 |     use std::io::Read;
    |         ^^^^^^^^^^^^^

warning: unused imports: `TestConfig` and `TestResult`
   --> src\ksl_ci.rs:843:21
    |
843 |     pub use super::{TestConfig, TestResult};
    |                     ^^^^^^^^^^  ^^^^^^^^^^

warning: unused import: `tokio::runtime::Runtime`
   --> src\ksl_kapra_scheduler.rs:978:9
    |
978 |     use tokio::runtime::Runtime;
    |         ^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `std::io::Read`
   --> src\ksl_migrate.rs:461:9
    |
461 |     use std::io::Read;
    |         ^^^^^^^^^^^^^

warning: unused import: `NamedTempFile`
   --> src\ksl_template.rs:353:29
    |
353 |     use tempfile::{TempDir, NamedTempFile};
    |                             ^^^^^^^^^^^^^

warning: unused imports: `TestResult` and `TestRunner`
   --> src\ksl_testgen.rs:443:21
    |
443 |     pub use super::{TestRunner, TestCase, TestResult, TestSuite};
    |                     ^^^^^^^^^^            ^^^^^^^^^^

error[E0728]: `await` is only allowed inside `async` functions and blocks
   --> src\ksl_game.rs:578:44
    |
565 |     fn test_physics_execution() {
    |     --------------------------- this is not `async`
...
578 |         let result = vm.execute(&bytecode).await;
    |                                            ^^^^^ only allowed inside `async` functions and blocks

error[E0728]: `await` is only allowed inside `async` functions and blocks
   --> src\ksl_game.rs:595:44
    |
584 |     fn test_render_execution() {
    |     -------------------------- this is not `async`
...
595 |         let result = vm.execute(&bytecode).await;
    |                                            ^^^^^ only allowed inside `async` functions and blocks

error[E0728]: `await` is only allowed inside `async` functions and blocks
   --> src\ksl_game.rs:613:44
    |
601 |     fn test_multiplayer_execution() {
    |     ------------------------------- this is not `async`
...
613 |         let result = vm.execute(&bytecode).await;
    |                                            ^^^^^ only allowed inside `async` functions and blocks

error[E0728]: `await` is only allowed inside `async` functions and blocks
   --> src\ksl_iot.rs:541:44
    |
528 |     fn test_device_comm_execution() {
    |     ------------------------------- this is not `async`
...
541 |         let result = vm.execute(&bytecode).await;
    |                                            ^^^^^ only allowed inside `async` functions and blocks

error[E0728]: `await` is only allowed inside `async` functions and blocks
   --> src\ksl_iot.rs:557:44
    |
548 |     fn test_power_manage_execution() {
    |     -------------------------------- this is not `async`
...
557 |         let result = vm.execute(&bytecode).await;
    |                                            ^^^^^ only allowed inside `async` functions and blocks

error[E0728]: `await` is only allowed inside `async` functions and blocks
   --> src\ksl_iot.rs:572:44
    |
564 |     fn test_sensor_reading() {
    |     ------------------------ this is not `async`
...
572 |         let result = vm.execute(&bytecode).await;
    |                                            ^^^^^ only allowed inside `async` functions and blocks

error[E0599]: no function or associated item named `new` found for struct `wasm_encoder::MemoryType` in the current scope
   --> src\ksl_wasm.rs:105:43
    |
105 |         memory_section.memory(MemoryType::new(1, None)); // 1 page (64KB)
    |                                           ^^^ function or associated item not found in `MemoryType`
    |
    = help: items from traits can only be used if the trait is in scope
help: there is a method `ne` with a similar name, but with different arguments
   --> C:\Users\ecomm\.rustup\toolchains\stable-x86_64-pc-windows-msvc\lib/rustlib/src/rust\library\core\src\cmp.rs:261:5
    |
261 |     fn ne(&self, other: &Rhs) -> bool {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::paint::Paint;
    |

error[E0063]: missing field `type_info` in initializer of `ksl_bytecode::KapraInstruction`
   --> src\ksl_wasm.rs:645:17
    |
645 |                 KapraInstruction {
    |                 ^^^^^^^^^^^^^^^^ missing `type_info`

error[E0063]: missing fields `config`, `llvm_ir` and `micro_vm_optimizations` in initializer of `ksl_bytecode::KapraBytecode`
   --> src\ksl_wasm.rs:643:24
    |
643 |         let bytecode = KapraBytecode {
    |                        ^^^^^^^^^^^^^ missing `config`, `llvm_ir` and `micro_vm_optimizations`

error[E0599]: no method named `unwrap` found for opaque type `impl Iterator<Item = Result<Payload<'_>, ...>>` in the current scope
   --> src\ksl_wasm.rs:660:66
    |
660 |         let module = wasmparser::Parser::new(0).parse_all(&wasm).unwrap();
    |                                                                  ^^^^^^
    |
help: there is a method `wrap` with a similar name
    |
660 -         let module = wasmparser::Parser::new(0).parse_all(&wasm).unwrap();
660 +         let module = wasmparser::Parser::new(0).parse_all(&wasm).wrap();
    |

error[E0599]: no function or associated item named `new` found for struct `ksl_stdlib_net::PeerConnection` in the current scope
   --> src\ksl_stdlib_net.rs:757:36
    |
185 | struct PeerConnection {
    | --------------------- function or associated item `new` not found for this struct
...
757 |         let peer = PeerConnection::new(peer_id);
    |                                    ^^^ function or associated item not found in `PeerConnection`
    |
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
5   + use yansi::paint::Paint;
    |

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_dev_tools.rs:127:36
    |
127 |             .map_err(|e| KslError::new(ErrorType::RuntimeError, e.to_string()))
    |                                    ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::paint::Paint;
    |

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_dev_tools.rs:134:36
    |
134 |             .map_err(|e| KslError::new(ErrorType::DebugError, e.to_string()))
    |                                    ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::paint::Paint;
    |

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_dev_tools.rs:143:36
    |
143 |             .map_err(|e| KslError::new(ErrorType::AsyncError, e.to_string()))
    |                                    ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::paint::Paint;
    |

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_dev_tools.rs:152:36
    |
152 |             .map_err(|e| KslError::new(ErrorType::AsyncError, e.to_string()))
    |                                    ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::paint::Paint;
    |

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_dev_tools.rs:159:36
    |
159 |             .map_err(|e| KslError::new(ErrorType::DebugError, e.to_string()))
    |                                    ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::paint::Paint;
    |

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_dev_tools.rs:166:36
    |
166 |             .map_err(|e| KslError::new(ErrorType::DebugError, e.to_string()))
    |                                    ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::paint::Paint;
    |

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_dev_tools.rs:198:46
    |
198 | ...   return Err(KslError::new(ErrorType::StackUnderflow, "Not enough values on stack for LOG".to_string()));
    |                            ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::paint::Paint;
    |

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_dev_tools.rs:203:51
    |
203 | ...   _ => return Err(KslError::new(ErrorType::TypeError, "Invalid type for LOG message".to_string())),
    |                                 ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::paint::Paint;
    |

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_dev_tools.rs:215:46
    |
215 | ...   return Err(KslError::new(ErrorType::StackUnderflow, "Not enough values on stack for MEASURE".to_string()));
    |                            ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::paint::Paint;
    |

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_dev_tools.rs:220:51
    |
220 | ...   _ => return Err(KslError::new(ErrorType::TypeError, "Invalid type for MEASURE task".to_string())),
    |                                 ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::paint::Paint;
    |

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_dev_tools.rs:232:46
    |
232 | ...   return Err(KslError::new(ErrorType::StackUnderflow, "Not enough values on stack for GENERATE_DIAGRAM".to...
    |                            ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::paint::Paint;
    |

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_dev_tools.rs:237:51
    |
237 | ...   _ => return Err(KslError::new(ErrorType::TypeError, "Invalid type for GENERATE_DIAGRAM data".to_string())),
    |                                 ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::paint::Paint;
    |

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_dev_tools.rs:244:46
    |
244 | ...   return Err(KslError::new(ErrorType::InvalidInstruction, "Incomplete PUSH instruction".to_string()));
    |                            ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::paint::Paint;
    |

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_dev_tools.rs:251:42
    |
251 | ...   return Err(KslError::new(ErrorType::RuntimeError, "Developer tools operation failed".to_string()));
    |                            ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::paint::Paint;
    |

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_dev_tools.rs:253:43
    |
253 | ...   _ => return Err(KslError::new(ErrorType::InvalidInstruction, format!("Unsupported opcode: {}", instr))),
    |                                 ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::paint::Paint;
    |

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_dev_tools.rs:258:34
    |
258 | ...   return Err(KslError::new(ErrorType::StackError, "Developer tools block must return exactly one value".to...
    |                            ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::paint::Paint;
    |

error[E0277]: the `?` operator can only be used in a closure that returns `Result` or `Option` (or another type that implements `std::ops::FromResidual`)
   --> src\ksl_fuzzer.rs:859:80
    |
851 |                     .map(|i| {
    |                          --- this function should return `Result` or `Option` to accept `?`
...
859 |                         let mut local_fuzzer = Fuzzer::new(self.config.clone())?;
    |                                                                                ^ cannot use the `?` operator in a closure that returns `impl futures::Future<Output = std::result::Result<(), std::string::String>>`
    |
    = help: the trait `std::ops::FromResidual<std::result::Result<std::convert::Infallible, std::string::String>>` is not implemented for `impl futures::Future<Output = std::result::Result<(), std::string::String>>`
    = note: the full name for the type has been written to 'C:\rn\ksl\target\debug\deps\KSL-4dbeb51e612588f0.long-type-6929963805287838056.txt'
    = note: consider using `--verbose` to print the full type name to the console

error[E0277]: the trait bound `Vec<Result<(), String>>: FromParallelIterator<...>` is not satisfied
    --> src\ksl_fuzzer.rs:862:22
     |
862  |                     .collect();
     |                      ^^^^^^^ unsatisfied trait bound
     |
     = help: the trait `FromParallelIterator<impl futures::Future<Output = std::result::Result<(), std::string::String>>>` is not implemented for `std::vec::Vec<std::result::Result<(), std::string::String>>`
             but trait `FromParallelIterator<std::result::Result<(), std::string::String>>` is implemented for it
     = help: for that trait implementation, expected `std::result::Result<(), std::string::String>`, found `impl futures::Future<Output = std::result::Result<(), std::string::String>>`
note: the method call chain might not have had the expected associated types
    --> src\ksl_fuzzer.rs:851:22
     |
849  |                   let results: Vec<Result<(), String>> = (0..num_threads)
     |                                                          ---------------- this expression has type `Range<usize>`
850  |                       .into_par_iter()
     |                        --------------- `ParallelIterator::Item` is `usize` here
851  |                       .map(|i| {
     |  ______________________^
852  | |                         let start = i * chunk_size;
853  | |                         let end = if i == num_threads - 1 {
854  | |                             self.config.num_cases
...    |
860  | |                         local_fuzzer.fuzz_contract_range(&abi, *storage, *modifiers, start, end)
861  | |                     })
     | |______________________^ `ParallelIterator::Item` changed to `impl Future<Output = Result<(), String>>` here
note: required by a bound in `rayon::iter::ParallelIterator::collect`
    --> C:\Users\ecomm\.cargo\registry\src\index.crates.io-1949cf8c6b5b557f\rayon-1.10.0\src\iter\mod.rs:2067:12
     |
2065 |     fn collect<C>(self) -> C
     |        ------- required by a bound in this associated function
2066 |     where
2067 |         C: FromParallelIterator<Self::Item>,
     |            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ required by this bound in `ParallelIterator::collect`
     = note: the full name for the type has been written to 'C:\rn\ksl\target\debug\deps\KSL-4dbeb51e612588f0.long-type-12521536189995787884.txt'
     = note: consider using `--verbose` to print the full type name to the console

error[E0277]: the `?` operator can only be used in a closure that returns `Result` or `Option` (or another type that implements `std::ops::FromResidual`)
   --> src\ksl_fuzzer.rs:900:80
    |
892 |                     .map(|i| {
    |                          --- this function should return `Result` or `Option` to accept `?`
...
900 |                         let mut local_fuzzer = Fuzzer::new(self.config.clone())?;
    |                                                                                ^ cannot use the `?` operator in a closure that returns `impl futures::Future<Output = std::result::Result<(), std::string::String>>`
    |
    = help: the trait `std::ops::FromResidual<std::result::Result<std::convert::Infallible, std::string::String>>` is not implemented for `impl futures::Future<Output = std::result::Result<(), std::string::String>>`
    = note: the full name for the type has been written to 'C:\rn\ksl\target\debug\deps\KSL-4dbeb51e612588f0.long-type-11462273937698034487.txt'
    = note: consider using `--verbose` to print the full type name to the console

error[E0277]: the trait bound `Vec<Result<(), String>>: FromParallelIterator<...>` is not satisfied
    --> src\ksl_fuzzer.rs:903:22
     |
903  |                     .collect();
     |                      ^^^^^^^ unsatisfied trait bound
     |
     = help: the trait `FromParallelIterator<impl futures::Future<Output = std::result::Result<(), std::string::String>>>` is not implemented for `std::vec::Vec<std::result::Result<(), std::string::String>>`
             but trait `FromParallelIterator<std::result::Result<(), std::string::String>>` is implemented for it
     = help: for that trait implementation, expected `std::result::Result<(), std::string::String>`, found `impl futures::Future<Output = std::result::Result<(), std::string::String>>`
note: the method call chain might not have had the expected associated types
    --> src\ksl_fuzzer.rs:892:22
     |
890  |                   let results: Vec<Result<(), String>> = (0..num_threads)
     |                                                          ---------------- this expression has type `Range<usize>`
891  |                       .into_par_iter()
     |                        --------------- `ParallelIterator::Item` is `usize` here
892  |                       .map(|i| {
     |  ______________________^
893  | |                         let start = i * chunk_size;
894  | |                         let end = if i == num_threads - 1 {
895  | |                             self.config.num_cases
...    |
901  | |                         local_fuzzer.fuzz_sharding_range(*cross_shard, *timing, start, end)
902  | |                     })
     | |______________________^ `ParallelIterator::Item` changed to `impl Future<Output = Result<(), String>>` here
note: required by a bound in `rayon::iter::ParallelIterator::collect`
    --> C:\Users\ecomm\.cargo\registry\src\index.crates.io-1949cf8c6b5b557f\rayon-1.10.0\src\iter\mod.rs:2067:12
     |
2065 |     fn collect<C>(self) -> C
     |        ------- required by a bound in this associated function
2066 |     where
2067 |         C: FromParallelIterator<Self::Item>,
     |            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ required by this bound in `ParallelIterator::collect`
     = note: the full name for the type has been written to 'C:\rn\ksl\target\debug\deps\KSL-4dbeb51e612588f0.long-type-6293879287509008590.txt'
     = note: consider using `--verbose` to print the full type name to the console

error[E0277]: the `?` operator can only be used in a closure that returns `Result` or `Option` (or another type that implements `std::ops::FromResidual`)
   --> src\ksl_fuzzer.rs:920:80
    |
912 |                     .map(|i| {
    |                          --- this function should return `Result` or `Option` to accept `?`
...
920 |                         let mut local_fuzzer = Fuzzer::new(self.config.clone())?;
    |                                                                                ^ cannot use the `?` operator in a closure that returns `impl futures::Future<Output = std::result::Result<(), std::string::String>>`
    |
    = help: the trait `std::ops::FromResidual<std::result::Result<std::convert::Infallible, std::string::String>>` is not implemented for `impl futures::Future<Output = std::result::Result<(), std::string::String>>`
    = note: the full name for the type has been written to 'C:\rn\ksl\target\debug\deps\KSL-4dbeb51e612588f0.long-type-1956486422694002060.txt'
    = note: consider using `--verbose` to print the full type name to the console

error[E0277]: the trait bound `Vec<Result<(), String>>: FromParallelIterator<...>` is not satisfied
    --> src\ksl_fuzzer.rs:923:22
     |
923  |                     .collect();
     |                      ^^^^^^^ unsatisfied trait bound
     |
     = help: the trait `FromParallelIterator<impl futures::Future<Output = std::result::Result<(), std::string::String>>>` is not implemented for `std::vec::Vec<std::result::Result<(), std::string::String>>`
             but trait `FromParallelIterator<std::result::Result<(), std::string::String>>` is implemented for it
     = help: for that trait implementation, expected `std::result::Result<(), std::string::String>`, found `impl futures::Future<Output = std::result::Result<(), std::string::String>>`
note: the method call chain might not have had the expected associated types
    --> src\ksl_fuzzer.rs:912:22
     |
910  |                   let results: Vec<Result<(), String>> = (0..num_threads)
     |                                                          ---------------- this expression has type `Range<usize>`
911  |                       .into_par_iter()
     |                        --------------- `ParallelIterator::Item` is `usize` here
912  |                       .map(|i| {
     |  ______________________^
913  | |                         let start = i * chunk_size;
914  | |                         let end = if i == num_threads - 1 {
915  | |                             self.config.num_cases
...    |
921  | |                         local_fuzzer.fuzz_consensus_range(*forks, *votes, start, end)
922  | |                     })
     | |______________________^ `ParallelIterator::Item` changed to `impl Future<Output = Result<(), String>>` here
note: required by a bound in `rayon::iter::ParallelIterator::collect`
    --> C:\Users\ecomm\.cargo\registry\src\index.crates.io-1949cf8c6b5b557f\rayon-1.10.0\src\iter\mod.rs:2067:12
     |
2065 |     fn collect<C>(self) -> C
     |        ------- required by a bound in this associated function
2066 |     where
2067 |         C: FromParallelIterator<Self::Item>,
     |            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ required by this bound in `ParallelIterator::collect`
     = note: the full name for the type has been written to 'C:\rn\ksl\target\debug\deps\KSL-4dbeb51e612588f0.long-type-10384093842493011132.txt'
     = note: consider using `--verbose` to print the full type name to the console

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_project.rs:194:34
    |
194 | ...   return Err(KslError::new(ErrorType::ValidationError, "Project name must be non-empty and contain only al...
    |                            ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::paint::Paint;
    |

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_project.rs:200:34
    |
200 |             return Err(KslError::new(ErrorType::FileError, format!("Directory '{}' already exists", name)));
    |                                  ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::paint::Paint;
    |

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_project.rs:205:38
    |
205 | ...   .ok_or_else(|| KslError::new(ErrorType::TemplateError, format!("Template '{}' not found", template_name)...
    |                                ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::paint::Paint;
    |

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_project.rs:209:36
    |
209 | ...   .map_err(|e| KslError::new(ErrorType::FileError, format!("Failed to create project directory: {}", e)))?;
    |                              ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::paint::Paint;
    |

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_project.rs:214:36
    |
214 |             .map_err(|e| KslError::new(ErrorType::FileError, format!("Failed to create src directory: {}", e)))?;
    |                                    ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::paint::Paint;
    |

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_project.rs:229:36
    |
229 |             .map_err(|e| KslError::new(ErrorType::ConfigError, e.to_string()))?;
    |                                    ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::paint::Paint;
    |

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_project.rs:236:36
    |
236 | ...   .map_err(|e| KslError::new(ErrorType::FileError, format!("Failed to create ksl_package.toml: {}", e)))?;
    |                              ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::paint::Paint;
    |

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_project.rs:238:36
    |
238 | ...   .map_err(|e| KslError::new(ErrorType::FileError, format!("Failed to write ksl_package.toml: {}", e)))?;
    |                              ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::paint::Paint;
    |

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_project.rs:243:36
    |
243 |             .map_err(|e| KslError::new(ErrorType::FileError, format!("Failed to create src/main.ksl: {}", e)))?;
    |                                    ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::paint::Paint;
    |

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_project.rs:245:36
    |
245 |             .map_err(|e| KslError::new(ErrorType::FileError, format!("Failed to write src/main.ksl: {}", e)))?;
    |                                    ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::paint::Paint;
    |

error[E0599]: no variant or associated item named `new` found for enum `ksl_errors::KslError` in the current scope
   --> src\ksl_project.rs:252:36
    |
252 |             .map_err(|e| KslError::new(ErrorType::AsyncError, e.to_string()))?;
    |                                    ^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `new` not found for this enum
    |
note: if you're trying to build a new `ksl_errors::KslError` consider using one of the following associated functions:
      ksl_errors::KslError::parse
      ksl_errors::KslError::type_error
      ksl_errors::KslError::compile
      ksl_errors::KslError::runtime
      ksl_errors::KslError::network
   --> src\ksl_errors.rs:96:5
    |
96  |     pub fn parse(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
122 |     pub fn compile(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `Paint` which provides `new` is implemented but not in scope; perhaps you want to import it
    |
4   + use yansi::paint::Paint;
    |

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
  --> src\ksl_smart_account.rs:84:23
   |
84 |           let sponsor = FixedArray([1; 32]);
   |                         ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
   |
  ::: src\ksl_kapra_crypto.rs:44:1
   |
44 | / pub struct FixedArray<const N: usize> {
45 | |     data: [u8; N],
46 | | }
   | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
  --> src\ksl_smart_account.rs:98:24
   |
98 |           let guardian = FixedArray([2; 32]);
   |                          ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
   |
  ::: src\ksl_kapra_crypto.rs:44:1
   |
44 | / pub struct FixedArray<const N: usize> {
45 | |     data: [u8; N],
46 | | }
   | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:2543:34
     |
2543 |           vm.current_sender = Some(FixedArray(delegator));
     |                                    ^^^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:2600:34
     |
2600 |           vm.current_sender = Some(FixedArray(delegator));
     |                                    ^^^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:2614:22
     |
2614 |           let sender = FixedArray([1; 32]);
     |                        ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:2615:23
     |
2615 |           let sponsor = FixedArray([2; 32]);
     |                         ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:2647:22
     |
2647 |           let sender = FixedArray([1; 32]);
     |                        ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:2648:23
     |
2648 |           let sponsor = FixedArray([2; 32]);
     |                         ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:2670:22
     |
2670 |           let sender = FixedArray([1; 32]);
     |                        ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:2671:23
     |
2671 |           let sponsor = FixedArray([2; 32]);
     |                         ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:2696:22
     |
2696 |           let sender = FixedArray([1; 32]);
     |                        ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:2697:23
     |
2697 |           let target1 = FixedArray([2; 32]);
     |                         ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:2698:23
     |
2698 |           let target2 = FixedArray([3; 32]);
     |                         ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:2751:22
     |
2751 |           let sender = FixedArray([1; 32]);
     |                        ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:2752:23
     |
2752 |           let target1 = FixedArray([2; 32]);
     |                         ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:2753:23
     |
2753 |           let target2 = FixedArray([3; 32]);
     |                         ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:2805:22
     |
2805 |           let sender = FixedArray([1; 32]);
     |                        ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:2806:23
     |
2806 |           let sponsor = FixedArray([2; 32]);
     |                         ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:2807:22
     |
2807 |           let target = FixedArray([3; 32]);
     |                        ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:2864:22
     |
2864 |           let sender = FixedArray([1; 32]);
     |                        ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:2865:23
     |
2865 |           let target1 = FixedArray([2; 32]);
     |                         ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:2866:23
     |
2866 |           let target2 = FixedArray([3; 32]);
     |                         ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:2923:22
     |
2923 |           let sender = FixedArray([1; 32]);
     |                        ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:2924:31
     |
2924 |           let default_sponsor = FixedArray([2; 32]);
     |                                 ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:2925:31
     |
2925 |           let dynamic_sponsor = FixedArray([3; 32]);
     |                                 ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:2926:22
     |
2926 |           let target = FixedArray([4; 32]);
     |                        ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:3224:22
     |
3224 |           let sender = FixedArray([1; 32]);
     |                        ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:3256:22
     |
3256 |           let sender = FixedArray([1; 32]);
     |                        ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:3257:24
     |
3257 |           let guardian = FixedArray([2; 32]);
     |                          ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:3305:22
     |
3305 |           let sender = FixedArray([1; 32]);
     |                        ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:3306:28
     |
3306 |           let unauthorized = FixedArray([2; 32]);
     |                              ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:3342:22
     |
3342 |           let sender = FixedArray([1; 32]);
     |                        ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:3385:22
     |
3385 |           let sender = FixedArray([1; 32]);
     |                        ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:3386:28
     |
3386 |           let unauthorized = FixedArray([2; 32]);
     |                              ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:3420:22
     |
3420 |           let sender = FixedArray([1; 32]);
     |                        ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:3421:24
     |
3421 |           let guardian = FixedArray([2; 32]);
     |                          ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:3422:28
     |
3422 |           let unauthorized = FixedArray([3; 32]);
     |                              ^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0425]: cannot find function `hot_reload` in this scope
    --> src\ksl_hot_reload.rs:1505:13
     |
1505 |             hot_reload(&input_file_clone).unwrap();
     |             ^^^^^^^^^^ not found in this scope

error[E0425]: cannot find function `hot_reload` in this scope
    --> src\ksl_hot_reload.rs:1532:22
     |
1532 |         let result = hot_reload(&input_file);
     |                      ^^^^^^^^^^ not found in this scope

warning: `KSL` (lib test) generated 638 warnings (606 duplicates)
error: could not compile `KSL` (lib test) due to 1607 previous errors; 638 warnings emitted