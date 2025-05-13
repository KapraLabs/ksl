# KSL Project Error Tracker


error[E0308]: mismatched types
   --> src\ksl_refactor.rs:114:15
    |
114 |         check(&ast)
    |         ----- ^^^^ expected `&[AstNode]`, found `&Vec<AstNode>`
    |         |
    |         arguments to this function are incorrect
    |
    = note: expected reference `&[ksl_ast::AstNode]`
               found reference `&Vec<ksl_macros::AstNode>`
note: function defined here
   --> src\ksl_checker.rs:651:8
    |
651 | pub fn check(nodes: &[AstNode]) -> Result<(), Vec<TypeError>> {
    |        ^^^^^ -----------------

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_refactor.rs:115:31
    |
115 |               .map_err(|errors| KslError::type_error(
    |  _______________________________^^^^^^^^^^^^^^^^^^^^-
116 | |                 errors.into_iter()
117 | |                     .map(|e| format!("Type error at position {}: {}", e.position, e.message))
118 | |                     .collect::<Vec<_>>()
119 | |                     .join("\n"),
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
115 ~             .map_err(|errors| KslError::type_error(errors.into_iter()
116 +                     .map(|e| format!("Type error at position {}: {}", e.position, e.message))
117 +                     .collect::<Vec<_>>()
118 ~                     .join("\n"), pos, /* std::string::String */))?;
    |

error[E0599]: no method named `analyze` found for struct `tokio::sync::MutexGuard<'_, Analyzer>` in the current scope
   --> src\ksl_refactor.rs:124:38
    |
124 |         let post_analysis = analyzer.analyze(&ast)
    |                                      ^^^^^^^
    |
help: there is a method `analyze_file` with a similar name
    |
124 |         let post_analysis = analyzer.analyze_file(&ast)
    |                                             +++++

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_refactor.rs:125:26
    |
125 |               .map_err(|e| KslError::type_error(
    |  __________________________^^^^^^^^^^^^^^^^^^^^-
126 | |                 format!("Post-refactoring analysis failed: {}", e),
127 | |                 pos,
128 | |             ))?;
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
125 -             .map_err(|e| KslError::type_error(
126 -                 format!("Post-refactoring analysis failed: {}", e),
127 -                 pos,
128 -             ))?;
125 +             .map_err(|e| KslError::type_error(format!("Post-refactoring analysis failed: {}", e), pos, /* std::string::String */))?;
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_refactor.rs:139:26
    |
139 |               .map_err(|e| KslError::type_error(
    |  __________________________^^^^^^^^^^^^^^^^^^^^-
140 | |                 format!("Failed to create output file {}: {}", output_path.display(), e),
141 | |                 pos,
142 | |             ))?
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
139 -             .map_err(|e| KslError::type_error(
140 -                 format!("Failed to create output file {}: {}", output_path.display(), e),
141 -                 pos,
142 -             ))?
139 +             .map_err(|e| KslError::type_error(format!("Failed to create output file {}: {}", output_path.display(), e), pos, /* std::string::String */))?
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_refactor.rs:144:26
    |
144 |               .map_err(|e| KslError::type_error(
    |  __________________________^^^^^^^^^^^^^^^^^^^^-
145 | |                 format!("Failed to write output file {}: {}", output_path.display(), e),
146 | |                 pos,
147 | |             ))?;
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
144 -             .map_err(|e| KslError::type_error(
145 -                 format!("Failed to write output file {}: {}", output_path.display(), e),
146 -                 pos,
147 -             ))?;
144 +             .map_err(|e| KslError::type_error(format!("Failed to write output file {}: {}", output_path.display(), e), pos, /* std::string::String */))?;
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_refactor.rs:153:30
    |
153 |                   .map_err(|e| KslError::type_error(
    |  ______________________________^^^^^^^^^^^^^^^^^^^^-
154 | |                     format!("Failed to create report file {}: {}", report_path.display(), e),
155 | |                     pos,
156 | |                 ))?
    | |_________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
153 -                 .map_err(|e| KslError::type_error(
154 -                     format!("Failed to create report file {}: {}", report_path.display(), e),
155 -                     pos,
156 -                 ))?
153 +                 .map_err(|e| KslError::type_error(format!("Failed to create report file {}: {}", report_path.display(), e), pos, /* std::string::String */))?
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_refactor.rs:158:30
    |
158 |                   .map_err(|e| KslError::type_error(
    |  ______________________________^^^^^^^^^^^^^^^^^^^^-
159 | |                     format!("Failed to write report file {}: {}", report_path.display(), e),
160 | |                     pos,
161 | |                 ))?;
    | |_________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
158 -                 .map_err(|e| KslError::type_error(
159 -                     format!("Failed to write report file {}: {}", report_path.display(), e),
160 -                     pos,
161 -                 ))?;
158 +                 .map_err(|e| KslError::type_error(format!("Failed to write report file {}: {}", report_path.display(), e), pos, /* std::string::String */))?;
    |

error[E0599]: the method `clone` exists for struct `Vec<RefactorChange>`, but its trait bounds were not satisfied
   --> src\ksl_refactor.rs:166:25
    |
39  | struct RefactorChange {
    | --------------------- doesn't satisfy `RefactorChange: std::clone::Clone`
...
166 |         Ok(self.changes.clone())
    |                         ^^^^^
    |
    = note: the following trait bounds were not satisfied:
            `RefactorChange: std::clone::Clone`
            which is required by `Vec<RefactorChange>: std::clone::Clone`
help: consider annotating `RefactorChange` with `#[derive(Clone)]`
    |
39  + #[derive(Clone)]
40  | struct RefactorChange {
    |

error[E0599]: no variant named `Async` found for enum `ksl_parser::ExprKind`
   --> src\ksl_refactor.rs:272:27
    |
272 |                 ExprKind::Async { expr } => {
    |                           ^^^^^ variant not found in `ksl_parser::ExprKind`
    |
   ::: src\ksl_parser.rs:59:1
    |
59  | pub enum ExprKind {
    | ----------------- variant `Async` not found here

error[E0308]: mismatched types
   --> src\ksl_refactor.rs:261:29
    |
261 |                     *name = new_name.to_string();
    |                     -----   ^^^^^^^^^^^^^^^^^^^^ expected `str`, found `String`
    |                     |
    |                     expected due to the type of this binding

error[E0277]: the size for values of type `str` cannot be known at compilation time
   --> src\ksl_refactor.rs:261:21
    |
261 |                     *name = new_name.to_string();
    |                     ^^^^^ doesn't have a size known at compile-time
    |
    = help: the trait `Sized` is not implemented for `str`
    = note: the left-hand-side of an assignment must have a statically known size

error[E0599]: no method named `inline_in_body` found for mutable reference `&mut RefactorTool` in the current scope
   --> src\ksl_refactor.rs:370:34
    |
370 | ...                   self.inline_in_body(&mut new_body, var_name, expr)?;
    |                            ^^^^^^^^^^^^^^ method not found in `&mut RefactorTool`

error[E0277]: `?` couldn't convert the error to `Vec<KslError>`
  --> src\ksl_verifier.rs:87:76
   |
87 |                         let verify_attr = self.parse_verify_attribute(attr)?;
   |                                                ----------------------------^ the trait `std::convert::From<KslError>` is not implemented for `Vec<KslError>`
   |                                                |
   |                                                this can't be annotated with `?` because it has type `Result<_, KslError>`
   |
   = note: the question mark operation (`?`) implicitly performs a conversion on the error value using the `From` trait
   = help: the following other types implement trait `std::convert::From<T>`:
             `Vec<T, A>` implements `std::convert::From<BinaryHeap<T, A>>`
             `Vec<T, A>` implements `std::convert::From<VecDeque<T, A>>`
             `Vec<T, A>` implements `std::convert::From<std::boxed::Box<[T], A>>`
             `Vec<T>` implements `std::convert::From<&[T; N]>`
             `Vec<T>` implements `std::convert::From<&[T]>`
             `Vec<T>` implements `std::convert::From<&mut [T; N]>`
             `Vec<T>` implements `std::convert::From<&mut [T]>`
             `Vec<T>` implements `std::convert::From<Cow<'_, [T]>>`
           and 21 others
   = note: required for `std::result::Result<(), Vec<KslError>>` to implement `FromResidual<std::result::Result<Infallible, KslError>>`

error[E0599]: the method `clone` exists for struct `Vec<KslError>`, but its trait bounds were not satisfied
  --> src\ksl_verifier.rs:97:56
   |
97 | ...                   return Err(self.errors.clone());
   |                                              ^^^^^
   |
  ::: src\ksl_errors.rs:58:1
   |
58 | pub enum KslError {
   | ----------------- doesn't satisfy `KslError: std::clone::Clone`
   |
   = note: the following trait bounds were not satisfied:
           `KslError: std::clone::Clone`
           which is required by `Vec<KslError>: std::clone::Clone`
help: consider annotating `KslError` with `#[derive(Clone)]`
  --> src\ksl_errors.rs:58:1
   |
58 + #[derive(Clone)]
59 | pub enum KslError {
   |

error[E0599]: the method `clone` exists for struct `Vec<KslError>`, but its trait bounds were not satisfied
   --> src\ksl_verifier.rs:111:29
    |
111 |             Err(self.errors.clone())
    |                             ^^^^^
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- doesn't satisfy `KslError: std::clone::Clone`
    |
    = note: the following trait bounds were not satisfied:
            `KslError: std::clone::Clone`
            which is required by `Vec<KslError>: std::clone::Clone`
help: consider annotating `KslError` with `#[derive(Clone)]`
   --> src\ksl_errors.rs:58:1
    |
58  + #[derive(Clone)]
59  | pub enum KslError {
    |

error[E0599]: no method named `resolve_type` found for struct `ksl_types::TypeSystem` in the current scope
   --> src\ksl_verifier.rs:177:44
    |
177 |         let result_type = self.type_system.resolve_type(return_type)?;
    |                                            ^^^^^^^^^^^^ method not found in `TypeSystem`
    |
   ::: src\ksl_types.rs:159:1
    |
159 | pub struct TypeSystem;
    | --------------------- method `resolve_type` not found for this struct

error[E0599]: no method named `translate_async_body` found for mutable reference `&mut ksl_verifier::Verifier<'a>` in the current scope
   --> src\ksl_verifier.rs:191:22
    |
191 |                 self.translate_async_body(body, runtime),
    |                      ^^^^^^^^^^^^^^^^^^^^
    |
help: there is a method `translate_node` with a similar name, but with different arguments
   --> src\ksl_verifier.rs:334:5
    |
334 |     fn translate_node(&mut self, node: &AstNode) -> Result<(), VerError> {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

error[E0599]: no method named `spawn` found for struct `tokio::sync::RwLockWriteGuard<'_, AsyncRuntime>` in the current scope
   --> src\ksl_verifier.rs:231:17
    |
231 |         runtime.spawn(task).await?;
    |                 ^^^^^ method not found in `RwLockWriteGuard<'_, AsyncRuntime>`
    |
    = help: items from traits can only be used if the trait is implemented and in scope
    = note: the following traits define an item `spawn`, perhaps you need to implement one of them:
            candidate #1: `SpawnExt`
            candidate #2: `opentelemetry_sdk::runtime::Runtime`
            candidate #3: `rayon_core::registry::ThreadSpawn`

error[E0599]: no method named `json` found for struct `reqwest::Response` in the current scope
   --> src\ksl_updater.rs:668:14
    |
667 |           let updates: Vec<UpdateMetadata> = response
    |  ____________________________________________-
668 | |             .json()
    | |             -^^^^ method not found in `Response`
    | |_____________|
    |

error[E0277]: the trait bound `reqwest::Body: std::convert::From<std::fs::File>` is not satisfied
   --> src\ksl_updater.rs:688:19
    |
688 |             .body(file)
    |              ---- ^^^^ the trait `std::convert::From<std::fs::File>` is not implemented for `reqwest::Body`
    |              |
    |              required by a bound introduced by this call
    |
    = help: the following other types implement trait `std::convert::From<T>`:
              `reqwest::Body` implements `std::convert::From<&[u8]>`
              `reqwest::Body` implements `std::convert::From<&str>`
              `reqwest::Body` implements `std::convert::From<Vec<u8>>`
              `reqwest::Body` implements `std::convert::From<bytes::bytes::Bytes>`
              `reqwest::Body` implements `std::convert::From<reqwest::Response>`
              `reqwest::Body` implements `std::convert::From<std::string::String>`
    = note: required for `std::fs::File` to implement `Into<reqwest::Body>`
note: required by a bound in `reqwest::RequestBuilder::body`
   --> C:\Users\ecomm\.cargo\registry\src\index.crates.io-1949cf8c6b5b557f\reqwest-0.12.15\src\async_impl\request.rs:274:20
    |
274 |     pub fn body<T: Into<Body>>(mut self, body: T) -> RequestBuilder {
    |                    ^^^^^^^^^^ required by this bound in `RequestBuilder::body`

error[E0599]: no variant or associated item named `web3_error` found for enum `KslError` in the current scope
   --> src\ksl_web3.rs:183:34
    |
183 |             return Err(KslError::web3_error(
    |                                  ^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `web3_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `web3_error` found for enum `KslError` in the current scope
   --> src\ksl_web3.rs:201:34
    |
201 |             return Err(KslError::web3_error(
    |                                  ^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `web3_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `web3_error` found for enum `KslError` in the current scope
   --> src\ksl_web3.rs:219:34
    |
219 |             return Err(KslError::web3_error(
    |                                  ^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `web3_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `web3_error` found for enum `KslError` in the current scope
   --> src\ksl_web3.rs:238:34
    |
238 |             return Err(KslError::web3_error(
    |                                  ^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `web3_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `web3_error` found for enum `KslError` in the current scope
   --> src\ksl_web3.rs:282:46
    |
282 |                         return Err(KslError::web3_error(
    |                                              ^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `web3_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `web3_error` found for enum `KslError` in the current scope
   --> src\ksl_web3.rs:291:51
    |
291 |                         _ => return Err(KslError::web3_error(
    |                                                   ^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `web3_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `web3_error` found for enum `KslError` in the current scope
   --> src\ksl_web3.rs:298:51
    |
298 |                         _ => return Err(KslError::web3_error(
    |                                                   ^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `web3_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `web3_error` found for enum `KslError` in the current scope
   --> src\ksl_web3.rs:313:46
    |
313 |                         return Err(KslError::web3_error(
    |                                              ^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `web3_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `web3_error` found for enum `KslError` in the current scope
   --> src\ksl_web3.rs:322:51
    |
322 |                         _ => return Err(KslError::web3_error(
    |                                                   ^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `web3_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `web3_error` found for enum `KslError` in the current scope
   --> src\ksl_web3.rs:329:51
    |
329 |                         _ => return Err(KslError::web3_error(
    |                                                   ^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `web3_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `web3_error` found for enum `KslError` in the current scope
   --> src\ksl_web3.rs:339:46
    |
339 |                         return Err(KslError::web3_error(
    |                                              ^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `web3_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `web3_error` found for enum `KslError` in the current scope
   --> src\ksl_web3.rs:347:51
    |
347 |                         _ => return Err(KslError::web3_error(
    |                                                   ^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `web3_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `web3_error` found for enum `KslError` in the current scope
   --> src\ksl_web3.rs:362:46
    |
362 |                         return Err(KslError::web3_error(
    |                                              ^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `web3_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `web3_error` found for enum `KslError` in the current scope
   --> src\ksl_web3.rs:371:51
    |
371 |                         _ => return Err(KslError::web3_error(
    |                                                   ^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `web3_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `web3_error` found for enum `KslError` in the current scope
   --> src\ksl_web3.rs:381:42
    |
381 |                     return Err(KslError::web3_error(
    |                                          ^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `web3_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0308]: mismatched types
   --> src\ksl_vscode.rs:47:67
    |
47  |             .map_err(|e| KslError::type_error(e.to_string(), pos, "E017"))?;
    |                          --------------------                     ^^^^^^- help: try using a conversion method: `.to_string()`
    |                          |                                        |
    |                          |                                        expected `String`, found `&str`
    |                          arguments to this function are incorrect
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------

error[E0061]: this function takes 2 arguments but 1 argument was supplied
  --> src\ksl_vscode.rs:50:26
   |
50 |         let lsp_server = LspServer::new(self.lsp_config.clone());
   |                          ^^^^^^^^^^^^^^------------------------- argument #2 of type `std::string::String` is missing
   |
note: associated function defined here
  --> src\ksl_lsp.rs:95:12
   |
95 |     pub fn new(config: LspServerConfig, workspace_root: String) -> Self {
   |            ^^^                          ----------------------
help: provide the argument
   |
50 -         let lsp_server = LspServer::new(self.lsp_config.clone());
50 +         let lsp_server = LspServer::new(self.lsp_config.clone(), /* std::string::String */);
   |

error[E0599]: no method named `initialize` found for struct `LspServer` in the current scope
  --> src\ksl_vscode.rs:51:20
   |
51 |         lsp_server.initialize().await?;
   |                    ^^^^^^^^^^
   |
  ::: src\ksl_lsp.rs:83:1
   |
83 | pub struct LspServer {
   | -------------------- method `initialize` not found for this struct
   |
   = help: items from traits can only be used if the trait is implemented and in scope
   = note: the following traits define an item `initialize`, perhaps you need to implement one of them:
           candidate #1: `LazyStatic`
           candidate #2: `tokio_stream::stream_ext::collect::sealed::FromStreamPriv`
help: there is a method `italic` with a similar name
   |
51 -         lsp_server.initialize().await?;
51 +         lsp_server.italic().await?;
   |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_stdlib_io.rs:170:26
    |
170 |               .map_err(|e| KslError::type_error(
    |  __________________________^^^^^^^^^^^^^^^^^^^^-
171 | |                 format!("HTTP GET failed: {}", e),
172 | |                 SourcePosition::new(1, 1),
173 | |             ))?;
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
170 -             .map_err(|e| KslError::type_error(
171 -                 format!("HTTP GET failed: {}", e),
172 -                 SourcePosition::new(1, 1),
173 -             ))?;
170 +             .map_err(|e| KslError::type_error(format!("HTTP GET failed: {}", e), SourcePosition::new(1, 1), /* std::string::String */))?;
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_stdlib_io.rs:176:24
    |
176 |               return Err(KslError::type_error(
    |  ________________________^^^^^^^^^^^^^^^^^^^^-
177 | |                 format!("HTTP GET failed with status: {}", response.status()),
178 | |                 SourcePosition::new(1, 1),
179 | |             ));
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
176 -             return Err(KslError::type_error(
177 -                 format!("HTTP GET failed with status: {}", response.status()),
178 -                 SourcePosition::new(1, 1),
179 -             ));
176 +             return Err(KslError::type_error(format!("HTTP GET failed with status: {}", response.status()), SourcePosition::new(1, 1), /* std::string::String */));
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_stdlib_io.rs:184:26
    |
184 |               .map_err(|e| KslError::type_error(
    |  __________________________^^^^^^^^^^^^^^^^^^^^-
185 | |                 format!("Failed to read response: {}", e),
186 | |                 SourcePosition::new(1, 1),
187 | |             ))?;
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
184 -             .map_err(|e| KslError::type_error(
185 -                 format!("Failed to read response: {}", e),
186 -                 SourcePosition::new(1, 1),
187 -             ))?;
184 +             .map_err(|e| KslError::type_error(format!("Failed to read response: {}", e), SourcePosition::new(1, 1), /* std::string::String */))?;
    |

error[E0063]: missing field `threshold` in initializer of `ConsensusRuntime`
   --> src\ksl_kapra_consensus.rs:186:12
    |
186 |         Ok(ConsensusRuntime {
    |            ^^^^^^^^^^^^^^^^ missing `threshold`

error[E0609]: no field `shard_states` on type `tokio::sync::RwLockReadGuard<'_, ConsensusState>`
   --> src\ksl_kapra_consensus.rs:206:33
    |
206 |         let shard_state = state.shard_states.get(&shard_id).ok_or_else(|| {
    |                                 ^^^^^^^^^^^^ unknown field
    |
    = note: available fields are: `height`, `latest_hash`, `validators`, `shards`

error[E0599]: no variant or associated item named `runtime_error` found for enum `KslError` in the current scope
   --> src\ksl_kapra_consensus.rs:207:23
    |
207 |             KslError::runtime_error(
    |                       ^^^^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `runtime_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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
help: there is an associated function `runtime` with a similar name
   --> src\ksl_errors.rs:135:5
    |
135 |     pub fn runtime(message: String, instruction: usize, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

error[E0609]: no field `validator_set` on type `tokio::sync::RwLockReadGuard<'_, ConsensusState>`
   --> src\ksl_kapra_consensus.rs:234:44
    |
234 |                     .filter_map(|id| state.validator_set.get(id))
    |                                            ^^^^^^^^^^^^^ unknown field
    |
help: a field with a similar name exists
    |
234 -                     .filter_map(|id| state.validator_set.get(id))
234 +                     .filter_map(|id| state.validators.get(id))
    |

error[E0609]: no field `validator_set` on type `tokio::sync::RwLockReadGuard<'_, ConsensusState>`
   --> src\ksl_kapra_consensus.rs:240:49
    |
240 |                     .filter_map(|(_, id)| state.validator_set.get(id))
    |                                                 ^^^^^^^^^^^^^ unknown field
    |
help: a field with a similar name exists
    |
240 -                     .filter_map(|(_, id)| state.validator_set.get(id))
240 +                     .filter_map(|(_, id)| state.validators.get(id))
    |

error[E0063]: missing fields `backend_options` and `flags` in initializer of `wgpu::InstanceDescriptor`
   --> src\ksl_kapra_consensus.rs:394:45
    |
394 |         let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor {
    |                                             ^^^^^^^^^^^^^^^^^^^^^^^^ missing `backend_options` and `flags`

error[E0599]: no method named `ok_or_else` found for enum `std::result::Result` in the current scope
   --> src\ksl_kapra_consensus.rs:402:18
    |
398 |           let adapter = instance.request_adapter(&wgpu::RequestAdapterOptions {
    |  _______________________-
399 | |             power_preference: wgpu::PowerPreference::HighPerformance,
400 | |             compatible_surface: None,
401 | |             force_fallback_adapter: false,
402 | |         }).await.ok_or_else(|| "Failed to find GPU adapter".to_string())?;
    | |_________________-^^^^^^^^^^
    |
help: there is a method `or_else` with a similar name
    |
402 -         }).await.ok_or_else(|| "Failed to find GPU adapter".to_string())?;
402 +         }).await.or_else(|| "Failed to find GPU adapter".to_string())?;
    |

error[E0063]: missing field `trace` in initializer of `DeviceDescriptor<std::option::Option<&str>>`
   --> src\ksl_kapra_consensus.rs:405:14
    |
405 |             &wgpu::DeviceDescriptor {
    |              ^^^^^^^^^^^^^^^^^^^^^^ missing `trace`

error[E0308]: mismatched types
   --> src\ksl_kapra_consensus.rs:437:26
    |
437 |             entry_point: "main",
    |                          ^^^^^^ expected `Option<&str>`, found `&str`
    |
    = note:   expected enum `std::option::Option<&str>`
            found reference `&'static str`
help: try wrapping the expression in `Some`
    |
437 |             entry_point: Some("main"),
    |                          +++++      +

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_kapra_shard.rs:236:24
    |
236 |               return Err(KslError::type_error(
    |  ________________________^^^^^^^^^^^^^^^^^^^^-
237 | |                 format!("Invalid shard ID: {}", shard_id),
238 | |                 SourcePosition::new(1, 1),
239 | |             ));
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
236 -             return Err(KslError::type_error(
237 -                 format!("Invalid shard ID: {}", shard_id),
238 -                 SourcePosition::new(1, 1),
239 -             ));
236 +             return Err(KslError::type_error(format!("Invalid shard ID: {}", shard_id), SourcePosition::new(1, 1), /* std::string::String */));
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_kapra_shard.rs:245:13
    |
245 |               KslError::type_error(
    |  _____________^^^^^^^^^^^^^^^^^^^^-
246 | |                 format!("Shard {} not found", shard_id),
247 | |                 SourcePosition::new(1, 1),
248 | |             )
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
245 -             KslError::type_error(
246 -                 format!("Shard {} not found", shard_id),
247 -                 SourcePosition::new(1, 1),
248 -             )
245 +             KslError::type_error(format!("Shard {} not found", shard_id), SourcePosition::new(1, 1), /* std::string::String */)
    |

error[E0599]: no method named `validate_block` found for struct `Arc<ConsensusRuntime>` in the current scope
   --> src\ksl_kapra_shard.rs:252:47
    |
252 |         let is_valid = self.consensus_runtime.validate_block(message, shard_id).await?;
    |                                               ^^^^^^^^^^^^^^
    |
help: there is a method `validate_block_gpu` with a similar name
    |
252 |         let is_valid = self.consensus_runtime.validate_block_gpu(message, shard_id).await?;
    |                                                             ++++

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_kapra_shard.rs:270:13
    |
270 |               KslError::type_error(
    |  _____________^^^^^^^^^^^^^^^^^^^^-
271 | |                 format!("Shard {} not found", shard_id),
272 | |                 SourcePosition::new(1, 1),
273 | |             )
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
270 -             KslError::type_error(
271 -                 format!("Shard {} not found", shard_id),
272 -                 SourcePosition::new(1, 1),
273 -             )
270 +             KslError::type_error(format!("Shard {} not found", shard_id), SourcePosition::new(1, 1), /* std::string::String */)
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_kapra_shard.rs:278:13
    |
278 |               KslError::type_error(
    |  _____________^^^^^^^^^^^^^^^^^^^^-
279 | |                 format!("Failed to serialize shard state: {}", e),
280 | |                 SourcePosition::new(1, 1),
281 | |             )
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
278 -             KslError::type_error(
279 -                 format!("Failed to serialize shard state: {}", e),
280 -                 SourcePosition::new(1, 1),
281 -             )
278 +             KslError::type_error(format!("Failed to serialize shard state: {}", e), SourcePosition::new(1, 1), /* std::string::String */)
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_kapra_shard.rs:335:36
    |
335 |                           return Err(KslError::type_error(
    |  ____________________________________^^^^^^^^^^^^^^^^^^^^-
336 | |                             "Not enough values on stack for SHARD_ROUTE".to_string(),
337 | |                             SourcePosition::new(1, 1),
338 | |                         ));
    | |_________________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
335 -                         return Err(KslError::type_error(
336 -                             "Not enough values on stack for SHARD_ROUTE".to_string(),
337 -                             SourcePosition::new(1, 1),
338 -                         ));
335 +                         return Err(KslError::type_error("Not enough values on stack for SHARD_ROUTE".to_string(), SourcePosition::new(1, 1), /* std::string::String */));
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_kapra_shard.rs:342:36
    |
342 |                           return Err(KslError::type_error(
    |  ____________________________________^^^^^^^^^^^^^^^^^^^^-
343 | |                             "Invalid constant index for SHARD_ROUTE".to_string(),
344 | |                             SourcePosition::new(1, 1),
345 | |                         ));
    | |_________________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
342 -                         return Err(KslError::type_error(
343 -                             "Invalid constant index for SHARD_ROUTE".to_string(),
344 -                             SourcePosition::new(1, 1),
345 -                         ));
342 +                         return Err(KslError::type_error("Invalid constant index for SHARD_ROUTE".to_string(), SourcePosition::new(1, 1), /* std::string::String */));
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_kapra_shard.rs:349:41
    |
349 |                           _ => return Err(KslError::type_error(
    |  _________________________________________^^^^^^^^^^^^^^^^^^^^-
350 | |                             "Invalid type for SHARD_ROUTE argument".to_string(),
351 | |                             SourcePosition::new(1, 1),
352 | |                         )),
    | |_________________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
349 -                         _ => return Err(KslError::type_error(
350 -                             "Invalid type for SHARD_ROUTE argument".to_string(),
351 -                             SourcePosition::new(1, 1),
352 -                         )),
349 +                         _ => return Err(KslError::type_error("Invalid type for SHARD_ROUTE argument".to_string(), SourcePosition::new(1, 1), /* std::string::String */)),
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_kapra_shard.rs:359:36
    |
359 |                           return Err(KslError::type_error(
    |  ____________________________________^^^^^^^^^^^^^^^^^^^^-
360 | |                             "Not enough values on stack for SHARD_SEND".to_string(),
361 | |                             SourcePosition::new(1, 1),
362 | |                         ));
    | |_________________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
359 -                         return Err(KslError::type_error(
360 -                             "Not enough values on stack for SHARD_SEND".to_string(),
361 -                             SourcePosition::new(1, 1),
362 -                         ));
359 +                         return Err(KslError::type_error("Not enough values on stack for SHARD_SEND".to_string(), SourcePosition::new(1, 1), /* std::string::String */));
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_kapra_shard.rs:367:36
    |
367 |                           return Err(KslError::type_error(
    |  ____________________________________^^^^^^^^^^^^^^^^^^^^-
368 | |                             "Invalid constant index for SHARD_SEND".to_string(),
369 | |                             SourcePosition::new(1, 1),
370 | |                         ));
    | |_________________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
367 -                         return Err(KslError::type_error(
368 -                             "Invalid constant index for SHARD_SEND".to_string(),
369 -                             SourcePosition::new(1, 1),
370 -                         ));
367 +                         return Err(KslError::type_error("Invalid constant index for SHARD_SEND".to_string(), SourcePosition::new(1, 1), /* std::string::String */));
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_kapra_shard.rs:374:41
    |
374 |                           _ => return Err(KslError::type_error(
    |  _________________________________________^^^^^^^^^^^^^^^^^^^^-
375 | |                             "Invalid type for SHARD_SEND argument".to_string(),
376 | |                             SourcePosition::new(1, 1),
377 | |                         )),
    | |_________________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
374 -                         _ => return Err(KslError::type_error(
375 -                             "Invalid type for SHARD_SEND argument".to_string(),
376 -                             SourcePosition::new(1, 1),
377 -                         )),
374 +                         _ => return Err(KslError::type_error("Invalid type for SHARD_SEND argument".to_string(), SourcePosition::new(1, 1), /* std::string::String */)),
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_kapra_shard.rs:387:36
    |
387 |                           return Err(KslError::type_error(
    |  ____________________________________^^^^^^^^^^^^^^^^^^^^-
388 | |                             "Not enough values on stack for SHARD_SYNC".to_string(),
389 | |                             SourcePosition::new(1, 1),
390 | |                         ));
    | |_________________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
387 -                         return Err(KslError::type_error(
388 -                             "Not enough values on stack for SHARD_SYNC".to_string(),
389 -                             SourcePosition::new(1, 1),
390 -                         ));
387 +                         return Err(KslError::type_error("Not enough values on stack for SHARD_SYNC".to_string(), SourcePosition::new(1, 1), /* std::string::String */));
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_kapra_shard.rs:397:36
    |
397 |                           return Err(KslError::type_error(
    |  ____________________________________^^^^^^^^^^^^^^^^^^^^-
398 | |                             "Incomplete PUSH instruction".to_string(),
399 | |                             SourcePosition::new(1, 1),
400 | |                         ));
    | |_________________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
397 -                         return Err(KslError::type_error(
398 -                             "Incomplete PUSH instruction".to_string(),
399 -                             SourcePosition::new(1, 1),
400 -                         ));
397 +                         return Err(KslError::type_error("Incomplete PUSH instruction".to_string(), SourcePosition::new(1, 1), /* std::string::String */));
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_kapra_shard.rs:408:36
    |
408 |                           return Err(KslError::type_error(
    |  ____________________________________^^^^^^^^^^^^^^^^^^^^-
409 | |                             "Stack underflow".to_string(),
410 | |                             SourcePosition::new(1, 1),
411 | |                         ));
    | |_________________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
408 -                         return Err(KslError::type_error(
409 -                             "Stack underflow".to_string(),
410 -                             SourcePosition::new(1, 1),
411 -                         ));
408 +                         return Err(KslError::type_error("Stack underflow".to_string(), SourcePosition::new(1, 1), /* std::string::String */));
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_kapra_shard.rs:415:33
    |
415 |                   _ => return Err(KslError::type_error(
    |  _________________________________^^^^^^^^^^^^^^^^^^^^-
416 | |                     format!("Unsupported opcode: {}", instr),
417 | |                     SourcePosition::new(1, 1),
418 | |                 )),
    | |_________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
415 -                 _ => return Err(KslError::type_error(
416 -                     format!("Unsupported opcode: {}", instr),
417 -                     SourcePosition::new(1, 1),
418 -                 )),
415 +                 _ => return Err(KslError::type_error(format!("Unsupported opcode: {}", instr), SourcePosition::new(1, 1), /* std::string::String */)),
    |

warning: use of deprecated method `rand::Rng::gen_range`: Renamed to `random_range`
   --> src\ksl_kapra_shard.rs:573:47
    |
573 |                     gas += rand::thread_rng().gen_range(1000..10000);
    |                                               ^^^^^^^^^

error[E0560]: struct `ksl_metrics::BlockResult` has no field named `kaprekar_pass_ratio`
   --> src\ksl_kapra_shard.rs:601:9
    |
601 |         kaprekar_pass_ratio: kaprekar_ratio,
    |         ^^^^^^^^^^^^^^^^^^^ unknown field
    |
help: a field with a similar name exists
    |
601 -         kaprekar_pass_ratio: kaprekar_ratio,
601 +         kaprekar_ratio: kaprekar_ratio,
    |

error[E0616]: field `stack` of struct `kapra_vm::KapraVM` is private
   --> src\ksl_kapra_validator.rs:190:29
    |
190 |                     if self.stack.len() < 1 {
    |                             ^^^^^ private field

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_kapra_validator.rs:191:36
    |
191 |                           return Err(KslError::type_error(
    |  ____________________________________^^^^^^^^^^^^^^^^^^^^-
192 | |                             "Not enough values on stack for SHA3".to_string(),
193 | |                             SourcePosition::new(1, 1),
194 | |                         ));
    | |_________________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
191 -                         return Err(KslError::type_error(
192 -                             "Not enough values on stack for SHA3".to_string(),
193 -                             SourcePosition::new(1, 1),
194 -                         ));
191 +                         return Err(KslError::type_error("Not enough values on stack for SHA3".to_string(), SourcePosition::new(1, 1), /* std::string::String */));
    |

error[E0616]: field `stack` of struct `kapra_vm::KapraVM` is private
   --> src\ksl_kapra_validator.rs:196:42
    |
196 |                     let input_idx = self.stack.pop().unwrap() as usize;
    |                                          ^^^^^ private field

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_kapra_validator.rs:199:41
    |
199 |                           _ => return Err(KslError::type_error(
    |  _________________________________________^^^^^^^^^^^^^^^^^^^^-
200 | |                             "Invalid type for SHA3 argument".to_string(),
201 | |                             SourcePosition::new(1, 1),
202 | |                         )),
    | |_________________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
199 -                         _ => return Err(KslError::type_error(
200 -                             "Invalid type for SHA3 argument".to_string(),
201 -                             SourcePosition::new(1, 1),
202 -                         )),
199 +                         _ => return Err(KslError::type_error("Invalid type for SHA3 argument".to_string(), SourcePosition::new(1, 1), /* std::string::String */)),
    |

error[E0616]: field `crypto` of struct `kapra_vm::KapraVM` is private
   --> src\ksl_kapra_validator.rs:204:37
    |
204 |                     let hash = self.crypto.sha3(&input[..]);
    |                                     ^^^^^^ private field

error[E0616]: field `stack` of struct `kapra_vm::KapraVM` is private
   --> src\ksl_kapra_validator.rs:206:26
    |
206 |                     self.stack.push(const_idx as u64);
    |                          ^^^^^ private field

error[E0616]: field `stack` of struct `kapra_vm::KapraVM` is private
   --> src\ksl_kapra_validator.rs:213:29
    |
213 |                     if self.stack.len() < 3 {
    |                             ^^^^^ private field

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_kapra_validator.rs:214:36
    |
214 |                           return Err(KslError::type_error(
    |  ____________________________________^^^^^^^^^^^^^^^^^^^^-
215 | |                             "Not enough values on stack for DIL_VERIFY".to_string(),
216 | |                             SourcePosition::new(1, 1),
217 | |                         ));
    | |_________________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
214 -                         return Err(KslError::type_error(
215 -                             "Not enough values on stack for DIL_VERIFY".to_string(),
216 -                             SourcePosition::new(1, 1),
217 -                         ));
214 +                         return Err(KslError::type_error("Not enough values on stack for DIL_VERIFY".to_string(), SourcePosition::new(1, 1), /* std::string::String */));
    |

error[E0616]: field `stack` of struct `kapra_vm::KapraVM` is private
   --> src\ksl_kapra_validator.rs:219:40
    |
219 |                     let sig_idx = self.stack.pop().unwrap() as usize;
    |                                        ^^^^^ private field

error[E0616]: field `stack` of struct `kapra_vm::KapraVM` is private
   --> src\ksl_kapra_validator.rs:220:43
    |
220 |                     let pubkey_idx = self.stack.pop().unwrap() as usize;
    |                                           ^^^^^ private field

error[E0616]: field `stack` of struct `kapra_vm::KapraVM` is private
   --> src\ksl_kapra_validator.rs:221:40
    |
221 |                     let msg_idx = self.stack.pop().unwrap() as usize;
    |                                        ^^^^^ private field

error[E0614]: type `[u8; 32]` cannot be dereferenced
   --> src\ksl_kapra_validator.rs:223:67
    |
223 |                         Constant::Array32(arr) => FixedArray::new(*arr),
    |                                                                   ^^^^

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_kapra_validator.rs:224:41
    |
224 |                           _ => return Err(KslError::type_error(
    |  _________________________________________^^^^^^^^^^^^^^^^^^^^-
225 | |                             "Invalid type for DIL_VERIFY message".to_string(),
226 | |                             SourcePosition::new(1, 1),
227 | |                         )),
    | |_________________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
224 -                         _ => return Err(KslError::type_error(
225 -                             "Invalid type for DIL_VERIFY message".to_string(),
226 -                             SourcePosition::new(1, 1),
227 -                         )),
224 +                         _ => return Err(KslError::type_error("Invalid type for DIL_VERIFY message".to_string(), SourcePosition::new(1, 1), /* std::string::String */)),
    |

error[E0614]: type `[u8; 1312]` cannot be dereferenced
   --> src\ksl_kapra_validator.rs:230:69
    |
230 |                         Constant::Array1312(arr) => FixedArray::new(*arr),
    |                                                                     ^^^^

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_kapra_validator.rs:231:41
    |
231 |                           _ => return Err(KslError::type_error(
    |  _________________________________________^^^^^^^^^^^^^^^^^^^^-
232 | |                             "Invalid type for DIL_VERIFY pubkey".to_string(),
233 | |                             SourcePosition::new(1, 1),
234 | |                         )),
    | |_________________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
231 -                         _ => return Err(KslError::type_error(
232 -                             "Invalid type for DIL_VERIFY pubkey".to_string(),
233 -                             SourcePosition::new(1, 1),
234 -                         )),
231 +                         _ => return Err(KslError::type_error("Invalid type for DIL_VERIFY pubkey".to_string(), SourcePosition::new(1, 1), /* std::string::String */)),
    |

error[E0614]: type `[u8; 2420]` cannot be dereferenced
   --> src\ksl_kapra_validator.rs:237:69
    |
237 |                         Constant::Array2420(arr) => FixedArray::new(*arr),
    |                                                                     ^^^^

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_kapra_validator.rs:238:41
    |
238 |                           _ => return Err(KslError::type_error(
    |  _________________________________________^^^^^^^^^^^^^^^^^^^^-
239 | |                             "Invalid type for DIL_VERIFY signature".to_string(),
240 | |                             SourcePosition::new(1, 1),
241 | |                         )),
    | |_________________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
238 -                         _ => return Err(KslError::type_error(
239 -                             "Invalid type for DIL_VERIFY signature".to_string(),
240 -                             SourcePosition::new(1, 1),
241 -                         )),
238 +                         _ => return Err(KslError::type_error("Invalid type for DIL_VERIFY signature".to_string(), SourcePosition::new(1, 1), /* std::string::String */)),
    |

error[E0616]: field `crypto` of struct `kapra_vm::KapraVM` is private
   --> src\ksl_kapra_validator.rs:243:39
    |
243 |                     let result = self.crypto.dil_verify(&message, &pubkey, &signature);
    |                                       ^^^^^^ private field

error[E0616]: field `stack` of struct `kapra_vm::KapraVM` is private
   --> src\ksl_kapra_validator.rs:244:26
    |
244 |                     self.stack.push(result as u64);
    |                          ^^^^^ private field

error[E0616]: field `stack` of struct `kapra_vm::KapraVM` is private
   --> src\ksl_kapra_validator.rs:247:29
    |
247 |                     if self.stack.len() < 2 {
    |                             ^^^^^ private field

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_kapra_validator.rs:248:36
    |
248 |                           return Err(KslError::type_error(
    |  ____________________________________^^^^^^^^^^^^^^^^^^^^-
249 | |                             "Not enough values on stack for VALIDATE_CONTRACT".to_string(),
250 | |                             SourcePosition::new(1, 1),
251 | |                         ));
    | |_________________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
248 -                         return Err(KslError::type_error(
249 -                             "Not enough values on stack for VALIDATE_CONTRACT".to_string(),
250 -                             SourcePosition::new(1, 1),
251 -                         ));
248 +                         return Err(KslError::type_error("Not enough values on stack for VALIDATE_CONTRACT".to_string(), SourcePosition::new(1, 1), /* std::string::String */));
    |

error[E0616]: field `stack` of struct `kapra_vm::KapraVM` is private
   --> src\ksl_kapra_validator.rs:253:45
    |
253 |                     let contract_idx = self.stack.pop().unwrap() as usize;
    |                                             ^^^^^ private field

error[E0616]: field `stack` of struct `kapra_vm::KapraVM` is private
   --> src\ksl_kapra_validator.rs:254:45
    |
254 |                     let function_idx = self.stack.pop().unwrap() as usize;
    |                                             ^^^^^ private field

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_kapra_validator.rs:257:41
    |
257 |                           _ => return Err(KslError::type_error(
    |  _________________________________________^^^^^^^^^^^^^^^^^^^^-
258 | |                             "Invalid type for VALIDATE_CONTRACT contract".to_string(),
259 | |                             SourcePosition::new(1, 1),
260 | |                         )),
    | |_________________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
257 -                         _ => return Err(KslError::type_error(
258 -                             "Invalid type for VALIDATE_CONTRACT contract".to_string(),
259 -                             SourcePosition::new(1, 1),
260 -                         )),
257 +                         _ => return Err(KslError::type_error("Invalid type for VALIDATE_CONTRACT contract".to_string(), SourcePosition::new(1, 1), /* std::string::String */)),
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_kapra_validator.rs:264:41
    |
264 |                           _ => return Err(KslError::type_error(
    |  _________________________________________^^^^^^^^^^^^^^^^^^^^-
265 | |                             "Invalid type for VALIDATE_CONTRACT function".to_string(),
266 | |                             SourcePosition::new(1, 1),
267 | |                         )),
    | |_________________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
264 -                         _ => return Err(KslError::type_error(
265 -                             "Invalid type for VALIDATE_CONTRACT function".to_string(),
266 -                             SourcePosition::new(1, 1),
267 -                         )),
264 +                         _ => return Err(KslError::type_error("Invalid type for VALIDATE_CONTRACT function".to_string(), SourcePosition::new(1, 1), /* std::string::String */)),
    |

error[E0609]: no field `validator_state` on type `&mut kapra_vm::KapraVM`
   --> src\ksl_kapra_validator.rs:271:48
    |
271 |                     let validator_state = self.validator_state.read().await;
    |                                                ^^^^^^^^^^^^^^^ unknown field

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_kapra_validator.rs:273:25
    |
273 |                           KslError::type_error(
    |  _________________________^^^^^^^^^^^^^^^^^^^^-
274 | |                             format!("Contract {} not found", hex::encode(contract)),
275 | |                             SourcePosition::new(1, 1),
276 | |                         )
    | |_________________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
273 -                         KslError::type_error(
274 -                             format!("Contract {} not found", hex::encode(contract)),
275 -                             SourcePosition::new(1, 1),
276 -                         )
273 +                         KslError::type_error(format!("Contract {} not found", hex::encode(contract)), SourcePosition::new(1, 1), /* std::string::String */)
    |

error[E0609]: no field `contract_compiler` on type `&mut kapra_vm::KapraVM`
   --> src\ksl_kapra_validator.rs:280:39
    |
280 |                     let result = self.contract_compiler.execute_async(contract_state, function, vec![]).await?;
    |                                       ^^^^^^^^^^^^^^^^^ unknown field

error[E0616]: field `stack` of struct `kapra_vm::KapraVM` is private
   --> src\ksl_kapra_validator.rs:281:26
    |
281 |                     self.stack.push(match result {
    |                          ^^^^^ private field

error[E0616]: field `stack` of struct `kapra_vm::KapraVM` is private
   --> src\ksl_kapra_validator.rs:287:29
    |
287 |                     if self.stack.len() < 1 {
    |                             ^^^^^ private field

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_kapra_validator.rs:288:36
    |
288 |                           return Err(KslError::type_error(
    |  ____________________________________^^^^^^^^^^^^^^^^^^^^-
289 | |                             "Not enough values on stack for VALIDATE_CONSENSUS".to_string(),
290 | |                             SourcePosition::new(1, 1),
291 | |                         ));
    | |_________________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
288 -                         return Err(KslError::type_error(
289 -                             "Not enough values on stack for VALIDATE_CONSENSUS".to_string(),
290 -                             SourcePosition::new(1, 1),
291 -                         ));
288 +                         return Err(KslError::type_error("Not enough values on stack for VALIDATE_CONSENSUS".to_string(), SourcePosition::new(1, 1), /* std::string::String */));
    |

error[E0616]: field `stack` of struct `kapra_vm::KapraVM` is private
   --> src\ksl_kapra_validator.rs:293:42
    |
293 |                     let block_idx = self.stack.pop().unwrap() as usize;
    |                                          ^^^^^ private field

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_kapra_validator.rs:296:41
    |
296 |                           _ => return Err(KslError::type_error(
    |  _________________________________________^^^^^^^^^^^^^^^^^^^^-
297 | |                             "Invalid type for VALIDATE_CONSENSUS block".to_string(),
298 | |                             SourcePosition::new(1, 1),
299 | |                         )),
    | |_________________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
296 -                         _ => return Err(KslError::type_error(
297 -                             "Invalid type for VALIDATE_CONSENSUS block".to_string(),
298 -                             SourcePosition::new(1, 1),
299 -                         )),
296 +                         _ => return Err(KslError::type_error("Invalid type for VALIDATE_CONSENSUS block".to_string(), SourcePosition::new(1, 1), /* std::string::String */)),
    |

error[E0609]: no field `consensus_runtime` on type `&mut kapra_vm::KapraVM`
   --> src\ksl_kapra_validator.rs:303:41
    |
303 |                     let is_valid = self.consensus_runtime.validate_block(block, 0).await?;
    |                                         ^^^^^^^^^^^^^^^^^ unknown field

error[E0616]: field `stack` of struct `kapra_vm::KapraVM` is private
   --> src\ksl_kapra_validator.rs:304:26
    |
304 |                     self.stack.push(is_valid as u64);
    |                          ^^^^^ private field

error[E0609]: no field `validator_state` on type `&mut kapra_vm::KapraVM`
   --> src\ksl_kapra_validator.rs:307:52
    |
307 |                     let mut validator_state = self.validator_state.write().await;
    |                                                    ^^^^^^^^^^^^^^^ unknown field

error[E0614]: type `[u8; 32]` cannot be dereferenced
   --> src\ksl_kapra_validator.rs:308:60
    |
308 |                     validator_state.last_validated_block = *block;
    |                                                            ^^^^^^

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_kapra_validator.rs:312:36
    |
312 |                           return Err(KslError::type_error(
    |  ____________________________________^^^^^^^^^^^^^^^^^^^^-
313 | |                             "Incomplete PUSH instruction".to_string(),
314 | |                             SourcePosition::new(1, 1),
315 | |                         ));
    | |_________________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
312 -                         return Err(KslError::type_error(
313 -                             "Incomplete PUSH instruction".to_string(),
314 -                             SourcePosition::new(1, 1),
315 -                         ));
312 +                         return Err(KslError::type_error("Incomplete PUSH instruction".to_string(), SourcePosition::new(1, 1), /* std::string::String */));
    |

error[E0616]: field `stack` of struct `kapra_vm::KapraVM` is private
   --> src\ksl_kapra_validator.rs:319:26
    |
319 |                     self.stack.push(value);
    |                          ^^^^^ private field

error[E0616]: field `stack` of struct `kapra_vm::KapraVM` is private
   --> src\ksl_kapra_validator.rs:322:29
    |
322 |                     if self.stack.is_empty() {
    |                             ^^^^^ private field

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_kapra_validator.rs:323:36
    |
323 |                           return Err(KslError::type_error(
    |  ____________________________________^^^^^^^^^^^^^^^^^^^^-
324 | |                             "Stack underflow".to_string(),
325 | |                             SourcePosition::new(1, 1),
326 | |                         ));
    | |_________________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
323 -                         return Err(KslError::type_error(
324 -                             "Stack underflow".to_string(),
325 -                             SourcePosition::new(1, 1),
326 -                         ));
323 +                         return Err(KslError::type_error("Stack underflow".to_string(), SourcePosition::new(1, 1), /* std::string::String */));
    |

error[E0616]: field `stack` of struct `kapra_vm::KapraVM` is private
   --> src\ksl_kapra_validator.rs:328:26
    |
328 |                     self.stack.pop();
    |                          ^^^^^ private field

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_kapra_validator.rs:330:33
    |
330 |                   _ => return Err(KslError::type_error(
    |  _________________________________^^^^^^^^^^^^^^^^^^^^-
331 | |                     format!("Unsupported opcode: {}", instr),
332 | |                     SourcePosition::new(1, 1),
333 | |                 )),
    | |_________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
330 -                 _ => return Err(KslError::type_error(
331 -                     format!("Unsupported opcode: {}", instr),
332 -                     SourcePosition::new(1, 1),
333 -                 )),
330 +                 _ => return Err(KslError::type_error(format!("Unsupported opcode: {}", instr), SourcePosition::new(1, 1), /* std::string::String */)),
    |

error[E0616]: field `stack` of struct `kapra_vm::KapraVM` is private
   --> src\ksl_kapra_validator.rs:338:17
    |
338 |         if self.stack.len() != 1 {
    |                 ^^^^^ private field

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_kapra_validator.rs:339:24
    |
339 |               return Err(KslError::type_error(
    |  ________________________^^^^^^^^^^^^^^^^^^^^-
340 | |                 "Validator block must return exactly one boolean value".to_string(),
341 | |                 SourcePosition::new(1, 1),
342 | |             ));
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
339 -             return Err(KslError::type_error(
340 -                 "Validator block must return exactly one boolean value".to_string(),
341 -                 SourcePosition::new(1, 1),
342 -             ));
339 +             return Err(KslError::type_error("Validator block must return exactly one boolean value".to_string(), SourcePosition::new(1, 1), /* std::string::String */));
    |

error[E0616]: field `stack` of struct `kapra_vm::KapraVM` is private
   --> src\ksl_kapra_validator.rs:344:17
    |
344 |         Ok(self.stack[0] != 0)
    |                 ^^^^^ private field

error[E0308]: mismatched types
   --> src\ksl_bundler.rs:103:15
    |
103 |         check(&ast[..])
    |         ----- ^^^^^^^^ expected `ksl_ast::AstNode`, found `ksl_macros::AstNode`
    |         |
    |         arguments to this function are incorrect
    |
    = note: `ksl_macros::AstNode` and `ksl_ast::AstNode` have similar names, but are actually distinct types
note: `ksl_macros::AstNode` is defined in module `crate::ksl_macros` of the current crate
   --> src\ksl_macros.rs:439:1
    |
439 | pub enum AstNode {
    | ^^^^^^^^^^^^^^^^
note: `ksl_ast::AstNode` is defined in module `crate::ksl_ast` of the current crate
   --> src\ksl_ast.rs:244:1
    |
244 | pub enum AstNode {
    | ^^^^^^^^^^^^^^^^
note: function defined here
   --> src\ksl_checker.rs:651:8
    |
651 | pub fn check(nodes: &[AstNode]) -> Result<(), Vec<TypeError>> {
    |        ^^^^^ -----------------

error[E0061]: this function takes 7 arguments but 1 argument was supplied
   --> src\ksl_bundler.rs:112:28
    |
112 |         let mut bytecode = compile(&ast)
    |                            ^^^^^^^------ multiple arguments are missing
    |
note: expected `&[AstNode]`, found `&Vec<AstNode>`
   --> src\ksl_bundler.rs:112:36
    |
112 |         let mut bytecode = compile(&ast)
    |                                    ^^^^
    = note: expected reference `&[ksl_ast::AstNode]`
               found reference `&Vec<ksl_macros::AstNode>`
note: function defined here
   --> src\ksl_compiler.rs:803:8
    |
803 | pub fn compile(
    |        ^^^^^^^
804 |     ast: &[AstNode],
    |     ---------------
805 |     module_name: &str,
    |     -----------------
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
112 -         let mut bytecode = compile(&ast)
112 +         let mut bytecode = compile(/* &[ksl_ast::AstNode] */, /* &str */, /* CompileTarget */, /* &str */, /* &ksl_analyzer::PerformanceMetrics */, /* bool */, /* std::option::Option<ksl_macros::HotReloadConfig> */)
    |

error[E0599]: `KslError` is not an iterator
   --> src\ksl_bundler.rs:114:24
    |
114 |                 errors.into_iter()
    |                        ^^^^^^^^^ `KslError` is not an iterator
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- method `into_iter` not found for this enum because it doesn't satisfy `KslError: IntoIterator` or `KslError: Iterator`
    |
    = note: the following trait bounds were not satisfied:
            `KslError: Iterator`
            which is required by `KslError: IntoIterator`
            `&KslError: Iterator`
            which is required by `&KslError: IntoIterator`
            `&mut KslError: Iterator`
            which is required by `&mut KslError: IntoIterator`
note: the trait `Iterator` must be implemented
   --> /rustc/05f9846f893b09a1be1fc8560e33fc3c815cfecb\library\core\src\iter\traits\iterator.rs:39:1
    = help: items from traits can only be used if the trait is implemented and in scope
    = note: the following traits define an item `into_iter`, perhaps you need to implement one of them:
            candidate #1: `IntoIterator`
            candidate #2: `rayon::iter::plumbing::Producer`

error[E0308]: mismatched types
   --> src\ksl_bundler.rs:123:18
    |
123 |         optimize(&mut bytecode)
    |         -------- ^^^^^^^^^^^^^ expected `KapraBytecode`, found `&mut (String, OptimizationFeedback)`
    |         |
    |         arguments to this function are incorrect
    |
    = note:         expected struct `KapraBytecode`
            found mutable reference `&mut (std::string::String, OptimizationFeedback)`
note: function defined here
   --> src\ksl_optimizer.rs:708:8
    |
708 | pub fn optimize(bytecode: KapraBytecode) -> Result<KapraBytecode, Vec<OptError>> {
    |        ^^^^^^^^ -----------------------

error[E0277]: `KslError` doesn't implement `std::fmt::Debug`
   --> src\ksl_bundler.rs:124:93
    |
124 | ...de optimization failed: {:?}", e), pos, "E0006".to_string()))?;
    |                                   ^ `KslError` cannot be formatted using `{:?}`
    |
    = help: the trait `std::fmt::Debug` is not implemented for `KslError`
    = note: add `#[derive(Debug)]` to `KslError` or manually `impl std::fmt::Debug for KslError`
    = help: the trait `std::fmt::Debug` is implemented for `Vec<T, A>`
    = note: this error originates in the macro `$crate::__export::format_args` which comes from the expansion of the macro `format` (in Nightly builds, run with -Z macro-backtrace for more info)
help: consider annotating `KslError` with `#[derive(Debug)]`
   --> src\ksl_errors.rs:58:1
    |
58  + #[derive(Debug)]
59  | pub enum KslError {
    |

error[E0616]: field `repository` of struct `ksl_package::PackageSystem` is private
   --> src\ksl_bundler.rs:175:46
    |
175 |                 let dep_dir = package_system.repository.join(&dep_name).join(&dep_version).join("src");
    |                                              ^^^^^^^^^^ private field

error[E0308]: mismatched types
   --> src\ksl_bundler.rs:229:16
    |
229 |         if let Some(output_file) = &self.config.output_file {
    |                ^^^^^^^^^^^^^^^^^   ------------------------ this expression has type `&PathBuf`
    |                |
    |                expected `PathBuf`, found `Option<_>`
    |
    = note: expected struct `PathBuf`
                 found enum `std::option::Option<_>`

error[E0599]: no variant or associated item named `new` found for enum `KslError` in the current scope
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
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `RuntimeError` found for enum `ErrorType` in the current scope
   --> src\ksl_dev_tools.rs:127:51
    |
127 |             .map_err(|e| KslError::new(ErrorType::RuntimeError, e.to_string()))
    |                                                   ^^^^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `RuntimeError` not found for this enum

error[E0599]: no method named `set_breakpoint` found for struct `tokio::sync::MutexGuard<'_, ksl_debug::Debugger>` in the current scope
   --> src\ksl_dev_tools.rs:133:18
    |
133 |         debugger.set_breakpoint(bp)
    |                  ^^^^^^^^^^^^^^
    |
help: there is a method `has_breakpoint` with a similar name
    |
133 -         debugger.set_breakpoint(bp)
133 +         debugger.has_breakpoint(bp)
    |

error[E0599]: no variant or associated item named `new` found for enum `KslError` in the current scope
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
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `DebugError` found for enum `ErrorType` in the current scope
   --> src\ksl_dev_tools.rs:134:51
    |
134 |             .map_err(|e| KslError::new(ErrorType::DebugError, e.to_string()))
    |                                                   ^^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `DebugError` not found for this enum

error[E0599]: no variant or associated item named `new` found for enum `KslError` in the current scope
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
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `AsyncError` found for enum `ErrorType` in the current scope
   --> src\ksl_dev_tools.rs:143:51
    |
143 |             .map_err(|e| KslError::new(ErrorType::AsyncError, e.to_string()))
    |                                                   ^^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `AsyncError` not found for this enum

error[E0599]: no variant or associated item named `new` found for enum `KslError` in the current scope
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
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `AsyncError` found for enum `ErrorType` in the current scope
   --> src\ksl_dev_tools.rs:152:51
    |
152 |             .map_err(|e| KslError::new(ErrorType::AsyncError, e.to_string()))
    |                                                   ^^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `AsyncError` not found for this enum

error[E0599]: no method named `get_state` found for struct `tokio::sync::MutexGuard<'_, ksl_debug::Debugger>` in the current scope
   --> src\ksl_dev_tools.rs:158:18
    |
158 |         debugger.get_state()
    |                  ^^^^^^^^^ method not found in `MutexGuard<'_, Debugger>`

error[E0599]: no variant or associated item named `new` found for enum `KslError` in the current scope
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
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `DebugError` found for enum `ErrorType` in the current scope
   --> src\ksl_dev_tools.rs:159:51
    |
159 |             .map_err(|e| KslError::new(ErrorType::DebugError, e.to_string()))
    |                                                   ^^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `DebugError` not found for this enum

error[E0599]: no method named `add_watchpoint` found for struct `tokio::sync::MutexGuard<'_, ksl_debug::Debugger>` in the current scope
   --> src\ksl_dev_tools.rs:165:18
    |
165 |         debugger.add_watchpoint(wp)
    |                  ^^^^^^^^^^^^^^ method not found in `MutexGuard<'_, Debugger>`

error[E0599]: no variant or associated item named `new` found for enum `KslError` in the current scope
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
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `DebugError` found for enum `ErrorType` in the current scope
   --> src\ksl_dev_tools.rs:166:51
    |
166 |             .map_err(|e| KslError::new(ErrorType::DebugError, e.to_string()))
    |                                                   ^^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `DebugError` not found for this enum

error[E0599]: no variant or associated item named `new` found for enum `KslError` in the current scope
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
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `StackUnderflow` found for enum `ErrorType` in the current scope
   --> src\ksl_dev_tools.rs:198:61
    |
198 | ...ror::new(ErrorType::StackUnderflow, "Not enough values on stack for LOG".to_string()));
    |                        ^^^^^^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `StackUnderflow` not found for this enum

error[E0599]: no variant or associated item named `new` found for enum `KslError` in the current scope
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
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `TypeError` found for enum `ErrorType` in the current scope
   --> src\ksl_dev_tools.rs:203:66
    |
203 | ...lError::new(ErrorType::TypeError, "Invalid type for LOG message".to_string())),
    |                           ^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `TypeError` not found for this enum

error[E0599]: no variant or associated item named `new` found for enum `KslError` in the current scope
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
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `StackUnderflow` found for enum `ErrorType` in the current scope
   --> src\ksl_dev_tools.rs:215:61
    |
215 | ...ror::new(ErrorType::StackUnderflow, "Not enough values on stack for MEASURE".to_string()));
    |                        ^^^^^^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `StackUnderflow` not found for this enum

error[E0599]: no variant or associated item named `new` found for enum `KslError` in the current scope
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
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `TypeError` found for enum `ErrorType` in the current scope
   --> src\ksl_dev_tools.rs:220:66
    |
220 | ...lError::new(ErrorType::TypeError, "Invalid type for MEASURE task".to_string())),
    |                           ^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `TypeError` not found for this enum

error[E0599]: no variant or associated item named `new` found for enum `KslError` in the current scope
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
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `StackUnderflow` found for enum `ErrorType` in the current scope
   --> src\ksl_dev_tools.rs:232:61
    |
232 | ...ror::new(ErrorType::StackUnderflow, "Not enough values on stack for GENERATE_DIAGRAM".to_string()));
    |                        ^^^^^^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `StackUnderflow` not found for this enum

error[E0599]: no variant or associated item named `new` found for enum `KslError` in the current scope
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
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `TypeError` found for enum `ErrorType` in the current scope
   --> src\ksl_dev_tools.rs:237:66
    |
237 | ...lError::new(ErrorType::TypeError, "Invalid type for GENERATE_DIAGRAM data".to_string())),
    |                           ^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `TypeError` not found for this enum

error[E0599]: no variant or associated item named `new` found for enum `KslError` in the current scope
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
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `InvalidInstruction` found for enum `ErrorType` in the current scope
   --> src\ksl_dev_tools.rs:244:61
    |
244 | ...r::new(ErrorType::InvalidInstruction, "Incomplete PUSH instruction".to_string()));
    |                      ^^^^^^^^^^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `InvalidInstruction` not found for this enum

error[E0599]: no variant or associated item named `new` found for enum `KslError` in the current scope
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
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `RuntimeError` found for enum `ErrorType` in the current scope
   --> src\ksl_dev_tools.rs:251:57
    |
251 | ...   return Err(KslError::new(ErrorType::RuntimeError, "Developer tools operation failed".to_string()));
    |                                           ^^^^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `RuntimeError` not found for this enum

error[E0599]: no variant or associated item named `new` found for enum `KslError` in the current scope
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
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `InvalidInstruction` found for enum `ErrorType` in the current scope
   --> src\ksl_dev_tools.rs:253:58
    |
253 | ...r::new(ErrorType::InvalidInstruction, format!("Unsupported opcode: {}", instr))),
    |                      ^^^^^^^^^^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `InvalidInstruction` not found for this enum

error[E0599]: no variant or associated item named `new` found for enum `KslError` in the current scope
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
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `StackError` found for enum `ErrorType` in the current scope
   --> src\ksl_dev_tools.rs:258:49
    |
258 | ...   return Err(KslError::new(ErrorType::StackError, "Developer tools block must return exactly one value".to...
    |                                           ^^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `StackError` not found for this enum

error[E0599]: no method named `start_async` found for struct `Arc<LspServer>` in the current scope
   --> src\ksl_doc_lsp.rs:118:25
    |
118 |         self.lsp_server.start_async().await?;
    |                         ^^^^^^^^^^^ method not found in `Arc<LspServer>`

error[E0599]: no method named `register_handler` found for struct `Arc<LspServer>` in the current scope
   --> src\ksl_doc_lsp.rs:129:16
    |
129 |         server.register_handler("textDocument/documentSymbol", move |params: Value| {
    |         -------^^^^^^^^^^^^^^^^ method not found in `Arc<LspServer>`

error[E0599]: no method named `get_document_symbols` found for struct `tokio::sync::RwLockReadGuard<'_, DocLspState>` in the current scope
   --> src\ksl_doc_lsp.rs:132:50
    |
132 | ...te.read().await.get_document_symbols(&params["textDocument"]["uri"].as_str().unwrap());
    |                    ^^^^^^^^^^^^^^^^^^^^ method not found in `RwLockReadGuard<'_, DocLspState>`

error[E0599]: no method named `register_handler` found for struct `Arc<LspServer>` in the current scope
   --> src\ksl_doc_lsp.rs:140:16
    |
140 |         server.register_handler("textDocument/hover", move |params: Value| {
    |         -------^^^^^^^^^^^^^^^^ method not found in `Arc<LspServer>`

error[E0599]: no method named `get_hover_info` found for struct `tokio::sync::RwLockReadGuard<'_, DocLspState>` in the current scope
   --> src\ksl_doc_lsp.rs:144:53
    |
144 |                 let hover_info = state.read().await.get_hover_info(
    |                                  -------------------^^^^^^^^^^^^^^ method not found in `RwLockReadGuard<'_, DocLspState>`

error[E0599]: no method named `register_handler` found for struct `Arc<LspServer>` in the current scope
   --> src\ksl_doc_lsp.rs:158:20
    |
158 |             server.register_handler("textDocument/semanticTokens/full", move |params: Value| {
    |             -------^^^^^^^^^^^^^^^^ method not found in `Arc<LspServer>`

error[E0599]: no method named `get_semantic_tokens` found for struct `tokio::sync::RwLockReadGuard<'_, DocLspState>` in the current scope
   --> src\ksl_doc_lsp.rs:161:53
    |
161 | ...te.read().await.get_semantic_tokens(&params["textDocument"]["uri"].as_str().unwrap());
    |                    ^^^^^^^^^^^^^^^^^^^ method not found in `RwLockReadGuard<'_, DocLspState>`

error[E0599]: no method named `register_handler` found for struct `Arc<LspServer>` in the current scope
   --> src\ksl_doc_lsp.rs:170:16
    |
170 |         server.register_handler("textDocument/diagnostics", move |params: Value| {
    |         -------^^^^^^^^^^^^^^^^ method not found in `Arc<LspServer>`

error[E0599]: no method named `get_diagnostics` found for struct `tokio::sync::RwLockReadGuard<'_, DocLspState>` in the current scope
   --> src\ksl_doc_lsp.rs:173:54
    |
173 | ...tate.read().await.get_diagnostics(&params["textDocument"]["uri"].as_str().unwrap());
    |                      ^^^^^^^^^^^^^^^ method not found in `RwLockReadGuard<'_, DocLspState>`

warning: unused variable: `doc`
   --> src\ksl_doc_lsp.rs:189:20
    |
189 |         for (name, doc) in &state.doc_cache {
    |                    ^^^ help: if this is intentional, prefix it with an underscore: `_doc`

warning: unused variable: `doc`
   --> src\ksl_doc_lsp.rs:204:20
    |
204 |         for (name, doc) in &state.macro_docs {
    |                    ^^^ help: if this is intentional, prefix it with an underscore: `_doc`

warning: unused variable: `abi`
   --> src\ksl_doc_lsp.rs:219:20
    |
219 |         for (name, abi) in &state.contract_abis {
    |                    ^^^ help: if this is intentional, prefix it with an underscore: `_abi`

error[E0616]: field `functions` of struct `ContractAbi` is private
   --> src\ksl_doc_lsp.rs:261:30
    |
261 |             for func in &abi.functions {
    |                              ^^^^^^^^^ private field

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_doc_lsp.rs:390:26
    |
390 |               .map_err(|e| KslError::type_error(
    |  __________________________^^^^^^^^^^^^^^^^^^^^-
391 | |                 format!("Failed to create temp file {}: {}", temp_file.display(), e),
392 | |                 pos,
393 | |             ))?;
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
390 -             .map_err(|e| KslError::type_error(
391 -                 format!("Failed to create temp file {}: {}", temp_file.display(), e),
392 -                 pos,
393 -             ))?;
390 +             .map_err(|e| KslError::type_error(format!("Failed to create temp file {}: {}", temp_file.display(), e), pos, /* std::string::String */))?;
    |

error[E0599]: cannot write into `std::fs::File`
   --> src\ksl_doc_lsp.rs:395:13
    |
395 |             file,
    |             ^^^^
    |
   ::: C:\Users\ecomm\.cargo\registry\src\index.crates.io-1949cf8c6b5b557f\system-interface-0.27.3\src\io\io_ext.rs:122:8
    |
122 |     fn write_fmt(&self, fmt: Arguments) -> io::Result<()>;
    |        --------- the method is available for `std::fs::File` here
    |
note: must implement `io::Write`, `fmt::Write`, or have a `write_fmt` method
   --> src\ksl_doc_lsp.rs:395:13
    |
395 |             file,
    |             ^^^^
    = help: items from traits can only be used if the trait is in scope
help: trait `IoExt` which provides `write_fmt` is implemented but not in scope; perhaps you want to import it
    |
5   + use system_interface::io::io_ext::IoExt;
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_doc_lsp.rs:397:23
    |
397 |           ).map_err(|e| KslError::type_error(
    |  _______________________^^^^^^^^^^^^^^^^^^^^-
398 | |             format!("Failed to write temp file {}: {}", temp_file.display(), e),
399 | |             pos,
400 | |         ))?;
    | |_________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
397 -         ).map_err(|e| KslError::type_error(
398 -             format!("Failed to write temp file {}: {}", temp_file.display(), e),
399 -             pos,
400 -         ))?;
397 +         ).map_err(|e| KslError::type_error(format!("Failed to write temp file {}: {}", temp_file.display(), e), pos, /* std::string::String */))?;
    |

error[E0308]: arguments to this function are incorrect
   --> src\ksl_doc_lsp.rs:402:9
    |
402 |         generate_docgen("std", "markdown", self.config.doc_cache_dir.clone())?;
    |         ^^^^^^^^^^^^^^^        ----------  --------------------------------- argument #3 of type `&[DocItem]` is missing
    |                                |
    |                                unexpected argument #2 of type `&'static str`
    |
note: function defined here
   --> src\ksl_docgen.rs:148:8
    |
148 | pub fn generate_docgen(
    |        ^^^^^^^^^^^^^^^
...
151 |     items: &[DocItem],
    |     -----------------
help: did you mean
    |
402 -         generate_docgen("std", "markdown", self.config.doc_cache_dir.clone())?;
402 +         generate_docgen("std", self.config.doc_cache_dir.clone(), /* &[DocItem] */)?;
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_doc_lsp.rs:405:26
    |
405 |               .map_err(|e| KslError::type_error(
    |  __________________________^^^^^^^^^^^^^^^^^^^^-
406 | |                 format!("Failed to read doc file {}: {}", doc_file.display(), e),
407 | |                 pos,
408 | |             ))?;
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
405 -             .map_err(|e| KslError::type_error(
406 -                 format!("Failed to read doc file {}: {}", doc_file.display(), e),
407 -                 pos,
408 -             ))?;
405 +             .map_err(|e| KslError::type_error(format!("Failed to read doc file {}: {}", doc_file.display(), e), pos, /* std::string::String */))?;
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_doc_lsp.rs:433:26
    |
433 |               .map_err(|e| KslError::type_error(
    |  __________________________^^^^^^^^^^^^^^^^^^^^-
434 | |                 format!("Failed to clean up temp file {}: {}", temp_file.display(), e),
435 | |                 pos,
436 | |             ))?;
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
433 -             .map_err(|e| KslError::type_error(
434 -                 format!("Failed to clean up temp file {}: {}", temp_file.display(), e),
435 -                 pos,
436 -             ))?;
433 +             .map_err(|e| KslError::type_error(format!("Failed to clean up temp file {}: {}", temp_file.display(), e), pos, /* std::string::String */))?;
    |

error[E0599]: no method named `analyze_gas_usage` found for struct `Arc<Analyzer>` in the current scope
   --> src\ksl_doc_lsp.rs:669:43
    |
669 |             let gas_stats = self.analyzer.analyze_gas_usage(node).await?;
    |                                           ^^^^^^^^^^^^^^^^^ method not found in `Arc<Analyzer>`

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_doc_lsp.rs:685:20
    |
685 |           return Err(KslError::type_error(
    |  ____________________^^^^^^^^^^^^^^^^^^^^-
686 | |             "Port must be between 1024 and 65535".to_string(),
687 | |             pos,
688 | |         ));
    | |_________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
685 -         return Err(KslError::type_error(
686 -             "Port must be between 1024 and 65535".to_string(),
687 -             pos,
688 -         ));
685 +         return Err(KslError::type_error("Port must be between 1024 and 65535".to_string(), pos, /* std::string::String */));
    |

warning: unused variable: `message`
   --> src\ksl_fuzzer.rs:251:24
    |
251 |         while let Some(message) = queue.pop() {
    |                        ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_message`

error[E0616]: field `functions` of struct `ContractAbi` is private
   --> src\ksl_fuzzer.rs:362:30
    |
362 |         for function in &abi.functions {
    |                              ^^^^^^^^^ private field

error[E0191]: the value of the associated type `Tree` in `proptest::strategy::Strategy` must be specified
   --> src\ksl_fuzzer.rs:509:82
    |
509 | ...yn Strategy<Value = Vec<u8>>>, String> {
    |       ^^^^^^^^^^^^^^^^^^^^^^^^^ help: specify the associated type: `Strategy<Value = Vec<u8>, Tree = Type>`

error[E0599]: no method named `fuzz_storage` found for mutable reference `&mut Fuzzer` in the current scope
   --> src\ksl_fuzzer.rs:374:26
    |
374 |                     self.fuzz_storage(&input).await?;
    |                          ^^^^^^^^^^^^ method not found in `&mut Fuzzer`

error[E0599]: no method named `fuzz_modifiers` found for mutable reference `&mut Fuzzer` in the current scope
   --> src\ksl_fuzzer.rs:379:26
    |
379 |                     self.fuzz_modifiers(function, &input).await?;
    |                          ^^^^^^^^^^^^^^ method not found in `&mut Fuzzer`

error[E0191]: the value of the associated type `Tree` in `proptest::strategy::Strategy` must be specified
   --> src\ksl_fuzzer.rs:532:85
    |
532 | ...yn Strategy<Value = Vec<u8>>>, String> {
    |       ^^^^^^^^^^^^^^^^^^^^^^^^^ help: specify the associated type: `Strategy<Value = Vec<u8>, Tree = Type>`

error[E0599]: no method named `fuzz_segments` found for mutable reference `&mut Fuzzer` in the current scope
   --> src\ksl_fuzzer.rs:415:22
    |
415 |                 self.fuzz_segments(&signature).await?;
    |                      ^^^^^^^^^^^^^ method not found in `&mut Fuzzer`

error[E0191]: the value of the associated type `Tree` in `proptest::strategy::Strategy` must be specified
   --> src\ksl_fuzzer.rs:544:63
    |
544 |     fn generate_cross_shard_messages(&self) -> Result<Box<dyn Strategy<Value = Vec<u8>>>, String> {
    |                                                               ^^^^^^^^^^^^^^^^^^^^^^^^^ help: specify the associated type: `Strategy<Value = Vec<u8>, Tree = Type>`

error[E0599]: no method named `fuzz_timing` found for mutable reference `&mut Fuzzer` in the current scope
   --> src\ksl_fuzzer.rs:450:22
    |
450 |                 self.fuzz_timing(&message).await?;
    |                      ^^^^^^^^^^^ method not found in `&mut Fuzzer`

error[E0191]: the value of the associated type `Tree` in `proptest::strategy::Strategy` must be specified
   --> src\ksl_fuzzer.rs:556:62
    |
556 |     fn generate_consensus_scenarios(&self) -> Result<Box<dyn Strategy<Value = Vec<u8>>>, String> {
    |                                                              ^^^^^^^^^^^^^^^^^^^^^^^^^ help: specify the associated type: `Strategy<Value = Vec<u8>, Tree = Type>`

error[E0599]: no method named `fuzz_forks` found for mutable reference `&mut Fuzzer` in the current scope
   --> src\ksl_fuzzer.rs:485:22
    |
485 |                 self.fuzz_forks(&scenario).await?;
    |                      ^^^^^^^^^^ method not found in `&mut Fuzzer`

error[E0599]: no method named `fuzz_votes` found for mutable reference `&mut Fuzzer` in the current scope
   --> src\ksl_fuzzer.rs:490:22
    |
490 |                 self.fuzz_votes(&scenario).await?;
    |                      ^^^^^^^^^^ method not found in `&mut Fuzzer`

error[E0277]: `?` couldn't convert the error to `std::string::String`
   --> src\ksl_fuzzer.rs:614:69
    |
614 |         fs::write(&corpus_path, serde_json::to_string_pretty(&crash)?)
    |                                 ------------------------------------^ the trait `std::convert::From<serde_json::Error>` is not implemented for `std::string::String`
    |                                 |
    |                                 this can't be annotated with `?` because it has type `Result<_, serde_json::Error>`
    |
    = note: the question mark operation (`?`) implicitly performs a conversion on the error value using the `From` trait
    = help: the following other types implement trait `std::convert::From<T>`:
              `std::string::String` implements `std::convert::From<&mut str>`
              `std::string::String` implements `std::convert::From<&std::string::String>`
              `std::string::String` implements `std::convert::From<&str>`
              `std::string::String` implements `std::convert::From<&widestring::utfstr::Utf16Str>`
              `std::string::String` implements `std::convert::From<&widestring::utfstr::Utf32Str>`
              `std::string::String` implements `std::convert::From<Cow<'_, str>>`
              `std::string::String` implements `std::convert::From<ProtoError>`
              `std::string::String` implements `std::convert::From<StringValue>`
            and 13 others
    = note: required for `std::result::Result<(), std::string::String>` to implement `FromResidual<std::result::Result<Infallible, serde_json::Error>>`

error[E0277]: `?` couldn't convert the error to `std::string::String`
   --> src\ksl_fuzzer.rs:627:73
    |
627 |             fs::write(&shrunk_path, serde_json::to_string_pretty(&crash)?)
    |                                     ------------------------------------^ the trait `std::convert::From<serde_json::Error>` is not implemented for `std::string::String`
    |                                     |
    |                                     this can't be annotated with `?` because it has type `Result<_, serde_json::Error>`
    |
    = note: the question mark operation (`?`) implicitly performs a conversion on the error value using the `From` trait
    = help: the following other types implement trait `std::convert::From<T>`:
              `std::string::String` implements `std::convert::From<&mut str>`
              `std::string::String` implements `std::convert::From<&std::string::String>`
              `std::string::String` implements `std::convert::From<&str>`
              `std::string::String` implements `std::convert::From<&widestring::utfstr::Utf16Str>`
              `std::string::String` implements `std::convert::From<&widestring::utfstr::Utf32Str>`
              `std::string::String` implements `std::convert::From<Cow<'_, str>>`
              `std::string::String` implements `std::convert::From<ProtoError>`
              `std::string::String` implements `std::convert::From<StringValue>`
            and 13 others
    = note: required for `std::result::Result<(), std::string::String>` to implement `FromResidual<std::result::Result<Infallible, serde_json::Error>>`

error[E0382]: use of partially moved value: `crash`
   --> src\ksl_fuzzer.rs:694:27
    |
682 |             if let Some(diff) = crash.ast_diff {
    |                         ---- value partially moved here
...
694 |             crashes: vec![crash],
    |                           ^^^^^ value used here after partial move
    |
    = note: partial move occurs because value has type `std::string::String`, which does not implement the `Copy` trait
help: borrow this binding in the pattern to avoid moving the value
    |
682 |             if let Some(ref diff) = crash.ast_diff {
    |                         +++

warning: unused variable: `input`
   --> src\ksl_fuzzer.rs:716:39
    |
716 |     async fn run_contract_test(&self, input: &[u8]) -> Result<(), String> {
    |                                       ^^^^^ help: if this is intentional, prefix it with an underscore: `_input`

warning: unused variable: `input`
   --> src\ksl_fuzzer.rs:722:40
    |
722 |     async fn run_validator_test(&self, input: &[u8]) -> Result<(), String> {
    |                                        ^^^^^ help: if this is intentional, prefix it with an underscore: `_input`

warning: unused variable: `input`
   --> src\ksl_fuzzer.rs:728:39
    |
728 |     async fn run_sharding_test(&self, input: &[u8]) -> Result<(), String> {
    |                                       ^^^^^ help: if this is intentional, prefix it with an underscore: `_input`

warning: unused variable: `input`
   --> src\ksl_fuzzer.rs:734:40
    |
734 |     async fn run_consensus_test(&self, input: &[u8]) -> Result<(), String> {
    |                                        ^^^^^ help: if this is intentional, prefix it with an underscore: `_input`

error[E0616]: field `functions` of struct `ContractAbi` is private
   --> src\ksl_fuzzer.rs:938:30
    |
938 |         for function in &abi.functions {
    |                              ^^^^^^^^^ private field

error[E0599]: no method named `fuzz_storage` found for mutable reference `&mut Fuzzer` in the current scope
   --> src\ksl_fuzzer.rs:947:26
    |
947 |                     self.fuzz_storage(&input).await?;
    |                          ^^^^^^^^^^^^ method not found in `&mut Fuzzer`

error[E0599]: no method named `fuzz_modifiers` found for mutable reference `&mut Fuzzer` in the current scope
   --> src\ksl_fuzzer.rs:951:26
    |
951 |                     self.fuzz_modifiers(function, &input).await?;
    |                          ^^^^^^^^^^^^^^ method not found in `&mut Fuzzer`

error[E0277]: the `?` operator can only be used in a closure that returns `Result` or `Option` (or another type that implements `FromResidual`)
   --> src\ksl_fuzzer.rs:859:80
    |
851 |                     .map(|i| {
    |                          --- this function should return `Result` or `Option` to accept `?`
...
859 |                         let mut local_fuzzer = Fuzzer::new(self.config.clone())?;
    |                                                                                ^ cannot use the `?` operator in a closure that returns `impl futures::Future<Output = std::result::Result<(), std::string::String>>`
    |
    = help: the trait `FromResidual<std::result::Result<Infallible, std::string::String>>` is not implemented for `impl futures::Future<Output = std::result::Result<(), std::string::String>>`
    = note: the full name for the type has been written to 'C:\rn\ksl\target\debug\deps\KSL-23b41cf53b6ebc6d.long-type-5988123181491703957.txt'
    = note: consider using `--verbose` to print the full type name to the console

error[E0277]: the trait bound `Vec<Result<(), String>>: FromParallelIterator<...>` is not satisfied
    --> src\ksl_fuzzer.rs:862:22
     |
862  |                     .collect();
     |                      ^^^^^^^ unsatisfied trait bound
     |
     = help: the trait `FromParallelIterator<impl futures::Future<Output = std::result::Result<(), std::string::String>>>` is not implemented for `Vec<std::result::Result<(), std::string::String>>`
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
     = note: the full name for the type has been written to 'C:\rn\ksl\target\debug\deps\KSL-23b41cf53b6ebc6d.long-type-6372400035623160469.txt'
     = note: consider using `--verbose` to print the full type name to the console

error[E0599]: no method named `fuzz_timing` found for mutable reference `&mut Fuzzer` in the current scope
    --> src\ksl_fuzzer.rs:1000:22
     |
1000 |                 self.fuzz_timing(&message).await?;
     |                      ^^^^^^^^^^^ method not found in `&mut Fuzzer`

error[E0277]: the `?` operator can only be used in a closure that returns `Result` or `Option` (or another type that implements `FromResidual`)
   --> src\ksl_fuzzer.rs:900:80
    |
892 |                     .map(|i| {
    |                          --- this function should return `Result` or `Option` to accept `?`
...
900 |                         let mut local_fuzzer = Fuzzer::new(self.config.clone())?;
    |                                                                                ^ cannot use the `?` operator in a closure that returns `impl futures::Future<Output = std::result::Result<(), std::string::String>>`
    |
    = help: the trait `FromResidual<std::result::Result<Infallible, std::string::String>>` is not implemented for `impl futures::Future<Output = std::result::Result<(), std::string::String>>`
    = note: the full name for the type has been written to 'C:\rn\ksl\target\debug\deps\KSL-23b41cf53b6ebc6d.long-type-17702318139079893335.txt'
    = note: consider using `--verbose` to print the full type name to the console

error[E0277]: the trait bound `Vec<Result<(), String>>: FromParallelIterator<...>` is not satisfied
    --> src\ksl_fuzzer.rs:903:22
     |
903  |                     .collect();
     |                      ^^^^^^^ unsatisfied trait bound
     |
     = help: the trait `FromParallelIterator<impl futures::Future<Output = std::result::Result<(), std::string::String>>>` is not implemented for `Vec<std::result::Result<(), std::string::String>>`
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
     = note: the full name for the type has been written to 'C:\rn\ksl\target\debug\deps\KSL-23b41cf53b6ebc6d.long-type-13464208707481302729.txt'
     = note: consider using `--verbose` to print the full type name to the console

error[E0599]: no method named `fuzz_forks` found for mutable reference `&mut Fuzzer` in the current scope
    --> src\ksl_fuzzer.rs:1024:22
     |
1024 |                 self.fuzz_forks(&scenario).await?;
     |                      ^^^^^^^^^^ method not found in `&mut Fuzzer`

error[E0599]: no method named `fuzz_votes` found for mutable reference `&mut Fuzzer` in the current scope
    --> src\ksl_fuzzer.rs:1028:22
     |
1028 |                 self.fuzz_votes(&scenario).await?;
     |                      ^^^^^^^^^^ method not found in `&mut Fuzzer`

error[E0277]: the `?` operator can only be used in a closure that returns `Result` or `Option` (or another type that implements `FromResidual`)
   --> src\ksl_fuzzer.rs:920:80
    |
912 |                     .map(|i| {
    |                          --- this function should return `Result` or `Option` to accept `?`
...
920 |                         let mut local_fuzzer = Fuzzer::new(self.config.clone())?;
    |                                                                                ^ cannot use the `?` operator in a closure that returns `impl futures::Future<Output = std::result::Result<(), std::string::String>>`
    |
    = help: the trait `FromResidual<std::result::Result<Infallible, std::string::String>>` is not implemented for `impl futures::Future<Output = std::result::Result<(), std::string::String>>`
    = note: the full name for the type has been written to 'C:\rn\ksl\target\debug\deps\KSL-23b41cf53b6ebc6d.long-type-5038728376529016850.txt'
    = note: consider using `--verbose` to print the full type name to the console

error[E0277]: the trait bound `Vec<Result<(), String>>: FromParallelIterator<...>` is not satisfied
    --> src\ksl_fuzzer.rs:923:22
     |
923  |                     .collect();
     |                      ^^^^^^^ unsatisfied trait bound
     |
     = help: the trait `FromParallelIterator<impl futures::Future<Output = std::result::Result<(), std::string::String>>>` is not implemented for `Vec<std::result::Result<(), std::string::String>>`
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
     = note: the full name for the type has been written to 'C:\rn\ksl\target\debug\deps\KSL-23b41cf53b6ebc6d.long-type-1410499466889254132.txt'
     = note: consider using `--verbose` to print the full type name to the console

error[E0599]: no method named `fuzz_segments` found for mutable reference `&mut Fuzzer` in the current scope
   --> src\ksl_fuzzer.rs:976:22
    |
976 |                 self.fuzz_segments(&signature).await?;
    |                      ^^^^^^^^^^^^^ method not found in `&mut Fuzzer`

error[E0599]: no method named `json` found for struct `reqwest::RequestBuilder` in the current scope
    --> src\ksl_fuzzer.rs:1079:14
     |
1078 | /         client.post(&webhook_config.url)
1079 | |             .json(&payload)
     | |             -^^^^ method not found in `RequestBuilder`
     | |_____________|
     |

warning: unused variable: `peer_id`
   --> src\ksl_game.rs:177:30
    |
177 |     pub async fn send(&self, peer_id: u32, state: &[u8]) -> Result<(), String> {
    |                              ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_peer_id`

warning: unused variable: `state`
   --> src\ksl_game.rs:177:44
    |
177 |     pub async fn send(&self, peer_id: u32, state: &[u8]) -> Result<(), String> {
    |                                            ^^^^^ help: if this is intentional, prefix it with an underscore: `_state`

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_interpreter.rs:88:26
    |
88  |               .map_err(|e| KslError::type_error(
    |  __________________________^^^^^^^^^^^^^^^^^^^^-
89  | |                 format!("Failed to read file {}: {}", file.display(), e),
90  | |                 pos,
91  | |             ))?;
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
88  -             .map_err(|e| KslError::type_error(
89  -                 format!("Failed to read file {}: {}", file.display(), e),
90  -                 pos,
91  -             ))?;
88  +             .map_err(|e| KslError::type_error(format!("Failed to read file {}: {}", file.display(), e), pos, /* std::string::String */))?;
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_interpreter.rs:93:26
    |
93  |               .map_err(|e| KslError::type_error(
    |  __________________________^^^^^^^^^^^^^^^^^^^^-
94  | |                 format!("Parse error at position {}: {}", e.position, e.message),
95  | |                 pos,
96  | |             ))?;
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
93  -             .map_err(|e| KslError::type_error(
94  -                 format!("Parse error at position {}: {}", e.position, e.message),
95  -                 pos,
96  -             ))?;
93  +             .map_err(|e| KslError::type_error(format!("Parse error at position {}: {}", e.position, e.message), pos, /* std::string::String */))?;
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_interpreter.rs:100:26
    |
100 |               .map_err(|e| KslError::type_error(
    |  __________________________^^^^^^^^^^^^^^^^^^^^-
101 | |                 format!("AST transformation error: {}", e),
102 | |                 pos,
103 | |             ))?;
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
100 -             .map_err(|e| KslError::type_error(
101 -                 format!("AST transformation error: {}", e),
102 -                 pos,
103 -             ))?;
100 +             .map_err(|e| KslError::type_error(format!("AST transformation error: {}", e), pos, /* std::string::String */))?;
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_interpreter.rs:107:31
    |
107 |               .map_err(|errors| KslError::type_error(
    |  _______________________________^^^^^^^^^^^^^^^^^^^^-
108 | |                 errors.into_iter()
109 | |                     .map(|e| format!("Type error at position {}: {}", e.position, e.message))
110 | |                     .collect::<Vec<_>>()
111 | |                     .join("\n"),
112 | |                 pos,
113 | |             ))?;
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
107 ~             .map_err(|errors| KslError::type_error(errors.into_iter()
108 +                     .map(|e| format!("Type error at position {}: {}", e.position, e.message))
109 +                     .collect::<Vec<_>>()
110 ~                     .join("\n"), pos, /* std::string::String */))?;
    |

error[E0061]: this function takes 0 arguments but 1 argument was supplied
   --> src\ksl_interpreter.rs:116:27
    |
116 |         let mut sandbox = Sandbox::new(SandboxPolicy::default());
    |                           ^^^^^^^^^^^^ ------------------------ unexpected argument of type `ksl_sandbox::SandboxPolicy`
    |
note: associated function defined here
   --> src\ksl_sandbox.rs:220:12
    |
220 |     pub fn new() -> Self {
    |            ^^^
help: remove the extra argument
    |
116 -         let mut sandbox = Sandbox::new(SandboxPolicy::default());
116 +         let mut sandbox = Sandbox::new();
    |

error[E0599]: no method named `run_sandbox_async` found for struct `Sandbox` in the current scope
   --> src\ksl_interpreter.rs:117:17
    |
117 |         sandbox.run_sandbox_async(file).await
    |                 ^^^^^^^^^^^^^^^^^
    |
   ::: src\ksl_sandbox.rs:92:1
    |
92  | pub struct Sandbox {
    | ------------------ method `run_sandbox_async` not found for this struct
    |
help: there is a method `run_sandbox` with a similar name
    |
117 -         sandbox.run_sandbox_async(file).await
117 +         sandbox.run_sandbox(file).await
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_interpreter.rs:118:26
    |
118 |               .map_err(|e| KslError::type_error(
    |  __________________________^^^^^^^^^^^^^^^^^^^^-
119 | |                 e.into_iter().map(|e| e.to_string()).collect::<Vec<_>>().join("\n"),
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
119 -                 e.into_iter().map(|e| e.to_string()).collect::<Vec<_>>().join("\n"),
120 -                 pos,
121 -             ))?;
118 +             .map_err(|e| KslError::type_error(e.into_iter().map(|e| e.to_string()).collect::<Vec<_>>().join("\n"), pos, /* std::string::String */))?;
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_interpreter.rs:137:28
    |
137 |                   return Err(KslError::type_error(
    |  ____________________________^^^^^^^^^^^^^^^^^^^^-
138 | |                     "Main function must have no parameters".to_string(),
139 | |                     pos,
140 | |                 ));
    | |_________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
137 -                 return Err(KslError::type_error(
138 -                     "Main function must have no parameters".to_string(),
139 -                     pos,
140 -                 ));
137 +                 return Err(KslError::type_error("Main function must have no parameters".to_string(), pos, /* std::string::String */));
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_interpreter.rs:144:17
    |
144 |               Err(KslError::type_error(
    |  _________________^^^^^^^^^^^^^^^^^^^^-
145 | |                 "No main function found".to_string(),
146 | |                 pos,
147 | |             ))
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
144 -             Err(KslError::type_error(
145 -                 "No main function found".to_string(),
146 -                 pos,
147 -             ))
144 +             Err(KslError::type_error("No main function found".to_string(), pos, /* std::string::String */))
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_interpreter.rs:180:33
    |
180 |                   _ => return Err(KslError::type_error(
    |  _________________________________^^^^^^^^^^^^^^^^^^^^-
181 | |                     "Unsupported statement in interpreter".to_string(),
182 | |                     pos,
183 | |                 )),
    | |_________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
180 -                 _ => return Err(KslError::type_error(
181 -                     "Unsupported statement in interpreter".to_string(),
182 -                     pos,
183 -                 )),
180 +                 _ => return Err(KslError::type_error("Unsupported statement in interpreter".to_string(), pos, /* std::string::String */)),
    |

error[E0308]: mismatched types
   --> src\ksl_interpreter.rs:196:39
    |
196 |                     env.variables.get(name)
    |                                   --- ^^^^ expected `&_`, found `String`
    |                                   |
    |                                   arguments to this method are incorrect
    |
    = note: expected reference `&_`
                  found struct `std::string::String`
note: method defined here
   --> /rustc/05f9846f893b09a1be1fc8560e33fc3c815cfecb\library\std\src\collections\hash\map.rs:894:12
help: consider borrowing here
    |
196 |                     env.variables.get(&name)
    |                                       +

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_interpreter.rs:198:40
    |
198 |                           .ok_or_else(|| KslError::type_error(
    |  ________________________________________^^^^^^^^^^^^^^^^^^^^-
199 | |                             format!("Undefined variable: {}", name),
200 | |                             pos,
201 | |                         ))
    | |_________________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
198 -                         .ok_or_else(|| KslError::type_error(
199 -                             format!("Undefined variable: {}", name),
200 -                             pos,
201 -                         ))
198 +                         .ok_or_else(|| KslError::type_error(format!("Undefined variable: {}", name), pos, /* std::string::String */))
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_interpreter.rs:207:42
    |
207 |   ...                   .map_err(|_| KslError::type_error(
    |  ____________________________________^^^^^^^^^^^^^^^^^^^^-
208 | | ...                       format!("Invalid float: {}", num),
209 | | ...                       pos,
210 | | ...                   ))
    | |_______________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
207 -                             .map_err(|_| KslError::type_error(
208 -                                 format!("Invalid float: {}", num),
209 -                                 pos,
210 -                             ))
207 +                             .map_err(|_| KslError::type_error(format!("Invalid float: {}", num), pos, /* std::string::String */))
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_interpreter.rs:214:42
    |
214 |   ...                   .map_err(|_| KslError::type_error(
    |  ____________________________________^^^^^^^^^^^^^^^^^^^^-
215 | | ...                       format!("Invalid integer: {}", num),
216 | | ...                       pos,
217 | | ...                   ))
    | |_______________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
214 -                             .map_err(|_| KslError::type_error(
215 -                                 format!("Invalid integer: {}", num),
216 -                                 pos,
217 -                             ))
214 +                             .map_err(|_| KslError::type_error(format!("Invalid integer: {}", num), pos, /* std::string::String */))
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_interpreter.rs:234:34
    |
234 |                           _ => Err(KslError::type_error(
    |  __________________________________^^^^^^^^^^^^^^^^^^^^-
235 | |                             format!("Unsupported operation: {} on {:?} and {:?}", op, left_val, right_val),
236 | |                             pos,
237 | |                         )),
    | |_________________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
234 -                         _ => Err(KslError::type_error(
235 -                             format!("Unsupported operation: {} on {:?} and {:?}", op, left_val, right_val),
236 -                             pos,
237 -                         )),
234 +                         _ => Err(KslError::type_error(format!("Unsupported operation: {} on {:?} and {:?}", op, left_val, right_val), pos, /* std::string::String */)),
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_interpreter.rs:244:40
    |
244 |   ...                   return Err(KslError::type_error(
    |  __________________________________^^^^^^^^^^^^^^^^^^^^-
245 | | ...                       format!("Expected {} arguments, got {}", params.len(), args.len()),
246 | | ...                       pos,
247 | | ...                   ));
    | |_______________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
244 -                             return Err(KslError::type_error(
245 -                                 format!("Expected {} arguments, got {}", params.len(), args.len()),
246 -                                 pos,
247 -                             ));
244 +                             return Err(KslError::type_error(format!("Expected {} arguments, got {}", params.len(), args.len()), pos, /* std::string::String */));
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_interpreter.rs:265:29
    |
265 |                           Err(KslError::type_error(
    |  _____________________________^^^^^^^^^^^^^^^^^^^^-
266 | |                             format!("Undefined function: {}", name),
267 | |                             pos,
268 | |                         ))
    | |_________________________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
265 -                         Err(KslError::type_error(
266 -                             format!("Undefined function: {}", name),
267 -                             pos,
268 -                         ))
265 +                         Err(KslError::type_error(format!("Undefined function: {}", name), pos, /* std::string::String */))
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_interpreter.rs:282:22
    |
282 |               _ => Err(KslError::type_error(
    |  ______________________^^^^^^^^^^^^^^^^^^^^-
283 | |                 "Expected expression".to_string(),
284 | |                 pos,
285 | |             )),
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
282 -             _ => Err(KslError::type_error(
283 -                 "Expected expression".to_string(),
284 -                 pos,
285 -             )),
282 +             _ => Err(KslError::type_error("Expected expression".to_string(), pos, /* std::string::String */)),
    |

error[E0599]: no method named `map_err` found for struct `AsyncResolver` in the current scope
   --> src\ksl_genesis.rs:679:11
    |
676 |           let resolver = TokioAsyncResolver::tokio(
    |  ________________________-
677 | |             ResolverConfig::default(),
678 | |             ResolverOpts::default(),
679 | |         ).map_err(|e| format!("Failed to create DNS resolver: {}", e))?;
    | |          -^^^^^^^ method not found in `AsyncResolver<GenericConnector<TokioRuntimeProvider>>`
    | |__________|
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_doc.rs:53:28
    |
53  |               .ok_or_else(|| KslError::type_error(
    |  ____________________________^^^^^^^^^^^^^^^^^^^^-
54  | |                 "Invalid main file name".to_string(),
55  | |                 SourcePosition::new(1, 1),
56  | |             ))?;
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
53  -             .ok_or_else(|| KslError::type_error(
54  -                 "Invalid main file name".to_string(),
55  -                 SourcePosition::new(1, 1),
56  -             ))?;
53  +             .ok_or_else(|| KslError::type_error("Invalid main file name".to_string(), SourcePosition::new(1, 1), /* std::string::String */))?;
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_doc.rs:72:26
    |
72  |             .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
    |                          ^^^^^^^^^^^^^^^^^^^^------------------------------------------ argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
72  -             .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
72  +             .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1), /* std::string::String */))?;
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_doc.rs:75:26
    |
75  |             .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
    |                          ^^^^^^^^^^^^^^^^^^^^------------------------------------------ argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
75  -             .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
75  +             .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1), /* std::string::String */))?;
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_doc.rs:77:26
    |
77  |             .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
    |                          ^^^^^^^^^^^^^^^^^^^^------------------------------------------ argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
77  -             .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
77  +             .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1), /* std::string::String */))?;
    |

error[E0061]: this function takes 1 argument but 2 arguments were supplied
  --> src\ksl_doc.rs:81:22
   |
81 |         let docgen = DocGen::new(main_module_name.to_string(), output.clone());
   |                      ^^^^^^^^^^^ ----------------------------  -------------- unexpected argument #2 of type `PathBuf`
   |                                  |
   |                                  expected `DocGenConfig`, found `String`
   |
note: associated function defined here
  --> src\ksl_docgen.rs:76:12
   |
76 |     pub fn new(config: DocGenConfig) -> Self {
   |            ^^^ --------------------
help: remove the extra argument
   |
81 -         let docgen = DocGen::new(main_module_name.to_string(), output.clone());
81 +         let docgen = DocGen::new(/* DocGenConfig */);
   |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_doc.rs:90:26
    |
90  |             .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
    |                          ^^^^^^^^^^^^^^^^^^^^------------------------------------------ argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
90  -             .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
90  +             .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1), /* std::string::String */))?;
    |

error[E0616]: field `functions` of struct `CryptoStdLib` is private
  --> src\ksl_doc.rs:98:41
   |
98 |         for func in &self.crypto_stdlib.functions {
   |                                         ^^^^^^^^^ private field

error[E0616]: field `functions` of struct `MathStdLib` is private
   --> src\ksl_doc.rs:104:39
    |
104 |         for func in &self.math_stdlib.functions {
    |                                       ^^^^^^^^^ private field

error[E0616]: field `functions` of struct `IOStdLib` is private
   --> src\ksl_doc.rs:110:37
    |
110 |         for func in &self.io_stdlib.functions {
    |                                     ^^^^^^^^^ private field

error[E0616]: field `functions` of struct `NetStdLib` is private
   --> src\ksl_doc.rs:116:38
    |
116 |         for func in &self.net_stdlib.functions {
    |                                      ^^^^^^^^^ private field

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_doc.rs:123:26
    |
123 |             .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
    |                          ^^^^^^^^^^^^^^^^^^^^------------------------------------------ argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
123 -             .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
123 +             .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1), /* std::string::String */))?;
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_doc.rs:125:26
    |
125 |             .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
    |                          ^^^^^^^^^^^^^^^^^^^^------------------------------------------ argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
125 -             .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1)))?;
125 +             .map_err(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1), /* std::string::String */))?;
    |

error[E0061]: this function takes 1 argument but 2 arguments were supplied
   --> src\ksl_doc.rs:129:22
    |
129 |         let docgen = DocGen::new("std".to_string(), output.clone());
    |                      ^^^^^^^^^^^ -----------------  -------------- unexpected argument #2 of type `PathBuf`
    |                                  |
    |                                  expected `DocGenConfig`, found `String`
    |
note: associated function defined here
   --> src\ksl_docgen.rs:76:12
    |
76  |     pub fn new(config: DocGenConfig) -> Self {
    |            ^^^ --------------------
help: remove the extra argument
    |
129 -         let docgen = DocGen::new("std".to_string(), output.clone());
129 +         let docgen = DocGen::new(/* DocGenConfig */);
    |

error[E0308]: mismatched types
   --> src\ksl_doc.rs:432:47
    |
432 |     let output_dir = output.unwrap_or_else(|| PathBuf::from("docs"));
    |                                               ^^^^^^^^^^^^^^^^^^^^^ expected `&PathBuf`, found `PathBuf`
    |
help: consider borrowing here
    |
432 |     let output_dir = output.unwrap_or_else(|| &PathBuf::from("docs"));
    |                                               +

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_doc.rs:439:20
    |
439 |           return Err(KslError::type_error(
    |  ____________________^^^^^^^^^^^^^^^^^^^^-
440 | |             "Either --file or --std must be specified".to_string(),
441 | |             SourcePosition::new(1, 1),
442 | |         ));
    | |_________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
439 -         return Err(KslError::type_error(
440 -             "Either --file or --std must be specified".to_string(),
441 -             SourcePosition::new(1, 1),
442 -         ));
439 +         return Err(KslError::type_error("Either --file or --std must be specified".to_string(), SourcePosition::new(1, 1), /* std::string::String */));
    |

error[E0308]: mismatched types
   --> src\ksl_test.rs:229:15
    |
229 |         check(&ast)
    |         ----- ^^^^ expected `&[AstNode]`, found `&Vec<AstNode>`
    |         |
    |         arguments to this function are incorrect
    |
    = note: expected reference `&[ksl_ast::AstNode]`
               found reference `&Vec<ksl_macros::AstNode>`
note: function defined here
   --> src\ksl_checker.rs:651:8
    |
651 | pub fn check(nodes: &[AstNode]) -> Result<(), Vec<TypeError>> {
    |        ^^^^^ -----------------

error[E0026]: variant `ksl_macros::AstNode::FnDecl` does not have fields named `is_async`, `attrs`
   --> src\ksl_test.rs:241:67
    |
241 |                 if let crate::ksl_parser::AstNode::FnDecl { name, is_async, attrs, .. } = node {
    |                                                                   ^^^^^^^^  ^^^^^ variant `ksl_macros::AstNode::FnDecl` does not have these fields

error[E0271]: expected `IntoIter<Vec<TestResult>>` to be an iterator that yields `TestResult`, but it yields `Vec<TestResult>`
   --> src\ksl_test.rs:303:29
    |
303 |         self.results.extend(results.into_iter().flatten());
    |                      ------ ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ expected `TestResult`, found `Vec<TestResult>`
    |                      |
    |                      required by a bound introduced by this call
    |
    = note: expected struct `ksl_test::TestResult`
               found struct `Vec<ksl_test::TestResult>`
note: the method call chain might not have had the expected associated types
   --> src\ksl_test.rs:303:37
    |
302 |         let results = join_all(futures).await;
    |                       ----------------------- this expression has type `Vec<Result<Vec<TestResult>, String>>`
303 |         self.results.extend(results.into_iter().flatten());
    |                                     ^^^^^^^^^^^ `IntoIterator::Item` is `Result<Vec<TestResult>, String>` here
note: required by a bound in `extend`
   --> /rustc/05f9846f893b09a1be1fc8560e33fc3c815cfecb\library\core\src\iter\traits\collect.rs:416:5

error[E0061]: this function takes 7 arguments but 1 argument was supplied
   --> src\ksl_test.rs:336:32
    |
336 |                 let bytecode = compile(ast)
    |                                ^^^^^^^----- multiple arguments are missing
    |
note: expected `ksl_ast::AstNode`, found `ksl_macros::AstNode`
   --> src\ksl_test.rs:336:40
    |
336 |                 let bytecode = compile(ast)
    |                                        ^^^
    = note: `ksl_macros::AstNode` and `ksl_ast::AstNode` have similar names, but are actually distinct types
note: `ksl_macros::AstNode` is defined in module `crate::ksl_macros` of the current crate
   --> src\ksl_macros.rs:439:1
    |
439 | pub enum AstNode {
    | ^^^^^^^^^^^^^^^^
note: `ksl_ast::AstNode` is defined in module `crate::ksl_ast` of the current crate
   --> src\ksl_ast.rs:244:1
    |
244 | pub enum AstNode {
    | ^^^^^^^^^^^^^^^^
note: function defined here
   --> src\ksl_compiler.rs:803:8
    |
803 | pub fn compile(
    |        ^^^^^^^
804 |     ast: &[AstNode],
    |     ---------------
805 |     module_name: &str,
    |     -----------------
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
336 -                 let bytecode = compile(ast)
336 +                 let bytecode = compile(/* &[ksl_ast::AstNode] */, /* &str */, /* CompileTarget */, /* &str */, /* &ksl_analyzer::PerformanceMetrics */, /* bool */, /* std::option::Option<ksl_macros::HotReloadConfig> */)
    |

error[E0599]: `KslError` is not an iterator
   --> src\ksl_test.rs:339:30
    |
338 | /                         errors
339 | |                             .into_iter()
    | |                             -^^^^^^^^^ `KslError` is not an iterator
    | |_____________________________|
    |
    |
   ::: src\ksl_errors.rs:58:1
    |
58  |   pub enum KslError {
    |   ----------------- method `into_iter` not found for this enum because it doesn't satisfy `KslError: IntoIterator` or `KslError: Iterator`
    |
    = note: the following trait bounds were not satisfied:
            `KslError: Iterator`
            which is required by `KslError: IntoIterator`
            `&KslError: Iterator`
            which is required by `&KslError: IntoIterator`
            `&mut KslError: Iterator`
            which is required by `&mut KslError: IntoIterator`
note: the trait `Iterator` must be implemented
   --> /rustc/05f9846f893b09a1be1fc8560e33fc3c815cfecb\library\core\src\iter\traits\iterator.rs:39:1
    = help: items from traits can only be used if the trait is implemented and in scope
    = note: the following traits define an item `into_iter`, perhaps you need to implement one of them:
            candidate #1: `IntoIterator`
            candidate #2: `rayon::iter::plumbing::Producer`

error[E0599]: no method named `run_test` found for reference `&ksl_test::TestRunner` in the current scope
   --> src\ksl_test.rs:346:35
    |
346 |                 let result = self.run_test(&bytecode, test_name, is_async, category.clone(), is_validator).await;
    |                                   ^^^^^^^^
    |
help: there is a method `run_tests` with a similar name, but with different arguments
   --> src\ksl_test.rs:219:5
    |
219 |     pub async fn run_tests(&mut self, file: &PathBuf) -> Result<(), String> {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

error[E0599]: no method named `get_gas_stats` found for reference `&Arc<Analyzer>` in the current scope
   --> src\ksl_test.rs:387:55
    |
387 |                     if let Some(gas_stats) = analyzer.get_gas_stats() {
    |                                                       ^^^^^^^^^^^^^ method not found in `&Arc<Analyzer>`

error[E0277]: `?` couldn't convert the error to `std::string::String`
   --> src\ksl_test.rs:420:88
    |
420 |                         fs::write(&snapshot_path, serde_json::to_string_pretty(&result)?)
    |                                                   -------------------------------------^ the trait `std::convert::From<serde_json::Error>` is not implemented for `std::string::String`
    |                                                   |
    |                                                   this can't be annotated with `?` because it has type `Result<_, serde_json::Error>`
    |
    = note: the question mark operation (`?`) implicitly performs a conversion on the error value using the `From` trait
    = help: the following other types implement trait `std::convert::From<T>`:
              `std::string::String` implements `std::convert::From<&mut str>`
              `std::string::String` implements `std::convert::From<&std::string::String>`
              `std::string::String` implements `std::convert::From<&str>`
              `std::string::String` implements `std::convert::From<&widestring::utfstr::Utf16Str>`
              `std::string::String` implements `std::convert::From<&widestring::utfstr::Utf32Str>`
              `std::string::String` implements `std::convert::From<Cow<'_, str>>`
              `std::string::String` implements `std::convert::From<ProtoError>`
              `std::string::String` implements `std::convert::From<StringValue>`
            and 13 others
    = note: required for `std::result::Result<Vec<ksl_test::TestResult>, std::string::String>` to implement `FromResidual<std::result::Result<Infallible, serde_json::Error>>`

warning: unused variable: `contract_id`
   --> src\ksl_sandbox.rs:562:9
    |
562 |         contract_id: &str,
    |         ^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_contract_id`

warning: unused variable: `bytecode`
   --> src\ksl_sandbox.rs:563:9
    |
563 |         bytecode: KapraBytecode,
    |         ^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_bytecode`

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_bench.rs:98:33
    |
98  |               .ok_or_else(|| vec![KslError::type_error(
    |  _________________________________^^^^^^^^^^^^^^^^^^^^-
99  | |                 "Invalid main file name".to_string(),
100 | |                 SourcePosition::new(1, 1),
101 | |             )])?;
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
98  -             .ok_or_else(|| vec![KslError::type_error(
99  -                 "Invalid main file name".to_string(),
100 -                 SourcePosition::new(1, 1),
101 -             )])?;
98  +             .ok_or_else(|| vec![KslError::type_error("Invalid main file name".to_string(), SourcePosition::new(1, 1), /* std::string::String */)])?;
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_bench.rs:105:31
    |
105 |             .map_err(|e| vec![KslError::type_error(e.to_string(), SourcePosition::new(1, 1))])?;
    |                               ^^^^^^^^^^^^^^^^^^^^------------------------------------------ argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
105 -             .map_err(|e| vec![KslError::type_error(e.to_string(), SourcePosition::new(1, 1))])?;
105 +             .map_err(|e| vec![KslError::type_error(e.to_string(), SourcePosition::new(1, 1), /* std::string::String */)])?;
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_bench.rs:109:31
    |
109 |               .map_err(|e| vec![KslError::type_error(
    |  _______________________________^^^^^^^^^^^^^^^^^^^^-
110 | |                 format!("Parse error at position {}: {}", e.position, e.message),
111 | |                 SourcePosition::new(1, 1),
112 | |             )])?;
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
109 -             .map_err(|e| vec![KslError::type_error(
110 -                 format!("Parse error at position {}: {}", e.position, e.message),
111 -                 SourcePosition::new(1, 1),
112 -             )])?;
109 +             .map_err(|e| vec![KslError::type_error(format!("Parse error at position {}: {}", e.position, e.message), SourcePosition::new(1, 1), /* std::string::String */)])?;
    |

error[E0308]: mismatched types
   --> src\ksl_bench.rs:115:15
    |
115 |         check(&ast)
    |         ----- ^^^^ expected `&[AstNode]`, found `&Vec<AstNode>`
    |         |
    |         arguments to this function are incorrect
    |
    = note: expected reference `&[ksl_ast::AstNode]`
               found reference `&Vec<ksl_macros::AstNode>`
note: function defined here
   --> src\ksl_checker.rs:651:8
    |
651 | pub fn check(nodes: &[AstNode]) -> Result<(), Vec<TypeError>> {
    |        ^^^^^ -----------------

error[E0277]: `?` couldn't convert the error to `Vec<KslError>`
   --> src\ksl_bench.rs:116:38
    |
115 |         check(&ast)
    |         ----------- this can't be annotated with `?` because it has type `Result<_, Vec<ksl_types::TypeError>>`
116 |             .map_err(|errors| errors)?;
    |                                      ^ the trait `std::convert::From<Vec<ksl_types::TypeError>>` is not implemented for `Vec<KslError>`
    |
    = note: the question mark operation (`?`) implicitly performs a conversion on the error value using the `From` trait
    = help: the following other types implement trait `std::convert::From<T>`:
              `Vec<T, A>` implements `std::convert::From<BinaryHeap<T, A>>`
              `Vec<T, A>` implements `std::convert::From<VecDeque<T, A>>`
              `Vec<T, A>` implements `std::convert::From<std::boxed::Box<[T], A>>`
              `Vec<T>` implements `std::convert::From<&[T; N]>`
              `Vec<T>` implements `std::convert::From<&[T]>`
              `Vec<T>` implements `std::convert::From<&mut [T; N]>`
              `Vec<T>` implements `std::convert::From<&mut [T]>`
              `Vec<T>` implements `std::convert::From<Cow<'_, [T]>>`
            and 21 others
    = note: required for `std::result::Result<(), Vec<KslError>>` to implement `FromResidual<std::result::Result<Infallible, Vec<ksl_types::TypeError>>>`

error[E0061]: this function takes 7 arguments but 1 argument was supplied
   --> src\ksl_bench.rs:119:24
    |
119 |         let bytecode = compile(&ast)
    |                        ^^^^^^^------ multiple arguments are missing
    |
note: expected `&[AstNode]`, found `&Vec<AstNode>`
   --> src\ksl_bench.rs:119:32
    |
119 |         let bytecode = compile(&ast)
    |                                ^^^^
    = note: expected reference `&[ksl_ast::AstNode]`
               found reference `&Vec<ksl_macros::AstNode>`
note: function defined here
   --> src\ksl_compiler.rs:803:8
    |
803 | pub fn compile(
    |        ^^^^^^^
804 |     ast: &[AstNode],
    |     ---------------
805 |     module_name: &str,
    |     -----------------
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
119 -         let bytecode = compile(&ast)
119 +         let bytecode = compile(/* &[ksl_ast::AstNode] */, /* &str */, /* CompileTarget */, /* &str */, /* &ksl_analyzer::PerformanceMetrics */, /* bool */, /* std::option::Option<ksl_macros::HotReloadConfig> */)
    |

error[E0599]: `KslError` is not an iterator
   --> src\ksl_bench.rs:120:38
    |
120 | ...   .map_err(|errors| errors.into_iter().map(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, ...
    |                                ^^^^^^^^^ `KslError` is not an iterator
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- method `into_iter` not found for this enum because it doesn't satisfy `KslError: IntoIterator` or `KslError: Iterator`
    |
    = note: the following trait bounds were not satisfied:
            `KslError: Iterator`
            which is required by `KslError: IntoIterator`
            `&KslError: Iterator`
            which is required by `&KslError: IntoIterator`
            `&mut KslError: Iterator`
            which is required by `&mut KslError: IntoIterator`
note: the trait `Iterator` must be implemented
   --> /rustc/05f9846f893b09a1be1fc8560e33fc3c815cfecb\library\core\src\iter\traits\iterator.rs:39:1
    = help: items from traits can only be used if the trait is implemented and in scope
    = note: the following traits define an item `into_iter`, perhaps you need to implement one of them:
            candidate #1: `IntoIterator`
            candidate #2: `rayon::iter::plumbing::Producer`

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_bench.rs:120:58
    |
120 | ...o_iter().map(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1))).collect())?;
    |                     ^^^^^^^^^^^^^^^^^^^^------------------------------------------ argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
120 -             .map_err(|errors| errors.into_iter().map(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1))).collect())?;
120 +             .map_err(|errors| errors.into_iter().map(|e| KslError::type_error(e.to_string(), SourcePosition::new(1, 1), /* std::string::String */)).collect())?;
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_bench.rs:163:22
    |
163 |               Err(vec![KslError::type_error(
    |  ______________________^^^^^^^^^^^^^^^^^^^^-
164 | |                 "No benchmark functions found".to_string(),
165 | |                 SourcePosition::new(1, 1),
166 | |             )])
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
163 -             Err(vec![KslError::type_error(
164 -                 "No benchmark functions found".to_string(),
165 -                 SourcePosition::new(1, 1),
166 -             )])
163 +             Err(vec![KslError::type_error("No benchmark functions found".to_string(), SourcePosition::new(1, 1), /* std::string::String */)])
    |

error[E0061]: this function takes 1 argument but 0 arguments were supplied
   --> src\ksl_bench.rs:195:33
    |
195 |         let metrics_collector = MetricsCollector::new();
    |                                 ^^^^^^^^^^^^^^^^^^^^^-- argument #1 of type `MetricsConfig` is missing
    |
note: associated function defined here
   --> src\ksl_metrics.rs:91:12
    |
91  |     pub fn new(config: MetricsConfig) -> Result<Self, KslError> {
    |            ^^^ ---------------------
help: provide the argument
    |
195 -         let metrics_collector = MetricsCollector::new();
195 +         let metrics_collector = MetricsCollector::new(/* MetricsConfig */);
    |

error[E0599]: no method named `start_collection` found for enum `std::result::Result` in the current scope
   --> src\ksl_bench.rs:196:27
    |
196 |         metrics_collector.start_collection();
    |                           ^^^^^^^^^^^^^^^^ method not found in `Result<MetricsCollector, KslError>`
    |
note: the method `start_collection` exists on the type `MetricsCollector`
   --> src\ksl_metrics.rs:331:5
    |
331 |     pub fn start_collection(&mut self) {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
help: consider using `Result::expect` to unwrap the `MetricsCollector` value, panicking if the value is a `Result::Err`
    |
196 |         metrics_collector.expect("REASON").start_collection();
    |                          +++++++++++++++++

error[E0034]: multiple applicable items in scope
   --> src\ksl_bench.rs:200:31
    |
200 |         let mut vm = KapraVM::new(bench_bytecode.clone());
    |                               ^^^ multiple `new` found
    |
note: candidate #1 is defined in an impl for the type `kapra_vm::KapraVM`
   --> src\kapra_vm.rs:199:5
    |
199 |     pub fn new(bytecode: KapraBytecode, runtime: Option<Arc<AsyncRuntime>>, gas_limit: Option<u64>) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
note: candidate #2 is defined in an impl for the type `kapra_vm::KapraVM`
   --> src\ksl_kapra_validator.rs:162:5
    |
162 | /     pub fn new(
163 | |         is_embedded: bool,
164 | |         consensus_runtime: Arc<ConsensusRuntime>,
165 | |         async_runtime: Arc<AsyncRuntime>,
166 | |         contract_compiler: Arc<ContractCompiler>,
167 | |     ) -> Self {
    | |_____________^

error[E0599]: no method named `clone` found for struct `KapraBytecode` in the current scope
   --> src\ksl_bench.rs:200:50
    |
200 |         let mut vm = KapraVM::new(bench_bytecode.clone());
    |                                                  ^^^^^ method not found in `KapraBytecode`
    |
   ::: src\ksl_bytecode.rs:720:1
    |
720 | pub struct KapraBytecode {
    | ------------------------ method `clone` not found for this struct
    |
    = help: items from traits can only be used if the trait is implemented and in scope
    = note: the following trait defines an item `clone`, perhaps you need to implement it:
            candidate #1: `std::clone::Clone`

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_bench.rs:204:18
    |
204 |               vec![KslError::type_error(
    |  __________________^^^^^^^^^^^^^^^^^^^^-
205 | |                 format!("Runtime error at instruction {}: {}", e.pc, e.message),
206 | |                 SourcePosition::new(1, 1),
207 | |             )]
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
204 -             vec![KslError::type_error(
205 -                 format!("Runtime error at instruction {}: {}", e.pc, e.message),
206 -                 SourcePosition::new(1, 1),
207 -             )]
204 +             vec![KslError::type_error(format!("Runtime error at instruction {}: {}", e.pc, e.message), SourcePosition::new(1, 1), /* std::string::String */)]
    |

error[E0599]: no method named `stop_collection` found for enum `std::result::Result` in the current scope
   --> src\ksl_bench.rs:211:41
    |
211 |         let metrics = metrics_collector.stop_collection();
    |                                         ^^^^^^^^^^^^^^^ method not found in `Result<MetricsCollector, KslError>`
    |
note: the method `stop_collection` exists on the type `MetricsCollector`
   --> src\ksl_metrics.rs:335:5
    |
335 |     pub fn stop_collection(&mut self) -> Vec<MetricValue> {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
help: consider using `Result::expect` to unwrap the `MetricsCollector` value, panicking if the value is a `Result::Err`
    |
211 |         let metrics = metrics_collector.expect("REASON").stop_collection();
    |                                        +++++++++++++++++

error[E0599]: no method named `get_cache_stats` found for enum `std::result::Result` in the current scope
   --> src\ksl_bench.rs:212:45
    |
212 |         let cache_stats = metrics_collector.get_cache_stats();
    |                                             ^^^^^^^^^^^^^^^ method not found in `Result<MetricsCollector, KslError>`
    |
note: the method `get_cache_stats` exists on the type `MetricsCollector`
   --> src\ksl_metrics.rs:339:5
    |
339 |     pub fn get_cache_stats(&self) -> CacheStats {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
help: consider using `Result::expect` to unwrap the `MetricsCollector` value, panicking if the value is a `Result::Err`
    |
212 |         let cache_stats = metrics_collector.expect("REASON").get_cache_stats();
    |                                            +++++++++++++++++

error[E0599]: no method named `get_async_metrics` found for enum `std::result::Result` in the current scope
   --> src\ksl_bench.rs:213:47
    |
213 |         let async_metrics = metrics_collector.get_async_metrics();
    |                                               ^^^^^^^^^^^^^^^^^ method not found in `Result<MetricsCollector, KslError>`
    |
note: the method `get_async_metrics` exists on the type `MetricsCollector`
   --> src\ksl_metrics.rs:354:5
    |
354 |     pub fn get_async_metrics(&self) -> AsyncMetrics {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
help: consider using `Result::expect` to unwrap the `MetricsCollector` value, panicking if the value is a `Result::Err`
    |
213 |         let async_metrics = metrics_collector.expect("REASON").get_async_metrics();
    |                                              +++++++++++++++++

error[E0599]: no method named `get_cpu_usage` found for enum `std::result::Result` in the current scope
   --> src\ksl_bench.rs:227:42
    |
227 |             cpu_usage: metrics_collector.get_cpu_usage(),
    |                                          ^^^^^^^^^^^^^ method not found in `Result<MetricsCollector, KslError>`
    |
note: the method `get_cpu_usage` exists on the type `MetricsCollector`
   --> src\ksl_metrics.rs:371:5
    |
371 |     pub fn get_cpu_usage(&self) -> f64 {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
help: consider using `Result::expect` to unwrap the `MetricsCollector` value, panicking if the value is a `Result::Err`
    |
227 |             cpu_usage: metrics_collector.expect("REASON").get_cpu_usage(),
    |                                         +++++++++++++++++

error[E0308]: mismatched types
   --> src\ksl_bench.rs:396:36
    |
396 |         log_metrics(tps, duration, &result);
    |         -----------                ^^^^^^^ expected `ksl_metrics::BlockResult`, found `ksl_bench::BlockResult`
    |         |
    |         arguments to this function are incorrect
    |
    = note: `ksl_bench::BlockResult` and `ksl_metrics::BlockResult` have similar names, but are actually distinct types
note: `ksl_bench::BlockResult` is defined in module `crate::ksl_bench` of the current crate
   --> src\ksl_bench.rs:347:1
    |
347 | pub struct BlockResult {
    | ^^^^^^^^^^^^^^^^^^^^^^
note: `ksl_metrics::BlockResult` is defined in module `crate::ksl_metrics` of the current crate
   --> src\ksl_metrics.rs:575:1
    |
575 | pub struct BlockResult {
    | ^^^^^^^^^^^^^^^^^^^^^^
note: function defined here
   --> src\ksl_metrics.rs:611:8
    |
611 | pub fn log_metrics(tps: usize, duration: Duration, result: &BlockResult) {
    |        ^^^^^^^^^^^                                 --------------------

warning: use of deprecated method `rand::Rng::gen_range`: Renamed to `random_range`
   --> src\ksl_bench.rs:440:53
    |
440 |                     chunk_gas += rand::thread_rng().gen_range(1000..10000);
    |                                                     ^^^^^^^^^

warning: unused variable: `tx`
   --> src\ksl_bench.rs:436:17
    |
436 |             for tx in chunk {
    |                 ^^ help: if this is intentional, prefix it with an underscore: `_tx`

error[E0599]: no variant or associated item named `serialization_error` found for enum `KslError` in the current scope
   --> src\ksl_package_publish.rs:169:36
    |
169 |             .map_err(|e| KslError::serialization_error(
    |                                    ^^^^^^^^^^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `serialization_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `io_error` found for enum `KslError` in the current scope
   --> src\ksl_package_publish.rs:175:36
    |
175 |             .map_err(|e| KslError::io_error(
    |                                    ^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `io_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `io_error` found for enum `KslError` in the current scope
   --> src\ksl_package_publish.rs:182:36
    |
182 |             .map_err(|e| KslError::io_error(
    |                                    ^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `io_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `io_error` found for enum `KslError` in the current scope
   --> src\ksl_package_publish.rs:191:40
    |
191 |                 .map_err(|e| KslError::io_error(
    |                                        ^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `io_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0277]: the trait bound `&Vec<u8>: std::io::Read` is not satisfied
   --> src\ksl_package_publish.rs:197:37
    |
197 |             builder.append(&header, content)
    |                     ------          ^^^^^^^ the trait `std::io::Read` is not implemented for `&Vec<u8>`
    |                     |
    |                     required by a bound introduced by this call
    |
note: required by a bound in `tar::Builder::<W>::append`
   --> C:\Users\ecomm\.cargo\registry\src\index.crates.io-1949cf8c6b5b557f\tar-0.4.44\src\builder.rs:132:22
    |
132 |     pub fn append<R: Read>(&mut self, header: &Header, mut data: R) -> io::Result<()> {
    |                      ^^^^ required by this bound in `Builder::<W>::append`

error[E0599]: no variant or associated item named `io_error` found for enum `KslError` in the current scope
   --> src\ksl_package_publish.rs:198:40
    |
198 |                 .map_err(|e| KslError::io_error(
    |                                        ^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `io_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `io_error` found for enum `KslError` in the current scope
   --> src\ksl_package_publish.rs:205:36
    |
205 |             .map_err(|e| KslError::io_error(
    |                                    ^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `io_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no method named `read` found for struct `std::io::Cursor` in the current scope
   --> src\ksl_package_publish.rs:217:28
    |
217 |             let n = cursor.read(&mut buffer)
    |                            ^^^^
    |
    = help: items from traits can only be used if the trait is in scope
help: there is a method `red` with a similar name, but with different arguments
   --> C:\Users\ecomm\.cargo\registry\src\index.crates.io-1949cf8c6b5b557f\yansi-1.0.1\src\paint.rs:130:5
    |
130 |     properties!(signature(&Self) -> Painted<&Self>);
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = note: this error originates in the macro `signature` which comes from the expansion of the macro `properties` (in Nightly builds, run with -Z macro-backtrace for more info)
help: the following traits which provide `read` are implemented but not in scope; perhaps you want to import one of them
    |
5   + use bincode::de::read::Reader;
    |
5   + use cranelift_assembler_x64::api::RegisterVisitor;
    |
5   + use cranelift_object::object::ReadCacheOps;
    |
5   + use cranelift_object::object::ReadRef;
    |
      and 13 other candidates

error[E0599]: no variant or associated item named `io_error` found for enum `KslError` in the current scope
   --> src\ksl_package_publish.rs:218:40
    |
218 |                 .map_err(|e| KslError::io_error(
    |                                        ^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `io_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `io_error` found for enum `KslError` in the current scope
   --> src\ksl_package_publish.rs:228:40
    |
228 |                 .map_err(|e| KslError::io_error(
    |                                        ^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `io_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no method named `finish` found for struct `Compress` in the current scope
   --> src\ksl_package_publish.rs:236:26
    |
236 |         let n = compress.finish(&mut out)
    |                          ^^^^^^ method not found in `Compress`

error[E0599]: no variant or associated item named `io_error` found for enum `KslError` in the current scope
   --> src\ksl_package_publish.rs:237:36
    |
237 |             .map_err(|e| KslError::io_error(
    |                                    ^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `io_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `validation_error` found for enum `KslError` in the current scope
   --> src\ksl_package_publish.rs:263:38
    |
263 |             .ok_or_else(|| KslError::validation_error(
    |                                      ^^^^^^^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `validation_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no method named `json` found for struct `reqwest::RequestBuilder` in the current scope
   --> src\ksl_package_publish.rs:271:14
    |
268 |           let response = self.registry_client
    |  ________________________-
269 | |             .post("https://registry.ksl.dev/upload")
270 | |             .header("Authorization", format!("Bearer {}", token))
271 | |             .json(&archive.config)
    | |             -^^^^ method not found in `RequestBuilder`
    | |_____________|
    |

error[E0599]: no variant or associated item named `network_error` found for enum `KslError` in the current scope
   --> src\ksl_package_publish.rs:275:36
    |
275 |             .map_err(|e| KslError::network_error(
    |                                    ^^^^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `network_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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
help: there is an associated function `network` with a similar name
   --> src\ksl_errors.rs:148:5
    |
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

error[E0599]: no variant or associated item named `network_error` found for enum `KslError` in the current scope
   --> src\ksl_package_publish.rs:281:34
    |
281 |             return Err(KslError::network_error(
    |                                  ^^^^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `network_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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
help: there is an associated function `network` with a similar name
   --> src\ksl_errors.rs:148:5
    |
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

error[E0599]: no method named `analyze_gas_usage_from_source` found for struct `Arc<Analyzer>` in the current scope
   --> src\ksl_package_publish.rs:294:47
    |
294 |                 let gas_stats = self.analyzer.analyze_gas_usage_from_source(content).await?;
    |                                               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ method not found in `Arc<Analyzer>`

error[E0599]: no variant or associated item named `validation_error` found for enum `KslError` in the current scope
   --> src\ksl_package_publish.rs:296:42
    |
296 |                     return Err(KslError::validation_error(
    |                                          ^^^^^^^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `validation_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0308]: mismatched types
   --> src\ksl_package_publish.rs:311:37
    |
311 |                 if content.contains("#[validator]") && content.contains("#[async]") {
    |                            -------- ^^^^^^^^^^^^^^ expected `&u8`, found `&str`
    |                            |
    |                            arguments to this method are incorrect
    |
    = note: expected reference `&u8`
               found reference `&'static str`
note: method defined here
   --> /rustc/05f9846f893b09a1be1fc8560e33fc3c815cfecb\library\core\src\slice\mod.rs:2551:12

error[E0308]: mismatched types
   --> src\ksl_package_publish.rs:311:73
    |
311 |                 if content.contains("#[validator]") && content.contains("#[async]") {
    |                                                                -------- ^^^^^^^^^^ expected `&u8`, found `&str`
    |                                                                |
    |                                                                arguments to this method are incorrect
    |
    = note: expected reference `&u8`
               found reference `&'static str`
note: method defined here
   --> /rustc/05f9846f893b09a1be1fc8560e33fc3c815cfecb\library\core\src\slice\mod.rs:2551:12

error[E0599]: no variant or associated item named `validation_error` found for enum `KslError` in the current scope
   --> src\ksl_package_publish.rs:312:42
    |
312 |                     return Err(KslError::validation_error(
    |                                          ^^^^^^^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `validation_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0308]: mismatched types
   --> src\ksl_package_publish.rs:319:37
    |
319 |                 if content.contains("unsafe") && !content.contains("#[allow(unsafe)]") {
    |                            -------- ^^^^^^^^ expected `&u8`, found `&str`
    |                            |
    |                            arguments to this method are incorrect
    |
    = note: expected reference `&u8`
               found reference `&'static str`
note: method defined here
   --> /rustc/05f9846f893b09a1be1fc8560e33fc3c815cfecb\library\core\src\slice\mod.rs:2551:12

error[E0308]: mismatched types
   --> src\ksl_package_publish.rs:319:68
    |
319 |                 if content.contains("unsafe") && !content.contains("#[allow(unsafe)]") {
    |                                                           -------- ^^^^^^^^^^^^^^^^^^ expected `&u8`, found `&str`
    |                                                           |
    |                                                           arguments to this method are incorrect
    |
    = note: expected reference `&u8`
               found reference `&'static str`
note: method defined here
   --> /rustc/05f9846f893b09a1be1fc8560e33fc3c815cfecb\library\core\src\slice\mod.rs:2551:12

error[E0599]: no variant or associated item named `validation_error` found for enum `KslError` in the current scope
   --> src\ksl_package_publish.rs:320:42
    |
320 |                     return Err(KslError::validation_error(
    |                                          ^^^^^^^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `validation_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no method named `extract_contract_abi` found for struct `Arc<Analyzer>` in the current scope
   --> src\ksl_package_publish.rs:334:50
    |
334 |                 if let Some(abi) = self.analyzer.extract_contract_abi(content).await? {
    |                                                  ^^^^^^^^^^^^^^^^^^^^ method not found in `Arc<Analyzer>`

error[E0599]: no variant or associated item named `io_error` found for enum `KslError` in the current scope
   --> src\ksl_package_publish.rs:338:48
    |
338 |                         .map_err(|e| KslError::io_error(
    |                                                ^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `io_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `validation_error` found for enum `KslError` in the current scope
   --> src\ksl_package_publish.rs:368:38
    |
368 |             .ok_or_else(|| KslError::validation_error(
    |                                      ^^^^^^^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `validation_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `network_error` found for enum `KslError` in the current scope
   --> src\ksl_package_publish.rs:378:36
    |
378 |             .map_err(|e| KslError::network_error(
    |                                    ^^^^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `network_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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
help: there is an associated function `network` with a similar name
   --> src\ksl_errors.rs:148:5
    |
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

error[E0599]: no variant or associated item named `network_error` found for enum `KslError` in the current scope
   --> src\ksl_package_publish.rs:384:34
    |
384 |             return Err(KslError::network_error(
    |                                  ^^^^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `network_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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
help: there is an associated function `network` with a similar name
   --> src\ksl_errors.rs:148:5
    |
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

error[E0599]: no variant or associated item named `validation_error` found for enum `KslError` in the current scope
   --> src\ksl_package_publish.rs:396:38
    |
396 |             .ok_or_else(|| KslError::validation_error(
    |                                      ^^^^^^^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `validation_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no method named `json` found for struct `reqwest::RequestBuilder` in the current scope
   --> src\ksl_package_publish.rs:404:14
    |
401 |           let response = self.registry_client
    |  ________________________-
402 | |             .post(format!("https://registry.ksl.dev/packages/{}/{}/deprecate", name, version))
403 | |             .header("Authorization", format!("Bearer {}", token))
404 | |             .json(&json!({ "reason": reason }))
    | |             -^^^^ method not found in `RequestBuilder`
    | |_____________|
    |

error[E0599]: no variant or associated item named `network_error` found for enum `KslError` in the current scope
   --> src\ksl_package_publish.rs:407:36
    |
407 |             .map_err(|e| KslError::network_error(
    |                                    ^^^^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `network_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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
help: there is an associated function `network` with a similar name
   --> src\ksl_errors.rs:148:5
    |
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

error[E0599]: no variant or associated item named `network_error` found for enum `KslError` in the current scope
   --> src\ksl_package_publish.rs:413:34
    |
413 |             return Err(KslError::network_error(
    |                                  ^^^^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `network_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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
help: there is an associated function `network` with a similar name
   --> src\ksl_errors.rs:148:5
    |
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

error[E0599]: no variant or associated item named `validation_error` found for enum `KslError` in the current scope
   --> src\ksl_package_publish.rs:425:38
    |
425 |             .ok_or_else(|| KslError::validation_error(
    |                                      ^^^^^^^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `validation_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `network_error` found for enum `KslError` in the current scope
   --> src\ksl_package_publish.rs:435:36
    |
435 |             .map_err(|e| KslError::network_error(
    |                                    ^^^^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `network_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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
help: there is an associated function `network` with a similar name
   --> src\ksl_errors.rs:148:5
    |
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

error[E0599]: no variant or associated item named `network_error` found for enum `KslError` in the current scope
   --> src\ksl_package_publish.rs:441:34
    |
441 |             return Err(KslError::network_error(
    |                                  ^^^^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `network_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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
help: there is an associated function `network` with a similar name
   --> src\ksl_errors.rs:148:5
    |
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

error[E0599]: no method named `load_baseline` found for mutable reference `&mut CiSystem` in the current scope
   --> src\ksl_ci.rs:377:18
    |
377 |             self.load_baseline()?;
    |                  ^^^^^^^^^^^^^ method not found in `&mut CiSystem`

error[E0308]: mismatched types
   --> src\ksl_ci.rs:392:16
    |
392 |         if let Some(metrics) = self.collect_resource_metrics()? {
    |                ^^^^^^^^^^^^^   -------------------------------- this expression has type `ksl_ci::ResourceMetrics`
    |                |
    |                expected `ResourceMetrics`, found `Option<_>`
    |
    = note: expected struct `ksl_ci::ResourceMetrics`
                 found enum `std::option::Option<_>`

error[E0599]: no method named `check_regressions` found for mutable reference `&mut CiSystem` in the current scope
   --> src\ksl_ci.rs:398:14
    |
398 |         self.check_regressions()?;
    |              ^^^^^^^^^^^^^^^^^ method not found in `&mut CiSystem`

error[E0063]: missing field `output_dir` in initializer of `ksl_test::TestConfig`
   --> src\ksl_ci.rs:472:27
    |
472 |         let test_config = TestConfig {
    |                           ^^^^^^^^^^ missing `output_dir`

error[E0308]: `if` and `else` have incompatible types
   --> src\ksl_ci.rs:489:13
    |
486 |           let resource_metrics = if self.config.measure_resources {
    |  ________________________________-
487 | |             self.collect_resource_metrics()?
    | |             -------------------------------- expected because of this
488 | |         } else {
489 | |             None
    | |             ^^^^ expected `ResourceMetrics`, found `Option<_>`
490 | |         };
    | |_________- `if` and `else` have incompatible types
    |
    = note: expected struct `ksl_ci::ResourceMetrics`
                 found enum `std::option::Option<_>`
help: consider using `Option::expect` to unwrap the `std::option::Option<_>` value, panicking if the value is an `Option::None`
    |
490 |         }.expect("REASON");
    |          +++++++++++++++++

error[E0599]: no method named `is_ok` found for unit type `()` in the current scope
   --> src\ksl_ci.rs:503:33
    |
503 |             passed: test_result.is_ok(),
    |                                 ^^^^^ method not found in `()`

error[E0599]: no method named `err` found for unit type `()` in the current scope
   --> src\ksl_ci.rs:504:32
    |
504 |             error: test_result.err(),
    |                                ^^^ method not found in `()`

error[E0599]: no method named `get_gas_stats` found for struct `Arc<Analyzer>` in the current scope
   --> src\ksl_ci.rs:506:40
    |
506 |             gas_metrics: self.analyzer.get_gas_stats().map(|stats| GasStats {
    |                                        ^^^^^^^^^^^^^ method not found in `Arc<Analyzer>`

error[E0560]: struct `GasStats` has no field named `max_gas`
   --> src\ksl_ci.rs:508:17
    |
508 |                 max_gas: stats.max_gas,
    |                 ^^^^^^^ `GasStats` does not have this field
    |
    = note: available fields are: `gas_utilization`

error[E0599]: no method named `json` found for struct `reqwest::RequestBuilder` in the current scope
   --> src\ksl_ci.rs:608:18
    |
607 | /             client.post(&config.url)
608 | |                 .json(&payload)
    | |                 -^^^^ method not found in `RequestBuilder`
    | |_________________|
    |

error[E0599]: no variant or associated item named `scheduler_error` found for enum `KslError` in the current scope
   --> src\ksl_kapra_scheduler.rs:272:38
    |
272 |                 return Err(KslError::scheduler_error(error, SourcePosition::new(1, 1)));
    |                                      ^^^^^^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `scheduler_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no method named `execute_contract` found for struct `AsyncRuntime` in the current scope
   --> src\ksl_kapra_scheduler.rs:299:41
    |
299 |         let result = self.async_runtime.execute_contract(contract_id, task).await?;
    |                                         ^^^^^^^^^^^^^^^^ method not found in `AsyncRuntime`
    |
   ::: src\ksl_async.rs:38:1
    |
38  | pub struct AsyncRuntime {
    | ----------------------- method `execute_contract` not found for this struct

error[E0599]: no method named `validate_block` found for reference `&ConsensusRuntime` in the current scope
   --> src\ksl_kapra_scheduler.rs:305:32
    |
305 |         let result = consensus.validate_block(&[0; 32], 0).await?;
    |                                ^^^^^^^^^^^^^^
    |
help: there is a method `validate_block_gpu` with a similar name
    |
305 |         let result = consensus.validate_block_gpu(&[0; 32], 0).await?;
    |                                              ++++

warning: use of deprecated method `rand::Rng::r#gen`: Renamed to `random` to avoid conflict with the new `gen` keyword in Rust 2024.
   --> src\ksl_kapra_scheduler.rs:906:33
    |
906 |             selected.insert(rng.gen());
    |                                 ^^^

warning: unused variable: `history`
   --> src\ksl_kapra_scheduler.rs:914:13
    |
914 |         let history = self.workload_history.read().await;
    |             ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_history`

warning: unused variable: `topic`
   --> src\ksl_iot.rs:189:30
    |
189 |     pub async fn send(&self, topic: &[u8], message: &[u8]) -> Result<(), IoTRuntimeError> {
    |                              ^^^^^ help: if this is intentional, prefix it with an underscore: `_topic`

warning: unused variable: `message`
   --> src\ksl_iot.rs:189:44
    |
189 |     pub async fn send(&self, topic: &[u8], message: &[u8]) -> Result<(), IoTRuntimeError> {
    |                                            ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_message`

error[E0308]: mismatched types
   --> src\ksl_embedded.rs:260:31
    |
260 |         self.kapra_vm.execute(bytecode).await?;
    |                       ------- ^^^^^^^^ expected `ksl_kapra_validator::Bytecode`, found `ksl_embedded::Bytecode`
    |                       |
    |                       arguments to this method are incorrect
    |
    = note: `ksl_embedded::Bytecode` and `ksl_kapra_validator::Bytecode` have similar names, but are actually distinct types
note: `ksl_embedded::Bytecode` is defined in module `crate::ksl_embedded` of the current crate
   --> src\ksl_embedded.rs:12:1
    |
12  | pub struct Bytecode {
    | ^^^^^^^^^^^^^^^^^^^
note: `ksl_kapra_validator::Bytecode` is defined in module `crate::ksl_kapra_validator` of the current crate
   --> src\ksl_kapra_validator.rs:31:1
    |
31  | pub struct Bytecode {
    | ^^^^^^^^^^^^^^^^^^^
note: method defined here
   --> src\ksl_kapra_validator.rs:182:18
    |
182 |     pub async fn execute(&mut self, bytecode: &Bytecode) -> AsyncResult<bool> {
    |                  ^^^^^^^            -------------------

warning: unused variable: `file`
   --> src\ksl_embedded.rs:338:35
    |
338 | pub async fn run_compile_embedded(file: &str) -> Result<Vec<u8>, KslError> {
    |                                   ^^^^ help: if this is intentional, prefix it with an underscore: `_file`

error[E0599]: no variant or associated item named `network_error` found for enum `KslError` in the current scope
   --> src\ksl_community.rs:189:34
    |
189 |             return Err(KslError::network_error(
    |                                  ^^^^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `network_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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
help: there is an associated function `network` with a similar name
   --> src\ksl_errors.rs:148:5
    |
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

error[E0599]: no variant or associated item named `network_error` found for enum `KslError` in the current scope
   --> src\ksl_community.rs:211:34
    |
211 |             return Err(KslError::network_error(
    |                                  ^^^^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `network_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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
help: there is an associated function `network` with a similar name
   --> src\ksl_errors.rs:148:5
    |
148 |     pub fn network(message: String, position: SourcePosition, code: String) -> Self {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

error[E0599]: no variant or associated item named `validation_error` found for enum `KslError` in the current scope
   --> src\ksl_community.rs:258:34
    |
258 |             return Err(KslError::validation_error(
    |                                  ^^^^^^^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `validation_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `validation_error` found for enum `KslError` in the current scope
   --> src\ksl_community.rs:326:34
    |
326 |             return Err(KslError::validation_error(
    |                                  ^^^^^^^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `validation_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `validation_error` found for enum `KslError` in the current scope
   --> src\ksl_community.rs:335:34
    |
335 |             return Err(KslError::validation_error(
    |                                  ^^^^^^^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `validation_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `not_found_error` found for enum `KslError` in the current scope
   --> src\ksl_community.rs:362:23
    |
362 |             KslError::not_found_error(
    |                       ^^^^^^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `not_found_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `validation_error` found for enum `KslError` in the current scope
   --> src\ksl_community.rs:391:34
    |
391 |             return Err(KslError::validation_error(
    |                                  ^^^^^^^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `validation_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `not_found_error` found for enum `KslError` in the current scope
   --> src\ksl_community.rs:408:23
    |
408 |             KslError::not_found_error(
    |                       ^^^^^^^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `not_found_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `cli_error` found for enum `KslError` in the current scope
   --> src\ksl_community.rs:441:32
    |
441 |             _ => Err(KslError::cli_error(
    |                                ^^^^^^^^^ variant or associated item not found in `KslError`
    |
   ::: src\ksl_errors.rs:58:1
    |
58  | pub enum KslError {
    | ----------------- variant or associated item `cli_error` not found for this enum
    |
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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
help: there is a method `clear` with a similar name, but with different arguments
   --> C:\Users\ecomm\.cargo\registry\src\index.crates.io-1949cf8c6b5b557f\yansi-1.0.1\src\paint.rs:130:5
    |
130 |     properties!(signature(&Self) -> Painted<&Self>);
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = note: this error originates in the macro `signature` which comes from the expansion of the macro `properties` (in Nightly builds, run with -Z macro-backtrace for more info)

error[E0599]: no method named `license` found for reference `&ksl_dep_audit::Package` in the current scope
   --> src\ksl_dep_audit.rs:262:52
    |
262 |         if !self.allowed_licenses.contains(package.license()) {
    |                                                    ^^^^^^^-- help: remove the arguments
    |                                                    |
    |                                                    field, not a method

error[E0599]: no method named `license` found for reference `&ksl_dep_audit::Package` in the current scope
   --> src\ksl_dep_audit.rs:265:25
    |
265 |                 package.license(),
    |                         ^^^^^^^-- help: remove the arguments
    |                         |
    |                         field, not a method

error[E0599]: no method named `name` found for reference `&ksl_dep_audit::Package` in the current scope
   --> src\ksl_dep_audit.rs:266:25
    |
266 |                 package.name(),
    |                         ^^^^-- help: remove the arguments
    |                         |
    |                         field, not a method
    |
    = help: items from traits can only be used if the trait is implemented and in scope
    = note: the following traits define an item `name`, perhaps you need to implement one of them:
            candidate #1: `AbiMutator`
            candidate #2: `LLVMPass`
            candidate #3: `MacroPlugin`
            candidate #4: `TransformPass`
            candidate #5: `ksl_stdlib::StdLibFunctionTrait`
            candidate #6: `Nlist`
            candidate #7: `ObjectComdat`
            candidate #8: `ObjectSection`
            candidate #9: `ObjectSegment`
            candidate #10: `ObjectSymbol`
            candidate #11: `TargetIsa`
            candidate #12: `clap::args::any_arg::AnyArg`
            candidate #13: `codespan_reporting::files::Files`
            candidate #14: `cranelift_codegen::gimli::write::Section`
            candidate #15: `cranelift_codegen::isa::TargetIsa`
            candidate #16: `cranelift_object::object::coff::ImageSymbol`
            candidate #17: `cranelift_object::object::read::elf::SectionHeader`
            candidate #18: `cranelift_object::object::read::elf::Sym`
            candidate #19: `cranelift_object::object::read::macho::Section`
            candidate #20: `cranelift_object::object::read::macho::Segment`
            candidate #21: `cranelift_object::object::read::xcoff::SectionHeader`
            candidate #22: `cranelift_object::object::read::xcoff::Symbol`
            candidate #23: `gimli::write::section::Section`
            candidate #24: `isa::pulley_shared::PulleyTargetKind`
            candidate #25: `object::read::coff::symbol::ImageSymbol`
            candidate #26: `object::read::elf::section::SectionHeader`
            candidate #27: `object::read::elf::symbol::Sym`
            candidate #28: `object::read::macho::section::Section`
            candidate #29: `object::read::macho::segment::Segment`
            candidate #30: `object::read::macho::symbol::Nlist`
            candidate #31: `object::read::traits::ObjectComdat`
            candidate #32: `object::read::traits::ObjectSection`
            candidate #33: `object::read::traits::ObjectSegment`
            candidate #34: `object::read::traits::ObjectSymbol`
            candidate #35: `object::read::xcoff::section::SectionHeader`
            candidate #36: `object::read::xcoff::symbol::Symbol`
            candidate #37: `wasmer_compiler::compiler::Compiler`

error[E0599]: no method named `metadata` found for reference `&ksl_dep_audit::Package` in the current scope
   --> src\ksl_dep_audit.rs:391:51
    |
391 |         let mut report = AuditReport::new(package.metadata().clone());
    |                                                   ^^^^^^^^ method not found in `&Package`
    |
    = help: items from traits can only be used if the trait is implemented and in scope
    = note: the following traits define an item `metadata`, perhaps you need to implement one of them:
            candidate #1: `powerfmt::smart_display::SmartDisplay`
            candidate #2: `tracing_core::callsite::Callsite`

error[E0599]: no method named `name` found for reference `&ksl_dep_audit::Package` in the current scope
   --> src\ksl_dep_audit.rs:412:39
    |
412 |             report.add_issue(&package.name(), AuditIssue::Vulnerability(vuln.clone()));
    |                                       ^^^^-- help: remove the arguments
    |                                       |
    |                                       field, not a method
    |
    = help: items from traits can only be used if the trait is implemented and in scope
    = note: the following traits define an item `name`, perhaps you need to implement one of them:
            candidate #1: `AbiMutator`
            candidate #2: `LLVMPass`
            candidate #3: `MacroPlugin`
            candidate #4: `TransformPass`
            candidate #5: `ksl_stdlib::StdLibFunctionTrait`
            candidate #6: `Nlist`
            candidate #7: `ObjectComdat`
            candidate #8: `ObjectSection`
            candidate #9: `ObjectSegment`
            candidate #10: `ObjectSymbol`
            candidate #11: `TargetIsa`
            candidate #12: `clap::args::any_arg::AnyArg`
            candidate #13: `codespan_reporting::files::Files`
            candidate #14: `cranelift_codegen::gimli::write::Section`
            candidate #15: `cranelift_codegen::isa::TargetIsa`
            candidate #16: `cranelift_object::object::coff::ImageSymbol`
            candidate #17: `cranelift_object::object::read::elf::SectionHeader`
            candidate #18: `cranelift_object::object::read::elf::Sym`
            candidate #19: `cranelift_object::object::read::macho::Section`
            candidate #20: `cranelift_object::object::read::macho::Segment`
            candidate #21: `cranelift_object::object::read::xcoff::SectionHeader`
            candidate #22: `cranelift_object::object::read::xcoff::Symbol`
            candidate #23: `gimli::write::section::Section`
            candidate #24: `isa::pulley_shared::PulleyTargetKind`
            candidate #25: `object::read::coff::symbol::ImageSymbol`
            candidate #26: `object::read::elf::section::SectionHeader`
            candidate #27: `object::read::elf::symbol::Sym`
            candidate #28: `object::read::macho::section::Section`
            candidate #29: `object::read::macho::segment::Segment`
            candidate #30: `object::read::macho::symbol::Nlist`
            candidate #31: `object::read::traits::ObjectComdat`
            candidate #32: `object::read::traits::ObjectSection`
            candidate #33: `object::read::traits::ObjectSegment`
            candidate #34: `object::read::traits::ObjectSymbol`
            candidate #35: `object::read::xcoff::section::SectionHeader`
            candidate #36: `object::read::xcoff::symbol::Symbol`
            candidate #37: `wasmer_compiler::compiler::Compiler`

error[E0599]: no method named `name` found for reference `&ksl_dep_audit::Package` in the current scope
   --> src\ksl_dep_audit.rs:418:39
    |
418 |             report.add_issue(&package.name(), AuditIssue::Security(issue));
    |                                       ^^^^-- help: remove the arguments
    |                                       |
    |                                       field, not a method
    |
    = help: items from traits can only be used if the trait is implemented and in scope
    = note: the following traits define an item `name`, perhaps you need to implement one of them:
            candidate #1: `AbiMutator`
            candidate #2: `LLVMPass`
            candidate #3: `MacroPlugin`
            candidate #4: `TransformPass`
            candidate #5: `ksl_stdlib::StdLibFunctionTrait`
            candidate #6: `Nlist`
            candidate #7: `ObjectComdat`
            candidate #8: `ObjectSection`
            candidate #9: `ObjectSegment`
            candidate #10: `ObjectSymbol`
            candidate #11: `TargetIsa`
            candidate #12: `clap::args::any_arg::AnyArg`
            candidate #13: `codespan_reporting::files::Files`
            candidate #14: `cranelift_codegen::gimli::write::Section`
            candidate #15: `cranelift_codegen::isa::TargetIsa`
            candidate #16: `cranelift_object::object::coff::ImageSymbol`
            candidate #17: `cranelift_object::object::read::elf::SectionHeader`
            candidate #18: `cranelift_object::object::read::elf::Sym`
            candidate #19: `cranelift_object::object::read::macho::Section`
            candidate #20: `cranelift_object::object::read::macho::Segment`
            candidate #21: `cranelift_object::object::read::xcoff::SectionHeader`
            candidate #22: `cranelift_object::object::read::xcoff::Symbol`
            candidate #23: `gimli::write::section::Section`
            candidate #24: `isa::pulley_shared::PulleyTargetKind`
            candidate #25: `object::read::coff::symbol::ImageSymbol`
            candidate #26: `object::read::elf::section::SectionHeader`
            candidate #27: `object::read::elf::symbol::Sym`
            candidate #28: `object::read::macho::section::Section`
            candidate #29: `object::read::macho::segment::Segment`
            candidate #30: `object::read::macho::symbol::Nlist`
            candidate #31: `object::read::traits::ObjectComdat`
            candidate #32: `object::read::traits::ObjectSection`
            candidate #33: `object::read::traits::ObjectSegment`
            candidate #34: `object::read::traits::ObjectSymbol`
            candidate #35: `object::read::xcoff::section::SectionHeader`
            candidate #36: `object::read::xcoff::symbol::Symbol`
            candidate #37: `wasmer_compiler::compiler::Compiler`

error[E0599]: no method named `name` found for reference `&ksl_dep_audit::Package` in the current scope
   --> src\ksl_dep_audit.rs:423:39
    |
423 |             report.add_issue(&package.name(), AuditIssue::License(license_issue));
    |                                       ^^^^-- help: remove the arguments
    |                                       |
    |                                       field, not a method
    |
    = help: items from traits can only be used if the trait is implemented and in scope
    = note: the following traits define an item `name`, perhaps you need to implement one of them:
            candidate #1: `AbiMutator`
            candidate #2: `LLVMPass`
            candidate #3: `MacroPlugin`
            candidate #4: `TransformPass`
            candidate #5: `ksl_stdlib::StdLibFunctionTrait`
            candidate #6: `Nlist`
            candidate #7: `ObjectComdat`
            candidate #8: `ObjectSection`
            candidate #9: `ObjectSegment`
            candidate #10: `ObjectSymbol`
            candidate #11: `TargetIsa`
            candidate #12: `clap::args::any_arg::AnyArg`
            candidate #13: `codespan_reporting::files::Files`
            candidate #14: `cranelift_codegen::gimli::write::Section`
            candidate #15: `cranelift_codegen::isa::TargetIsa`
            candidate #16: `cranelift_object::object::coff::ImageSymbol`
            candidate #17: `cranelift_object::object::read::elf::SectionHeader`
            candidate #18: `cranelift_object::object::read::elf::Sym`
            candidate #19: `cranelift_object::object::read::macho::Section`
            candidate #20: `cranelift_object::object::read::macho::Segment`
            candidate #21: `cranelift_object::object::read::xcoff::SectionHeader`
            candidate #22: `cranelift_object::object::read::xcoff::Symbol`
            candidate #23: `gimli::write::section::Section`
            candidate #24: `isa::pulley_shared::PulleyTargetKind`
            candidate #25: `object::read::coff::symbol::ImageSymbol`
            candidate #26: `object::read::elf::section::SectionHeader`
            candidate #27: `object::read::elf::symbol::Sym`
            candidate #28: `object::read::macho::section::Section`
            candidate #29: `object::read::macho::segment::Segment`
            candidate #30: `object::read::macho::symbol::Nlist`
            candidate #31: `object::read::traits::ObjectComdat`
            candidate #32: `object::read::traits::ObjectSection`
            candidate #33: `object::read::traits::ObjectSegment`
            candidate #34: `object::read::traits::ObjectSymbol`
            candidate #35: `object::read::xcoff::section::SectionHeader`
            candidate #36: `object::read::xcoff::symbol::Symbol`
            candidate #37: `wasmer_compiler::compiler::Compiler`

error[E0599]: no function or associated item named `load` found for struct `ksl_dep_audit::Package` in the current scope
   --> src\ksl_dep_audit.rs:437:28
    |
15  | pub struct Package {
    | ------------------ function or associated item `load` not found for this struct
...
437 |     let package = Package::load(project)?;
    |                            ^^^^ function or associated item not found in `Package`
    |
note: if you're trying to build a new `ksl_dep_audit::Package`, consider using `ksl_dep_audit::Package::new` which returns `ksl_dep_audit::Package`
   --> src\ksl_dep_audit.rs:23:5
    |
23  |     pub fn new(name: &str, version: SemVer, dependencies: Vec<(String, VersionConstraint)>, license: &str) -> Sel...
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = help: items from traits can only be used if the trait is implemented and in scope
    = note: the following traits define an item `load`, perhaps you need to implement one of them:
            candidate #1: `History`
            candidate #2: `InstBuilder`
            candidate #3: `WasmResults`
            candidate #4: `WasmTy`
            candidate #5: `WasmTyList`
            candidate #6: `cranelift_codegen::gimli::Section`
            candidate #7: `cranelift_codegen::ir::builder::InstBuilder`
            candidate #8: `gimli::read::Section`
            candidate #9: `icu_provider::data_provider::DataProvider`
            candidate #10: `tower::load::Load`
            candidate #11: `wasmtime::component::Lift`

error[E0277]: `?` couldn't convert the error to `KslError`
   --> src\ksl_dep_audit.rs:438:31
    |
438 |     resolver.resolve(&package)?;
    |              -----------------^ the trait `std::convert::From<std::string::String>` is not implemented for `KslError`
    |              |
    |              this can't be annotated with `?` because it has type `Result<_, std::string::String>`
    |
    = note: the question mark operation (`?`) implicitly performs a conversion on the error value using the `From` trait
    = help: the trait `FromResidual<std::result::Result<Infallible, E>>` is implemented for `std::result::Result<T, F>`
    = note: required for `std::result::Result<std::string::String, KslError>` to implement `FromResidual<std::result::Result<Infallible, std::string::String>>`

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
   --> src\ksl_kapra_validator.rs:162:5
    |
162 | /     pub fn new(
163 | |         is_embedded: bool,
164 | |         consensus_runtime: Arc<ConsensusRuntime>,
165 | |         async_runtime: Arc<AsyncRuntime>,
166 | |         contract_compiler: Arc<ContractCompiler>,
167 | |     ) -> Self {
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
               found reference `&Vec<ksl_macros::AstNode>`
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
    | ---------------------- doesn't satisfy `MigrationChange: std::clone::Clone`
...
140 |         Ok(self.changes.clone())
    |                         ^^^^^
    |
    = note: the following trait bounds were not satisfied:
            `MigrationChange: std::clone::Clone`
            which is required by `Vec<MigrationChange>: std::clone::Clone`
help: consider annotating `MigrationChange` with `#[derive(Clone)]`
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
            candidate #1: `Itertools`
            candidate #2: `RangeBounds`
            candidate #3: `bitflags::traits::Flags`
            candidate #4: `clap_lex::ext::OsStrExt`
            candidate #5: `ipnet::ipnet::Contains`
            candidate #6: `itertools::Itertools`
            candidate #7: `option_ext::OptionExt`

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

error[E0599]: no variant or associated item named `new` found for enum `KslError` in the current scope
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
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `ValidationError` found for enum `ErrorType` in the current scope
   --> src\ksl_project.rs:194:49
    |
194 | ...ror::new(ErrorType::ValidationError, "Project name must be non-empty and contain only alphanumeric characte...
    |                        ^^^^^^^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `ValidationError` not found for this enum

error[E0599]: no variant or associated item named `new` found for enum `KslError` in the current scope
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
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `FileError` found for enum `ErrorType` in the current scope
   --> src\ksl_project.rs:200:49
    |
200 |             return Err(KslError::new(ErrorType::FileError, format!("Directory '{}' already exists", name)));
    |                                                 ^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `FileError` not found for this enum

error[E0599]: no variant or associated item named `new` found for enum `KslError` in the current scope
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
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `TemplateError` found for enum `ErrorType` in the current scope
   --> src\ksl_project.rs:205:53
    |
205 | ...rror::new(ErrorType::TemplateError, format!("Template '{}' not found", template_name)))?;
    |                         ^^^^^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `TemplateError` not found for this enum

error[E0599]: no variant or associated item named `new` found for enum `KslError` in the current scope
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
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `FileError` found for enum `ErrorType` in the current scope
   --> src\ksl_project.rs:209:51
    |
209 | ...   .map_err(|e| KslError::new(ErrorType::FileError, format!("Failed to create project directory: {}", e)))?;
    |                                             ^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `FileError` not found for this enum

error[E0599]: no variant or associated item named `new` found for enum `KslError` in the current scope
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
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `FileError` found for enum `ErrorType` in the current scope
   --> src\ksl_project.rs:214:51
    |
214 |             .map_err(|e| KslError::new(ErrorType::FileError, format!("Failed to create src directory: {}", e)))?;
    |                                                   ^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `FileError` not found for this enum

error[E0599]: no method named `save_project_config` found for struct `tokio::sync::MutexGuard<'_, ConfigManager>` in the current scope
   --> src\ksl_project.rs:227:16
    |
227 |         config.save_project_config(&project_config)
    |                ^^^^^^^^^^^^^^^^^^^ method not found in `MutexGuard<'_, ConfigManager>`

error[E0599]: no variant or associated item named `new` found for enum `KslError` in the current scope
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
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `ConfigError` found for enum `ErrorType` in the current scope
   --> src\ksl_project.rs:229:51
    |
229 |             .map_err(|e| KslError::new(ErrorType::ConfigError, e.to_string()))?;
    |                                                   ^^^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `ConfigError` not found for this enum

error[E0599]: no variant or associated item named `new` found for enum `KslError` in the current scope
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
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `FileError` found for enum `ErrorType` in the current scope
   --> src\ksl_project.rs:236:51
    |
236 | ...   .map_err(|e| KslError::new(ErrorType::FileError, format!("Failed to create ksl_package.toml: {}", e)))?;
    |                                             ^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `FileError` not found for this enum

error[E0599]: no variant or associated item named `new` found for enum `KslError` in the current scope
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
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `FileError` found for enum `ErrorType` in the current scope
   --> src\ksl_project.rs:238:51
    |
238 | ...   .map_err(|e| KslError::new(ErrorType::FileError, format!("Failed to write ksl_package.toml: {}", e)))?;
    |                                             ^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `FileError` not found for this enum

error[E0599]: no variant or associated item named `new` found for enum `KslError` in the current scope
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
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `FileError` found for enum `ErrorType` in the current scope
   --> src\ksl_project.rs:243:51
    |
243 |             .map_err(|e| KslError::new(ErrorType::FileError, format!("Failed to create src/main.ksl: {}", e)))?;
    |                                                   ^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `FileError` not found for this enum

error[E0599]: no variant or associated item named `new` found for enum `KslError` in the current scope
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
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `FileError` found for enum `ErrorType` in the current scope
   --> src\ksl_project.rs:245:51
    |
245 |             .map_err(|e| KslError::new(ErrorType::FileError, format!("Failed to write src/main.ksl: {}", e)))?;
    |                                                   ^^^^^^^^^ variant or associated item not found in `ErrorType`
    |
   ::: src\ksl_errors.rs:354:1
    |
354 | pub enum ErrorType {
    | ------------------ variant or associated item `FileError` not found for this enum

error[E0599]: no variant or associated item named `new` found for enum `KslError` in the current scope
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
note: if you're trying to build a new `KslError` consider using one of the following associated functions:
      KslError::parse
      KslError::type_error
      KslError::compile
      KslError::runtime
      KslError::network
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

error[E0599]: no variant or associated item named `AsyncError` found for enum `ErrorType` in the current scope
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

error[E0599]: no variant or associated item named `Rust` found for enum `CompileTarget` in the current scope
   --> src\ksl_transpiler.rs:107:57
    |
107 |                 TranspileTarget::Rust => CompileTarget::Rust,
    |                                                         ^^^^ variant or associated item not found in `CompileTarget`
    |
   ::: src\ksl_compiler.rs:47:1
    |
47  | pub enum CompileTarget {
    | ---------------------- variant or associated item `Rust` not found for this enum

error[E0599]: no variant or associated item named `Python` found for enum `CompileTarget` in the current scope
   --> src\ksl_transpiler.rs:108:59
    |
108 |                 TranspileTarget::Python => CompileTarget::Python,
    |                                                           ^^^^^^ variant or associated item not found in `CompileTarget`
    |
   ::: src\ksl_compiler.rs:47:1
    |
47  | pub enum CompileTarget {
    | ---------------------- variant or associated item `Python` not found for this enum

error[E0599]: no variant or associated item named `JavaScript` found for enum `CompileTarget` in the current scope
   --> src\ksl_transpiler.rs:109:63
    |
109 |                 TranspileTarget::JavaScript => CompileTarget::JavaScript,
    |                                                               ^^^^^^^^^^ variant or associated item not found in `CompileTarget`
    |
   ::: src\ksl_compiler.rs:47:1
    |
47  | pub enum CompileTarget {
    | ---------------------- variant or associated item `JavaScript` not found for this enum

error[E0599]: no variant or associated item named `TypeScript` found for enum `CompileTarget` in the current scope
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
               found reference `&Vec<ksl_macros::AstNode>`
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
114 +         let bytecode = compile(/* &[ksl_ast::AstNode] */, &compile_config, /* CompileTarget */, /* &str */, /* &ksl_analyzer::PerformanceMetrics */, /* bool */, /* std::option::Option<ksl_macros::HotReloadConfig> */)?;
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

error[E0277]: the `?` operator can only be used in a closure that returns `Result` or `Option` (or another type that implements `FromResidual`)
   --> src\ksl_transpiler.rs:155:90
    |
155 |                         .map(|(name, typ)| format!("{}: {}", name, self.type_to_rust(typ)?))
    |                              -------------                                               ^ cannot use the `?` operator in a closure that returns `std::string::String`
    |                              |
    |                              this function should return `Result` or `Option` to accept `?`
    |
    = help: the trait `FromResidual<std::result::Result<Infallible, KslError>>` is not implemented for `std::string::String`

error[E0599]: no method named `transpile_rust_body_async` found for reference `&Transpiler` in the current scope
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
    = help: the trait `Sized` is not implemented for `str`
    = note: all local variables must have a statically known size
    = help: unsized locals are gated as an unstable feature

error[E0277]: the size for values of type `str` cannot be known at compilation time
   --> src\ksl_transpiler.rs:161:78
    |
161 |                     code.push_str(&self.transpile_rust_body_async(body).await?);
    |                                                                              ^ doesn't have a size known at compile-time
    |
    = help: the trait `Sized` is not implemented for `str`
note: required by a bound in `std::ops::ControlFlow::Break`
   --> /rustc/05f9846f893b09a1be1fc8560e33fc3c815cfecb\library\core\src\ops\control_flow.rs:94:5

error[E0277]: the size for values of type `str` cannot be known at compilation time
   --> src\ksl_transpiler.rs:161:36
    |
161 |                     code.push_str(&self.transpile_rust_body_async(body).await?);
    |                                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ doesn't have a size known at compile-time
    |
    = help: the trait `Sized` is not implemented for `str`
note: required by a bound in `std::ops::ControlFlow::Continue`
   --> /rustc/05f9846f893b09a1be1fc8560e33fc3c815cfecb\library\core\src\ops\control_flow.rs:90:5

error[E0277]: the `?` operator can only be used in a closure that returns `Result` or `Option` (or another type that implements `FromResidual`)
   --> src\ksl_transpiler.rs:189:92
    |
189 |                         .map(|(name, typ)| format!("{}: {}", name, self.type_to_python(typ)?))
    |                              -------------                                                 ^ cannot use the `?` operator in a closure that returns `std::string::String`
    |                              |
    |                              this function should return `Result` or `Option` to accept `?`
    |
    = help: the trait `FromResidual<std::result::Result<Infallible, KslError>>` is not implemented for `std::string::String`

error[E0599]: no method named `transpile_python_body_async` found for reference `&Transpiler` in the current scope
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
    = help: the trait `Sized` is not implemented for `str`
    = note: all local variables must have a statically known size
    = help: unsized locals are gated as an unstable feature

error[E0277]: the size for values of type `str` cannot be known at compilation time
   --> src\ksl_transpiler.rs:195:80
    |
195 |                     code.push_str(&self.transpile_python_body_async(body).await?);
    |                                                                                ^ doesn't have a size known at compile-time
    |
    = help: the trait `Sized` is not implemented for `str`
note: required by a bound in `std::ops::ControlFlow::Break`
   --> /rustc/05f9846f893b09a1be1fc8560e33fc3c815cfecb\library\core\src\ops\control_flow.rs:94:5

error[E0277]: the size for values of type `str` cannot be known at compilation time
   --> src\ksl_transpiler.rs:195:36
    |
195 |                     code.push_str(&self.transpile_python_body_async(body).await?);
    |                                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ doesn't have a size known at compile-time
    |
    = help: the trait `Sized` is not implemented for `str`
note: required by a bound in `std::ops::ControlFlow::Continue`
   --> /rustc/05f9846f893b09a1be1fc8560e33fc3c815cfecb\library\core\src\ops\control_flow.rs:90:5

error[E0599]: no method named `transpile_js_body_async` found for reference `&Transpiler` in the current scope
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
    = help: the trait `Sized` is not implemented for `str`
    = note: all local variables must have a statically known size
    = help: unsized locals are gated as an unstable feature

error[E0277]: the size for values of type `str` cannot be known at compilation time
   --> src\ksl_transpiler.rs:227:76
    |
227 |                     code.push_str(&self.transpile_js_body_async(body).await?);
    |                                                                            ^ doesn't have a size known at compile-time
    |
    = help: the trait `Sized` is not implemented for `str`
note: required by a bound in `std::ops::ControlFlow::Break`
   --> /rustc/05f9846f893b09a1be1fc8560e33fc3c815cfecb\library\core\src\ops\control_flow.rs:94:5

error[E0277]: the size for values of type `str` cannot be known at compilation time
   --> src\ksl_transpiler.rs:227:36
    |
227 |                     code.push_str(&self.transpile_js_body_async(body).await?);
    |                                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ doesn't have a size known at compile-time
    |
    = help: the trait `Sized` is not implemented for `str`
note: required by a bound in `std::ops::ControlFlow::Continue`
   --> /rustc/05f9846f893b09a1be1fc8560e33fc3c815cfecb\library\core\src\ops\control_flow.rs:90:5

error[E0277]: the `?` operator can only be used in a closure that returns `Result` or `Option` (or another type that implements `FromResidual`)
   --> src\ksl_transpiler.rs:253:88
    |
253 |                         .map(|(name, typ)| format!("{}: {}", name, self.type_to_ts(typ)?))
    |                              -------------                                             ^ cannot use the `?` operator in a closure that returns `std::string::String`
    |                              |
    |                              this function should return `Result` or `Option` to accept `?`
    |
    = help: the trait `FromResidual<std::result::Result<Infallible, KslError>>` is not implemented for `std::string::String`

error[E0599]: no method named `transpile_ts_body_async` found for reference `&Transpiler` in the current scope
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
    = help: the trait `Sized` is not implemented for `str`
    = note: all local variables must have a statically known size
    = help: unsized locals are gated as an unstable feature

error[E0277]: the size for values of type `str` cannot be known at compilation time
   --> src\ksl_transpiler.rs:259:76
    |
259 |                     code.push_str(&self.transpile_ts_body_async(body).await?);
    |                                                                            ^ doesn't have a size known at compile-time
    |
    = help: the trait `Sized` is not implemented for `str`
note: required by a bound in `std::ops::ControlFlow::Break`
   --> /rustc/05f9846f893b09a1be1fc8560e33fc3c815cfecb\library\core\src\ops\control_flow.rs:94:5

error[E0277]: the size for values of type `str` cannot be known at compilation time
   --> src\ksl_transpiler.rs:259:36
    |
259 |                     code.push_str(&self.transpile_ts_body_async(body).await?);
    |                                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ doesn't have a size known at compile-time
    |
    = help: the trait `Sized` is not implemented for `str`
note: required by a bound in `std::ops::ControlFlow::Continue`
   --> /rustc/05f9846f893b09a1be1fc8560e33fc3c815cfecb\library\core\src\ops\control_flow.rs:90:5

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_testgen.rs:77:26
    |
77  |               .map_err(|e| KslError::type_error(
    |  __________________________^^^^^^^^^^^^^^^^^^^^-
78  | |                 format!("Failed to read file {}: {}", self.config.input_file.display(), e),
79  | |                 pos,
80  | |             ))?;
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
77  -             .map_err(|e| KslError::type_error(
78  -                 format!("Failed to read file {}: {}", self.config.input_file.display(), e),
79  -                 pos,
80  -             ))?;
77  +             .map_err(|e| KslError::type_error(format!("Failed to read file {}: {}", self.config.input_file.display(), e), pos, /* std::string::String */))?;
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_testgen.rs:82:26
    |
82  |               .map_err(|e| KslError::type_error(
    |  __________________________^^^^^^^^^^^^^^^^^^^^-
83  | |                 format!("Parse error at position {}: {}", e.position, e.message),
84  | |                 pos,
85  | |             ))?;
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
82  -             .map_err(|e| KslError::type_error(
83  -                 format!("Parse error at position {}: {}", e.position, e.message),
84  -                 pos,
85  -             ))?;
82  +             .map_err(|e| KslError::type_error(format!("Parse error at position {}: {}", e.position, e.message), pos, /* std::string::String */))?;
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_testgen.rs:89:26
    |
89  |               .map_err(|e| KslError::type_error(
    |  __________________________^^^^^^^^^^^^^^^^^^^^-
90  | |                 format!("Failed to create output directory {}: {}", self.config.output_dir.display(), e),
91  | |                 pos,
92  | |             ))?;
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
89  -             .map_err(|e| KslError::type_error(
90  -                 format!("Failed to create output directory {}: {}", self.config.output_dir.display(), e),
91  -                 pos,
92  -             ))?;
89  +             .map_err(|e| KslError::type_error(format!("Failed to create output directory {}: {}", self.config.output_dir.display(), e), pos, /* std::string::String */))?;
    |

error[E0599]: no method named `get_type_info` found for struct `Arc<ksl_types::TypeSystem>` in the current scope
   --> src\ksl_testgen.rs:126:43
    |
126 |         let type_info = state.type_system.get_type_info(return_type)
    |                                           ^^^^^^^^^^^^^
    |
help: there is a method `type_id` with a similar name, but with different arguments
   --> /rustc/05f9846f893b09a1be1fc8560e33fc3c815cfecb\library\core\src\any.rs:134:5

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_testgen.rs:127:26
    |
127 |             .map_err(|e| KslError::type_error(format!("Type error: {}", e), pos))?;
    |                          ^^^^^^^^^^^^^^^^^^^^----------------------------------- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
127 -             .map_err(|e| KslError::type_error(format!("Type error: {}", e), pos))?;
127 +             .map_err(|e| KslError::type_error(format!("Type error: {}", e), pos, /* std::string::String */))?;
    |

error[E0599]: no method named `generate_edge_case_test` found for reference `&TestGen` in the current scope
   --> src\ksl_testgen.rs:131:34
    |
131 |         test_suite.add_test(self.generate_edge_case_test(name, params, return_type, is_async)?);
    |                                  ^^^^^^^^^^^^^^^^^^^^^^^
    |
help: there is a method `generate_async_test` with a similar name, but with different arguments
   --> src\ksl_testgen.rs:204:5
    |
204 | /     fn generate_async_test(
205 | |         &self,
206 | |         name: &str,
207 | |         params: &[(String, Type)],
208 | |         return_type: &Type,
209 | |     ) -> Result<TestCase, KslError> {
    | |___________________________________^

error[E0599]: no method named `generate_property_test` found for reference `&TestGen` in the current scope
   --> src\ksl_testgen.rs:132:34
    |
132 |         test_suite.add_test(self.generate_property_test(name, params, return_type, is_async)?);
    |                                  ^^^^^^^^^^^^^^^^^^^^^^
    |
help: there is a method `generate_async_test` with a similar name, but with different arguments
   --> src\ksl_testgen.rs:204:5
    |
204 | /     fn generate_async_test(
205 | |         &self,
206 | |         name: &str,
207 | |         params: &[(String, Type)],
208 | |         return_type: &Type,
209 | |     ) -> Result<TestCase, KslError> {
    | |___________________________________^

error[E0599]: no method named `generate_numeric_test` found for reference `&TestGen` in the current scope
   --> src\ksl_testgen.rs:143:42
    |
143 |                 test_suite.add_test(self.generate_numeric_test(name, params, return_type)?);
    |                                          ^^^^^^^^^^^^^^^^^^^^^
    |
help: there is a method `generate_basic_test` with a similar name, but with different arguments
   --> src\ksl_testgen.rs:162:5
    |
162 | /     fn generate_basic_test(
163 | |         &self,
164 | |         name: &str,
165 | |         params: &[(String, Type)],
166 | |         return_type: &Type,
167 | |         is_async: bool,
168 | |     ) -> Result<TestCase, KslError> {
    | |___________________________________^

error[E0599]: no method named `generate_array_test` found for reference `&TestGen` in the current scope
   --> src\ksl_testgen.rs:146:42
    |
146 |                 test_suite.add_test(self.generate_array_test(name, params, return_type)?);
    |                                          ^^^^^^^^^^^^^^^^^^^
    |
help: there is a method `generate_async_test` with a similar name
    |
146 -                 test_suite.add_test(self.generate_array_test(name, params, return_type)?);
146 +                 test_suite.add_test(self.generate_async_test(name, params, return_type)?);
    |

error[E0599]: no method named `generate_error_test` found for reference `&TestGen` in the current scope
   --> src\ksl_testgen.rs:149:42
    |
149 |                 test_suite.add_test(self.generate_error_test(name, params, return_type)?);
    |                                          ^^^^^^^^^^^^^^^^^^^
    |
help: there is a method `generate_async_test` with a similar name
    |
149 -                 test_suite.add_test(self.generate_error_test(name, params, return_type)?);
149 +                 test_suite.add_test(self.generate_async_test(name, params, return_type)?);
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_testgen.rs:296:26
    |
296 |               .map_err(|e| KslError::type_error(
    |  __________________________^^^^^^^^^^^^^^^^^^^^-
297 | |                 format!("Failed to write test file {}: {}", output_path.display(), e),
298 | |                 pos,
299 | |             ))?;
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
296 -             .map_err(|e| KslError::type_error(
297 -                 format!("Failed to write test file {}: {}", output_path.display(), e),
298 -                 pos,
299 -             ))?;
296 +             .map_err(|e| KslError::type_error(format!("Failed to write test file {}: {}", output_path.display(), e), pos, /* std::string::String */))?;
    |

error[E0599]: no function or associated item named `new_with_profiling` found for struct `kapra_vm::KapraVM` in the current scope
   --> src\ksl_profile.rs:261:31
    |
261 |         let mut vm = KapraVM::new_with_profiling(self.bytecode.clone());
    |                               ^^^^^^^^^^^^^^^^^^ function or associated item not found in `KapraVM`
    |
   ::: src\kapra_vm.rs:120:1
    |
120 | pub struct KapraVM {
    | ------------------ function or associated item `new_with_profiling` not found for this struct
    |
help: there is an associated function `new_with_async` with a similar name
    |
261 -         let mut vm = KapraVM::new_with_profiling(self.bytecode.clone());
261 +         let mut vm = KapraVM::new_with_async(self.bytecode.clone());
    |

error[E0599]: no method named `clone` found for struct `KapraBytecode` in the current scope
   --> src\ksl_profile.rs:261:64
    |
261 |         let mut vm = KapraVM::new_with_profiling(self.bytecode.clone());
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

error[E0599]: no method named `get_metrics` found for struct `Arc<MetricsCollector>` in the current scope
   --> src\ksl_profile.rs:268:46
    |
268 |         let metrics = self.metrics_collector.get_metrics();
    |                                              ^^^^^^^^^^^
    |
help: there is a method `get_async_metrics` with a similar name
    |
268 -         let metrics = self.metrics_collector.get_metrics();
268 +         let metrics = self.metrics_collector.get_async_metrics();
    |

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_profile.rs:315:26
    |
315 |               .map_err(|e| KslError::type_error(
    |  __________________________^^^^^^^^^^^^^^^^^^^^-
316 | |                 format!("Parse error at position {}: {}", e.position, e.message),
317 | |                 pos,
318 | |             ))?;
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
315 -             .map_err(|e| KslError::type_error(
316 -                 format!("Parse error at position {}: {}", e.position, e.message),
317 -                 pos,
318 -             ))?;
315 +             .map_err(|e| KslError::type_error(format!("Parse error at position {}: {}", e.position, e.message), pos, /* std::string::String */))?;
    |

error[E0599]: no method named `run_async` found for mutable reference `&mut kapra_vm::KapraVM` in the current scope
   --> src\ksl_profile.rs:324:12
    |
324 |         vm.run_async().await
    |            ^^^^^^^^^
    |
help: there is a method `run_with_async` with a similar name, but with different arguments
   --> src\kapra_vm.rs:775:5
    |
775 |     pub async fn run_with_async(&mut self, runtime: &AsyncRuntime) -> Result<(), RuntimeError> {
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

error[E0061]: this function takes 3 arguments but 2 arguments were supplied
   --> src\ksl_profile.rs:325:26
    |
325 |               .map_err(|e| KslError::type_error(
    |  __________________________^^^^^^^^^^^^^^^^^^^^-
326 | |                 format!("Execution error: {}", e),
327 | |                 pos,
328 | |             ))?;
    | |_____________- argument #3 of type `std::string::String` is missing
    |
note: associated function defined here
   --> src\ksl_errors.rs:109:12
    |
109 |     pub fn type_error(message: String, position: SourcePosition, code: String) -> Self {
    |            ^^^^^^^^^^                                            ------------
help: provide the argument
    |
325 -             .map_err(|e| KslError::type_error(
326 -                 format!("Execution error: {}", e),
327 -                 pos,
328 -             ))?;
325 +             .map_err(|e| KslError::type_error(format!("Execution error: {}", e), pos, /* std::string::String */))?;
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

error[E0599]: no method named `run_sandbox_async` found for struct `Sandbox` in the current scope
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

error[E0599]: no method named `map_err` found for opaque type `impl futures::Future<Output = std::result::Result<(), Vec<KslError>>>` in the current scope
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
    |          ------- the method is available for `impl futures::Future<Output = std::result::Result<(), Vec<KslError>>>` here
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
   --> src\kapra_vm.rs:598:32
    |
598 |                       delegatee: FixedArray(delegatee),
    |                                  ^^^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
    |
   ::: src\ksl_kapra_crypto.rs:44:1
    |
44  | / pub struct FixedArray<const N: usize> {
45  | |     data: [u8; N],
46  | | }
    | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
   --> src\kapra_vm.rs:625:52
    |
625 |                   let result = self.execute_contract(FixedArray(target));
    |                                                      ^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
    |
   ::: src\ksl_kapra_crypto.rs:44:1
    |
44  | / pub struct FixedArray<const N: usize> {
45  | |     data: [u8; N],
46  | | }
    | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:1204:27
     |
1204 |           let contract_id = FixedArray(hasher.finalize().into());
     |                             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ help: use struct literal syntax instead: `FixedArray { data: val }`
     |
    ::: src\ksl_kapra_crypto.rs:44:1
     |
44   | / pub struct FixedArray<const N: usize> {
45   | |     data: [u8; N],
46   | | }
     | |_- `FixedArray` defined here

error[E0423]: expected function, tuple struct or tuple variant, found struct `FixedArray`
    --> src\kapra_vm.rs:1362:9
     |
1362 |           FixedArray(hasher.finalize().into())
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
   --> src\ksl_profile.rs:239:24
    |
239 |         let line_map = build_line_map(&ast, &bytecode);
    |                        ^^^^^^^^^^^^^^ not found in this scope

Some errors have detailed explanations: E0026, E0034, E0061, E0063, E0106, E0119, E0191, E0252, E0255...
For more information about an error, try `rustc --explain E0026`.
warning: `KSL` (lib) generated 607 warnings
error: could not compile `KSL` (lib) due to 1543 previous errors; 607 warnings emitted
PS C:\rn\ksl>