# Language-boundary edges

| Mechanism | What to look for | Record |
| --- | --- | --- |
| Subprocess | `subprocess.*`, `os.system`, `child_process.spawn/exec`, `exec.Command`, `ProcessBuilder`, `std::process::Command`, backticks in Ruby/Perl | binary or script path (and the env var that sets it), args, stdin/stdout format, which repo builds the binary (search Dockerfiles and build files for the output name) |
| FFI / native | `ctypes`, `cffi`, `cgo` (`import "C"`), `extern "C"`, JNI, N-API/node-gyp, PyO3, pybind11, `#[no_mangle]` | library name, exported symbols, which side owns memory |
| Generated clients | `DO NOT EDIT`, `openapi-generator`, `protoc-gen-*`, `*_pb2.py`, `*.pb.go`, `*_grpc.pb.go`, GraphQL codegen | generator, contract file it came from, client methods used |
| Embedded runtimes | Lua/JS engines, WASM (`wasmtime`, `wasm_bindgen`), templating DSLs | host↔guest interface |
| IPC | Unix sockets, named pipes, shared memory, gRPC over localhost, stdin/stdout JSON | endpoint/path, protocol |
| Shared libs across repos | internal packages imported by several services (`@acme/*`, `github.com/acme/common`) | package name, version per consumer, contract it encodes |

Each edge gets a confidence: high when both sides are cited, medium when one side is inferred from a name or a build output, low when it's only a naming match.
