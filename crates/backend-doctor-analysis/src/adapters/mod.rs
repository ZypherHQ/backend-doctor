mod c;
mod common;
mod cpp;
mod csharp;
mod elixir;
mod go;
mod java;
mod kotlin;
mod node;
mod php;
mod python;
mod ruby;
mod rust;
mod scala;

pub use c::CAdapter;
pub use cpp::CppAdapter;
pub use csharp::CSharpAdapter;
pub use elixir::ElixirAdapter;
pub use go::GoAdapter;
pub use java::JavaAdapter;
pub use kotlin::KotlinAdapter;
pub use node::NodeTypeScriptAdapter;
pub use php::PhpAdapter;
pub use python::PythonAdapter;
pub use ruby::RubyAdapter;
pub use rust::RustAdapter;
pub use scala::ScalaAdapter;

use crate::ParserRegistry;

pub fn register_default_adapters(registry: &mut ParserRegistry) {
    registry.register(CAdapter);
    registry.register(CppAdapter);
    registry.register(GoAdapter);
    registry.register(NodeTypeScriptAdapter);
    registry.register(JavaAdapter);
    registry.register(PythonAdapter);
    registry.register(CSharpAdapter);
    registry.register(PhpAdapter);
    registry.register(RustAdapter);
    registry.register(RubyAdapter);
    registry.register(ElixirAdapter);
    registry.register(KotlinAdapter);
    registry.register(ScalaAdapter);
}

pub fn register_tier_a_adapters(registry: &mut ParserRegistry) {
    register_default_adapters(registry);
}
