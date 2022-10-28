use wasm_bindgen::{JsValue, JsCast};
use web_sys::{Window, WorkerGlobalScope, IdbFactory};

pub enum Global {
    Window(Window),
    WorkerGlobalScope(WorkerGlobalScope),
}

impl Global {
    pub fn indexed_db(&self) -> Result<Option<IdbFactory>, JsValue> {
        match self {
            Global::Window(window) => window.indexed_db(),
            Global::WorkerGlobalScope(scope) => scope.indexed_db(),
        }   
    }
}

pub fn self_() -> Result<Global, JsValue> {
    let global = js_sys::global();
    // how to properly detect this in wasm_bindgen?
    if js_sys::eval("typeof WorkerGlobalScope !== 'undefined'")?.as_bool().unwrap() {
        Ok(global.dyn_into::<WorkerGlobalScope>().map(Global::WorkerGlobalScope)?)
    }
    else {
        Ok(global.dyn_into::<Window>().map(Global::Window)?)
    }
}