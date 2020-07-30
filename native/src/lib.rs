use neon::prelude::*;

mod party_i;

struct BackgroundTask;
impl Task for BackgroundTask {
    type Output = i32;
    type Error = String;
    type JsEvent = JsNumber;
    fn perform(&self) -> Result<Self::Output, Self::Error> {
        Ok(17)
    }
    fn complete(
        self,
        mut cx: TaskContext,
        result: Result<Self::Output, Self::Error>,
    ) -> JsResult<Self::JsEvent> {
        Ok(cx.number(result.unwrap()))
    }
}

pub fn perform_async_task(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let f = cx.argument::<JsFunction>(0)?;
    BackgroundTask.schedule(f);
    Ok(cx.undefined())
}

register_module!(mut cx, {
    cx.export_function("initKeygen", party_i::keygen::init_keygen)?;
    cx.export_function("getPubkey", party_i::hd_keys::get_pubkey)?;
    cx.export_function("asyncTask", perform_async_task)?;
    cx.export_function("signMessage", party_i::sign::sign_message_task)
});
