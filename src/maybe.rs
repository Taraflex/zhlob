pub type UnifiedError = Box<dyn std::error::Error + Send + Sync>;

#[macro_export]
macro_rules! maybe {
    ($($tt:tt)*) => {
        (|| -> Result<_, crate::maybe::UnifiedError> {
            Ok({ $($tt)* })
        })().ok()
    };
}
