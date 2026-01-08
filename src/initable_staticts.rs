#[macro_export]
macro_rules! initable_static {
    // --- Ветка 1: LazyLock (name: Type = || { body }) ---
    (
        $name:ident : $ty:ty = || $body:block ;
        $($rest:tt)*
    ) => {
        pub static $name: std::sync::LazyLock<$ty> = std::sync::LazyLock::new(|| $body);
        initable_static! { $($rest)* }
    };
    // Финальный элемент LazyLock (без точки с запятой или с ней)
    (
        $name:ident : $ty:ty = || $body:block $(;)?
    ) => {
        pub static $name: std::sync::LazyLock<$ty> = std::sync::LazyLock::new(|| $body);
    };

    // --- Ветка 2: Initable (name = |args| -> Result { body }) ---
    (
        $name:ident = |$($arg:ident : $arg_ty:ty),*| -> Result<$ret_ty:ty, $err_ty:ty> $body:block ;
        $($rest:tt)*
    ) => {
        initable_static! { @render $name, |$($arg : $arg_ty),*| -> Result<$ret_ty, $err_ty> $body }
        initable_static! { $($rest)* }
    };
    // Финальный элемент Initable
    (
        $name:ident = |$($arg:ident : $arg_ty:ty),*| -> Result<$ret_ty:ty, $err_ty:ty> $body:block $(;)?
    ) => {
        initable_static! { @render $name, |$($arg : $arg_ty),*| -> Result<$ret_ty, $err_ty> $body }
    };

    // --- Вспомогательный рендер логики OnceLock + Mutex ---
    (@render $name:ident, |$($arg:ident : $arg_ty:ty),*| -> Result<$ret_ty:ty, $err_ty:ty> $body:block) => {
        static $name: std::sync::OnceLock<$ret_ty> = std::sync::OnceLock::new();

        #[allow(non_snake_case)]
        pub mod $name {
            use super::*;
            pub fn init($($arg : $arg_ty),*) -> Result<&'static $ret_ty, $err_ty> {
                static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

                if let Some(val) = super::$name.get() { return Ok(val); }

                let _guard = LOCK.lock().unwrap();

                if let Some(val) = super::$name.get() { return Ok(val); }

                let result = (|$($arg : $arg_ty),*| -> Result<$ret_ty, $err_ty> { $body })($($arg),*)?;

                let _ = super::$name.set(result);
                Ok(super::$name.get().expect("Initialized"))
            }

            #[inline]
            #[allow(dead_code)]
            pub fn get() -> &'static $ret_ty {
                super::$name.get().expect(concat!(stringify!($name), " is not initialized"))
            }
        }
    };

    // Терминатор
    () => {};
}
