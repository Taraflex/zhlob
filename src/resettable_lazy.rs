use std::cell::RefCell;

pub struct ResettableLazy<'a, T> {
    // Box<dyn...> стирает тип конкретного замыкания
    init: Box<dyn Fn() -> T + 'a>,
    // RefCell позволяет обновлять кэш через &self
    value: RefCell<Option<T>>,
}

impl<'a, T: Clone> ResettableLazy<'a, T> {
    pub fn new<F>(init: F) -> Self
    where
        F: Fn() -> T + 'a,
    {
        Self {
            init: Box::new(init),
            value: RefCell::new(None),
        }
    }

    /// Получает значение. Если кэш пуст — вычисляет.
    /// Работает через &self (неизменяемую ссылку).
    pub fn get(&self) -> T {
        if let Some(ref val) = *self.value.borrow() {
            return val.clone();
        }
        let val = (self.init)();
        *self.value.borrow_mut() = Some(val.clone());
        val
    }

    /// Сбрасывает кэш. Последующий вызов get() приведет к перевычислению.
    pub fn reset(&self) {
        *self.value.borrow_mut() = None;
    }
}
