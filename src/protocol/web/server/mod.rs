use std::borrow::Borrow;

pub mod cycle;
pub mod token;
pub mod verdict;

pub(crate) fn format_verdict<B>(name: &str, message: B) -> String
where 
    B: AsRef<str>
{
    format!("{name}: {}", message.as_ref())
}