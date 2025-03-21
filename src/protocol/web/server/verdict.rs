use http::StatusCode;
use serde::Serialize;


pub enum Verdict<O> {
    Result {
        obj: O,
        code: StatusCode
    },
    Custom {
        name: String,
        code: StatusCode,
        response: String
    }
}

#[derive(Serialize)]
struct CustomVerdictPayload<'a> {
    code: &'a str,
    message: &'a str
}

fn format_verdict<B, O>(name: &str, code: StatusCode,  message: B) -> Verdict<O>
where 
    B: AsRef<str>
{
    Verdict::Custom { name: name.to_string(), code, response: message.as_ref().to_string() }
}

impl<O> Verdict<O> {
    pub fn custom<B>(name: &str, code: StatusCode, message: B) -> Self
    where 
        B: AsRef<str>
    {
        format_verdict(name, code, message)
    }
    pub fn code(&self) -> StatusCode {
        match self {
            Self::Result { code, .. } => *code,
            Self::Custom { code, .. } => *code
        }
    }
}

impl<O> Verdict<O>
where 
    O: Serialize
{
    
    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        match self {
            Self::Custom { name, code:_, response } => serde_json::to_string(&CustomVerdictPayload {
                code: &name,
                message: &response
            }),
            Self::Result { obj, .. } => serde_json::to_string(obj)
        }
    }
}