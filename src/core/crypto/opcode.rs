use std::fmt::Display;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum OpCode {
    Register,
    RegSuccess,
    Cycle,
    CycleOk,
    Stamp,
    Stamped,
}



impl OpCode {
    pub fn to_code(&self) -> u8 {
        match self {
            Self::Register => 0,
            Self::RegSuccess => 1,
            Self::Cycle => 2,
            Self::CycleOk => 3,
            Self::Stamp => 4,
            Self::Stamped => 5,
        }
    }
    pub fn to_static_str(&self) -> &'static str {
        match self {
            OpCode::Register => "Register",
            OpCode::RegSuccess => "RegSuccess",
            OpCode::Cycle => "Cycle",
            OpCode::CycleOk => "CycleOk",
            OpCode::Stamp => "Stamp",
            OpCode::Stamped => "Stamped",
        }
    }
}

impl TryFrom<u8> for OpCode {
    type Error = OpcodeParseError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => Self::Register,
            1 => Self::RegSuccess,
            2 => Self::Cycle,
            3 => Self::CycleOk,
            4 => Self::Stamp,
            5 => Self::Stamped,
            x => Err(OpcodeParseError::OutOfRange(x))?
        })
    }
}

impl Display for OpCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_static_str().fmt(f)
    }
}

impl TryFrom<&str> for OpCode {
    type Error = OpcodeParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match &*s.to_lowercase() {
            "register" => Ok(OpCode::Register),
            "regsuccess" => Ok(OpCode::RegSuccess),
            "cycle" => Ok(OpCode::Cycle),
            "cycleok" => Ok(OpCode::CycleOk),
            "stamp" => Ok(OpCode::Stamp),
            "stamped" => Ok(OpCode::Stamped),
            _ => Err(OpcodeParseError::UnrecognizedLiteral),
        }
    }
}


#[derive(thiserror::Error, Debug)]
pub enum OpcodeParseError {
    #[error("Failed to decode the opcode as an integer.")]
    OutOfRange(u8),
    #[error("Failed to parse the opcode from a string.")]
    UnrecognizedLiteral

}