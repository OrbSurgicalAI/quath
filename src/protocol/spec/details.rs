use core::ops::Range;

/// Represents an error to do with protocols or the protocol
/// registries.
#[derive(Debug, PartialEq)]
pub enum ProtocolError {
    /// An access or register was attempted outside of the
    /// protocol band space. For instance if a protocol band 
    OutOfProtocolSpace,
    /// There is already a protocol registered with this code.
    ExistingProtocolWithCode,
    /// There is already a protocol registered with this name.
    ExistingProtocolWithName,
    /// Attempted to reserve a protocol band that overlaps with
    /// the reserved area.
    IllegalStartAddress
}

/// This specifies a protocol to be used with the
/// quantum authentication library. The first 32 codes
/// are reserved protocol codes and the rest can be
/// registered with custom protocols.
///
/// Comparison works by comparing codes. No two protocols with different
/// names should have the same code.
/// 
/// Protocols are best thought of as bands where the total reservable space is
/// 255 protocols. We have 32 protocols reserved for a special case.
/// 
/// To register and work with custom protocols, you need to use a [ProtocolRegistry] object.
#[derive(Debug, Clone, Copy)]
pub struct Protocol {
    /// The protocol name.
    name: &'static str,
    /// The protocol code, this is what is actually encoded into
    /// the token.
    code: u8,
}



impl PartialEq<Protocol> for Protocol {
    fn eq(&self, other: &Protocol) -> bool {
        self.code == other.code
    }
}

impl Protocol {
    // Standard protocols.

    /// The DIL2A protocol.
    pub const DIL2A: Protocol = DIL2A_PROTOCOL;
    pub const DIL2B: Protocol = DIL2B_PROTOCOL;
    pub const DUMMY: Protocol = DUMMY_PROTOCOL;

    /// Gets a protocol by name by searching reserve table.
    /// 
    /// This is a linear search and thus is relatively slow
    /// and should be avoided as a lookup method.
    pub fn try_from_str(source: &str) -> Option<Self> {
        RESERVED_PROTOCOLS.search_str(source)
    }
    /// Gets a protocol by name by first searching the reserve table and then
    /// searching the registry table.
    /// 
    /// This is a linear search and thus is relatively slow
    /// and should be avoided as a lookup method.
    pub fn try_from_str_with_registry<const N: usize>(source: &str, registry: &ProtocolRegistry<N>) -> Option<Self>
    {
        RESERVED_PROTOCOLS.search_str(source).or(registry.search_str(source))
    }
    /// Gets a protocol by code by searching the reserve table.
    /// 
    /// This is a constant time operation and at worst results in one array lookup.
    pub fn try_from_code(code: u8) -> Option<Self> {
        RESERVED_PROTOCOLS.search_code(code)
    }
    /// Gets a protocol by code by first searching the reserve table and then
    /// searching the registry table.
    /// 
    /// This is a constant time operation and at worst results in two array lookups.
    pub fn try_from_code_with_registry<const N: usize>(code: u8, registry: &ProtocolRegistry<N>) -> Option<Self> {
        RESERVED_PROTOCOLS.search_code(code).or(registry.search_code(code))
    }
    


    pub fn name(&self) -> &'static str {
        self.name
    }

    pub fn code(&self) -> u8 {
        self.code
    }
}

pub const RESERVED_PROTOCOL_RANGE: Range<usize> = 0..32;
pub const RESERVED_PROTOCOLS: ProtocolRegistry<3> = ProtocolRegistry {
    table: [
        Some(DIL2A_PROTOCOL),
        Some(DIL2B_PROTOCOL),
        Some(DUMMY_PROTOCOL),
    ],
    start_point: 0,
};

const DIL2A_PROTOCOL: Protocol = Protocol {
    name: "DIL2A",
    code: 0,
};

const DIL2B_PROTOCOL: Protocol = Protocol {
    name: "DIL2B",
    code: 1,
};

const DUMMY_PROTOCOL: Protocol = Protocol {
    name: "DUMMY",
    code: 2,
};

/// Allows for the implementation of custom protocols.
///
/// This represents a protocol band from the starting point
/// to the size (N). Protocols can only be registered within this
/// band.
///
/// A concrete example is if we have a protocol table that starts at the
/// address 32 and has a size of 16. This can reserve protocols 32,.., 47 (inclusive!)
///
/// Registering a new protocol will recompile the hashmap.
#[derive(Debug)]
pub struct ProtocolRegistry<const N: usize> {
    /// The table of protocol slots.
    table: [Option<Protocol>; N],
    /// The start of the protocol band. The size of the protocol band can be
    /// found by checking the length of the table.
    start_point: usize,
}

impl<const N: usize> ProtocolRegistry<N> {
    /// Creates a new protocol registry on the stack with constant
    /// size. This is to make sure that people are reserving certain
    /// ranges of protocol codes.
    pub fn new(start_code: u8) -> Result<Self, ProtocolError> {
        if RESERVED_PROTOCOL_RANGE.contains(&(start_code as usize)) {
            return Err(ProtocolError::IllegalStartAddress);
        }
        Ok(Self {
            table: [None; N],
            start_point: start_code as usize
        })
    }

    /// Checks if a code is within range.
    fn in_code_range(&self, code: u8) -> bool {
        (self.start_point..self.start_point + self.table.len()).contains(&(code as usize))
    }
    /// Registers a new [Protocol] within this registry object.
    /// 
    /// You request a specific code and this method will either not error
    /// and slot the code in properly or error should this request be an invalid one.
    pub fn register(&mut self, code: u8, name: &'static str) -> Result<Protocol, ProtocolError> {
        if !self.in_code_range(code) {
            // Verify the code is in range.
            return Err(ProtocolError::OutOfProtocolSpace);
        } else if self.table[code as usize - self.start_point].is_some() {
            // Checks if this protocol slot is empty.
            return Err(ProtocolError::ExistingProtocolWithCode);
        } else if RESERVED_PROTOCOLS.search_str(name).is_some() {
            // Checks if the protocol name is in the reserved table.
            return Err(ProtocolError::ExistingProtocolWithName);
        } else if self.search_str(name).is_some() {
            // Checks if the protocol name is in this registry.
            return Err(ProtocolError::ExistingProtocolWithName);
        }
        let protocol = Protocol { name, code };
        self.table[code as usize - self.start_point] = Some(protocol);
        Ok(protocol)
    }
    /// Searches for a string within the protocol table.
    /// 
    /// This is slower as the search will iterate over all
    /// the entries. Code lookups should ALWAYS be preferred.
    /// 
    /// This will not check if the code is in the reserved
    /// set of proocols and thus should not be used for 
    /// protocol code lookups.
    /// 
    /// This behaviour is exposed through the [Protocol] API.
    fn search_str(&self, name: &str) -> Option<Protocol> {
        search_table_for_string(name, self.table.iter().filter(|o| o.is_some()).map(|o| o.unwrap()))
    }
    /// Searches for a code within the protocol table.
    /// 
    /// This will not check if the code is in the reserved
    /// set of proocols and thus should not be used for 
    /// protocol code lookups.
    /// 
    /// This behaviour is exposed through the [Protocol] API.
    fn search_code(&self, code: u8) -> Option<Protocol> {
        if self.in_code_range(code) {
            self.table[code as usize - self.start_point]
        } else {
            None
        }
    }
}



/// Searches the table for a protocol with a certain name.
///
/// This is not particularly efficient and these types of lookups
/// should generally be minimized.
fn search_table_for_string<I>(source: &str, mut table: I) -> Option<Protocol>
where
    I: Iterator<Item = Protocol>,
{
    table.find(|protocol| protocol.name.eq_ignore_ascii_case(source))
}

#[cfg(test)]
mod tests {
    use crate::protocol::spec::details::{Protocol, ProtocolError, ProtocolRegistry, RESERVED_PROTOCOLS, RESERVED_PROTOCOL_RANGE};

    #[test]
    pub fn try_protocol_str_parse_reserved() {
        // Try a couple.
        assert_eq!(Protocol::try_from_str("DUMMY"), Some(Protocol::DUMMY));
        assert_eq!(Protocol::try_from_str("DumMy"), Some(Protocol::DUMMY));
        assert_eq!(Protocol::try_from_str("Obviously not real..."), None);

        // Verify reserved protocols are picked up.
        for p in &RESERVED_PROTOCOLS.table[..RESERVED_PROTOCOLS.table.len()] {
            assert_eq!(Protocol::try_from_str(p.unwrap().name()), *p);
        }

        
    }


    #[test]
    pub fn try_protocol_registry_illegal_address() {
        assert_eq!(ProtocolRegistry::<2>::new(0).unwrap_err(), ProtocolError::IllegalStartAddress);
        assert_eq!(ProtocolRegistry::<2>::new((RESERVED_PROTOCOL_RANGE.end - 1) as u8).unwrap_err(), ProtocolError::IllegalStartAddress);
    }

    #[test]
    pub fn try_protocol_str_parse_with_registry() {

        let mut registry = ProtocolRegistry::<2>::new(RESERVED_PROTOCOL_RANGE.end as u8).expect("Could not make a valid registry.");

        // Check reserved address.
        assert_eq!(Protocol::try_from_str_with_registry("DUMMY", &registry), Some(Protocol::DUMMY));
        assert_eq!(Protocol::try_from_str_with_registry("Dummy", &registry), Some(Protocol::DUMMY));
        assert_eq!(Protocol::try_from_str_with_registry("dummy", &registry), Some(Protocol::DUMMY));
        assert_eq!(Protocol::try_from_str_with_registry("not real", &registry), None);

        assert_eq!(registry.register(3, "not real"), Err(ProtocolError::OutOfProtocolSpace));
        registry.register(RESERVED_PROTOCOL_RANGE.end as u8, "not real").unwrap();

        assert_eq!(Protocol::try_from_str("not real"), None);
        assert_eq!(Protocol::try_from_str_with_registry("not real", &registry).unwrap().name(), "not real");
    }

    #[test]
    pub fn try_protocol_code_parse_with_registry() {

        let mut registry = ProtocolRegistry::<2>::new(RESERVED_PROTOCOL_RANGE.end as u8).expect("Could not make a valid registry.");

        // Check reserved address.
        assert_eq!(Protocol::try_from_code_with_registry(0, &registry), Some(Protocol::DIL2A));
        assert_eq!(Protocol::try_from_code_with_registry(16, &registry), None);

        registry.register(RESERVED_PROTOCOL_RANGE.end as u8, "not real").unwrap();
        assert_eq!(Protocol::try_from_code_with_registry(RESERVED_PROTOCOL_RANGE.end as u8, &registry).unwrap().name(), "not real");
    }
    

    #[test]
    pub fn try_protocol_code_parse_reserved() {
        assert_eq!(RESERVED_PROTOCOLS.search_code(0).unwrap(), Protocol::DIL2A);
        assert_eq!(RESERVED_PROTOCOLS.search_code(1).unwrap(), Protocol::DIL2B);
        assert_eq!(RESERVED_PROTOCOLS.search_code(2).unwrap(), Protocol::DUMMY);
        assert_eq!(RESERVED_PROTOCOLS.search_code(3), None);
    }


}
