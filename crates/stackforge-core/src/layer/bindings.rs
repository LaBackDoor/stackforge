//! Layer binding system for automatic field setting when stacking layers.
//!
//! For example, when stacking `Ether() / ARP()`, the Ethernet type field
//! should automatically be set to 0x0806 (ARP).

use crate::layer::{LayerKind, ethertype, ip_protocol};

/// Describes a binding between two layers.
///
/// When the upper layer is placed on top of the lower layer,
/// the specified field of the lower layer should be set to the given value.
#[derive(Debug, Clone, Copy)]
pub struct LayerBinding {
    /// The layer being placed on top
    pub upper: LayerKind,
    /// The layer below
    pub lower: LayerKind,
    /// The field name in the lower layer to set
    pub field_name: &'static str,
    /// The value to set (as u16 for simplicity; can be cast)
    pub field_value: u16,
}

impl LayerBinding {
    pub const fn new(
        lower: LayerKind,
        upper: LayerKind,
        field_name: &'static str,
        field_value: u16,
    ) -> Self {
        Self {
            upper,
            lower,
            field_name,
            field_value,
        }
    }
}

/// Static table of layer bindings.
///
/// Format: (lower_layer, upper_layer, field_name, field_value)
pub static LAYER_BINDINGS: &[LayerBinding] = &[
    // Ethernet -> *
    LayerBinding::new(LayerKind::Ethernet, LayerKind::Arp, "type", ethertype::ARP),
    LayerBinding::new(
        LayerKind::Ethernet,
        LayerKind::Ipv4,
        "type",
        ethertype::IPV4,
    ),
    LayerBinding::new(
        LayerKind::Ethernet,
        LayerKind::Ipv6,
        "type",
        ethertype::IPV6,
    ),
    LayerBinding::new(
        LayerKind::Ethernet,
        LayerKind::Dot1Q,
        "type",
        ethertype::VLAN,
    ),
    LayerBinding::new(
        LayerKind::Ethernet,
        LayerKind::Dot1AD,
        "type",
        ethertype::DOT1AD,
    ),
    LayerBinding::new(
        LayerKind::Ethernet,
        LayerKind::Dot1AH,
        "type",
        ethertype::DOT1AH,
    ),
    LayerBinding::new(LayerKind::Ethernet, LayerKind::LLC, "type", 122), // LLC over Ethernet
    // Dot3 -> LLC
    LayerBinding::new(LayerKind::Dot3, LayerKind::LLC, "len", 0), // Auto-calculated
    // Dot1Q -> *
    LayerBinding::new(LayerKind::Dot1Q, LayerKind::Arp, "type", ethertype::ARP),
    LayerBinding::new(LayerKind::Dot1Q, LayerKind::Ipv4, "type", ethertype::IPV4),
    LayerBinding::new(LayerKind::Dot1Q, LayerKind::Ipv6, "type", ethertype::IPV6),
    LayerBinding::new(LayerKind::Dot1Q, LayerKind::Dot1Q, "type", ethertype::VLAN),
    LayerBinding::new(
        LayerKind::Dot1Q,
        LayerKind::Dot1AD,
        "type",
        ethertype::DOT1AD,
    ),
    LayerBinding::new(
        LayerKind::Dot1Q,
        LayerKind::Dot1AH,
        "type",
        ethertype::DOT1AH,
    ),
    // Dot1AD -> *
    LayerBinding::new(
        LayerKind::Dot1AD,
        LayerKind::Dot1AD,
        "type",
        ethertype::DOT1AD,
    ),
    LayerBinding::new(LayerKind::Dot1AD, LayerKind::Dot1Q, "type", ethertype::VLAN),
    LayerBinding::new(
        LayerKind::Dot1AD,
        LayerKind::Dot1AH,
        "type",
        ethertype::DOT1AH,
    ),
    // IPv4 -> *
    LayerBinding::new(
        LayerKind::Ipv4,
        LayerKind::Tcp,
        "proto",
        ip_protocol::TCP as u16,
    ),
    LayerBinding::new(
        LayerKind::Ipv4,
        LayerKind::Udp,
        "proto",
        ip_protocol::UDP as u16,
    ),
    LayerBinding::new(
        LayerKind::Ipv4,
        LayerKind::Icmp,
        "proto",
        ip_protocol::ICMP as u16,
    ),
    // IPv6 -> *
    LayerBinding::new(
        LayerKind::Ipv6,
        LayerKind::Tcp,
        "nh",
        ip_protocol::TCP as u16,
    ),
    LayerBinding::new(
        LayerKind::Ipv6,
        LayerKind::Udp,
        "nh",
        ip_protocol::UDP as u16,
    ),
    LayerBinding::new(
        LayerKind::Ipv6,
        LayerKind::Icmpv6,
        "nh",
        ip_protocol::ICMPV6 as u16,
    ),
];

/// Find the binding for a given layer pair.
pub fn find_binding(lower: LayerKind, upper: LayerKind) -> Option<&'static LayerBinding> {
    LAYER_BINDINGS
        .iter()
        .find(|b| b.lower == lower && b.upper == upper)
}

/// Find all bindings where the given layer is the lower layer.
pub fn find_bindings_from(lower: LayerKind) -> impl Iterator<Item = &'static LayerBinding> {
    LAYER_BINDINGS.iter().filter(move |b| b.lower == lower)
}

/// Find all bindings where the given layer is the upper layer.
pub fn find_bindings_to(upper: LayerKind) -> impl Iterator<Item = &'static LayerBinding> {
    LAYER_BINDINGS.iter().filter(move |b| b.upper == upper)
}

/// Determine the upper layer kind based on field value.
///
/// For example, if lower=Ethernet and field_name="type" and value=0x0806,
/// returns Some(LayerKind::Arp).
pub fn infer_upper_layer(lower: LayerKind, field_name: &str, value: u16) -> Option<LayerKind> {
    LAYER_BINDINGS
        .iter()
        .find(|b| b.lower == lower && b.field_name == field_name && b.field_value == value)
        .map(|b| b.upper)
}

/// Get the expected upper layer kinds for a given lower layer.
pub fn expected_upper_layers(lower: LayerKind) -> Vec<LayerKind> {
    find_bindings_from(lower).map(|b| b.upper).collect()
}

/// Registry for custom bindings (runtime-defined).
#[derive(Debug, Clone, Default)]
pub struct BindingRegistry {
    bindings: Vec<LayerBinding>,
}

impl BindingRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a registry pre-populated with static bindings.
    pub fn with_defaults() -> Self {
        Self {
            bindings: LAYER_BINDINGS.to_vec(),
        }
    }

    /// Register a new binding.
    pub fn register(
        &mut self,
        lower: LayerKind,
        upper: LayerKind,
        field_name: &'static str,
        field_value: u16,
    ) {
        // Remove any existing binding for this pair
        self.bindings
            .retain(|b| !(b.lower == lower && b.upper == upper));
        self.bindings
            .push(LayerBinding::new(lower, upper, field_name, field_value));
    }

    /// Find a binding in this registry.
    pub fn find(&self, lower: LayerKind, upper: LayerKind) -> Option<&LayerBinding> {
        self.bindings
            .iter()
            .find(|b| b.lower == lower && b.upper == upper)
    }

    /// Find all bindings from a lower layer.
    pub fn find_from(&self, lower: LayerKind) -> impl Iterator<Item = &LayerBinding> {
        self.bindings.iter().filter(move |b| b.lower == lower)
    }

    /// Infer upper layer from field value.
    pub fn infer_upper(&self, lower: LayerKind, field_name: &str, value: u16) -> Option<LayerKind> {
        self.bindings
            .iter()
            .find(|b| b.lower == lower && b.field_name == field_name && b.field_value == value)
            .map(|b| b.upper)
    }
}

/// Apply binding to set the appropriate field when stacking layers.
///
/// Returns the field name and value that should be set, if a binding exists.
pub fn apply_binding(lower: LayerKind, upper: LayerKind) -> Option<(&'static str, u16)> {
    find_binding(lower, upper).map(|b| (b.field_name, b.field_value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_binding() {
        let binding = find_binding(LayerKind::Ethernet, LayerKind::Arp);
        assert!(binding.is_some());
        let b = binding.unwrap();
        assert_eq!(b.field_name, "type");
        assert_eq!(b.field_value, 0x0806);
    }

    #[test]
    fn test_find_bindings_from() {
        let bindings: Vec<_> = find_bindings_from(LayerKind::Ethernet).collect();
        assert!(bindings.len() >= 3); // At least ARP, IPv4, IPv6
    }

    #[test]
    fn test_infer_upper_layer() {
        assert_eq!(
            infer_upper_layer(LayerKind::Ethernet, "type", 0x0800),
            Some(LayerKind::Ipv4)
        );
        assert_eq!(
            infer_upper_layer(LayerKind::Ethernet, "type", 0x0806),
            Some(LayerKind::Arp)
        );
        assert_eq!(
            infer_upper_layer(LayerKind::Ipv4, "proto", 6),
            Some(LayerKind::Tcp)
        );
    }

    #[test]
    fn test_apply_binding() {
        let result = apply_binding(LayerKind::Ethernet, LayerKind::Ipv6);
        assert_eq!(result, Some(("type", 0x86DD)));
    }

    #[test]
    fn test_binding_registry() {
        let mut registry = BindingRegistry::with_defaults();

        // Add a custom binding
        registry.register(LayerKind::Ethernet, LayerKind::Raw, "type", 0x1234);

        let binding = registry.find(LayerKind::Ethernet, LayerKind::Raw);
        assert!(binding.is_some());
        assert_eq!(binding.unwrap().field_value, 0x1234);
    }

    #[test]
    fn test_expected_upper_layers() {
        let uppers = expected_upper_layers(LayerKind::Ethernet);
        assert!(uppers.contains(&LayerKind::Arp));
        assert!(uppers.contains(&LayerKind::Ipv4));
        assert!(uppers.contains(&LayerKind::Ipv6));
    }
}
